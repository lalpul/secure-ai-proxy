"""
main.py — FastAPI application and /chat endpoint.
Deployment: Groq (or any OpenAI-compatible API) + in-memory token store.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware

from app.config import Settings, get_settings
from app.masking_engine import MaskingEngine
from app.models import ChatRequest, ChatResponse, MaskingReport

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# In-memory token store (replaces DB + CryptoManager for this deployment)
# { session_id: { token: original_value } }
# ---------------------------------------------------------------------------
_token_store: dict[str, dict[str, str]] = {}


def store_tokens(session_id: str, token_map: dict[str, str]) -> None:
    if session_id not in _token_store:
        _token_store[session_id] = {}
    _token_store[session_id].update(token_map)


def resolve_tokens(session_id: str, tokens: list[str]) -> dict[str, str]:
    session = _token_store.get(session_id, {})
    return {t: session[t] for t in tokens if t in session}


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Secure AI Proxy (Groq mode)…")
    app.state.masking = MaskingEngine()
    logger.info("MaskingEngine ready.")
    yield
    logger.info("Secure AI Proxy shut down.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    application = FastAPI(
        title="Secure AI Proxy",
        version="0.1.0",
        description="Privacy-preserving AI gateway — PII never reaches the LLM.",
        lifespan=lifespan,
        docs_url="/docs" if os.getenv("DEBUG") else None,
        redoc_url=None,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["POST", "GET"],
        allow_headers=["*"],
    )
    return application


app = create_app()


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

def get_masking(request: Request) -> MaskingEngine:
    return request.app.state.masking


def get_settings_dep() -> Settings:
    return get_settings()


# ---------------------------------------------------------------------------
# /mask — smoke test
# ---------------------------------------------------------------------------

@app.post("/mask")
async def mask_data(
    data: dict,
    masking: Annotated[MaskingEngine, Depends(get_masking)],
) -> dict:
    raw_text = data.get("text", "")
    result = masking.mask(raw_text)
    return {
        "status": "protected",
        "original_length": len(raw_text),
        "masked_result": result.masked_text,
        "tokens_created": len(result.token_to_original),
        "pii_types_found": result.pii_types_found,
    }


# ---------------------------------------------------------------------------
# /chat — full secure proxy flow
# ---------------------------------------------------------------------------

@app.post("/chat", response_model=ChatResponse, status_code=status.HTTP_200_OK)
async def chat(
    body: ChatRequest,
    masking: Annotated[MaskingEngine, Depends(get_masking)],
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> ChatResponse:

    # ── Step 1: Mask PII ──────────────────────────────────────────────
    masking_result = masking.mask(body.prompt)

    logger.info(
        "\n%s\n"
        "  SESSION   : %s\n"
        "  TOKENS    : %d  %s\n"
        "  ORIGINAL  : %s\n"
        "  MASKED    : %s\n"
        "%s",
        "=" * 60,
        body.session_id,
        len(masking_result.token_to_original),
        masking_result.pii_types_found,
        body.prompt[:120] + ("…" if len(body.prompt) > 120 else ""),
        masking_result.masked_text[:120] + ("…" if len(masking_result.masked_text) > 120 else ""),
        "-" * 60,
    )

    # ── Step 2: Store token map (in-memory) ───────────────────────
    store_tokens(body.session_id, masking_result.token_to_original)

    # ── Step 3: Call LLM — ZERO TRUST: only tokens sent ──────────
    logger.info("→ LLM REQUEST | session=%s | model=%s | prompt_len=%d",
                body.session_id, settings.model_name, len(masking_result.masked_text))
    try:
        llm_response = await _call_llm(
            masked_prompt=masking_result.masked_text,
            system_prompt=body.system_prompt,
            settings=settings,
        )
    except Exception as exc:
        logger.exception("LLM call failed for session %s", body.session_id)
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    logger.info("← LLM RESPONSE | session=%s | response_len=%d | tokens_in_response=%s",
                body.session_id, len(llm_response),
                _extract_tokens(llm_response, settings.token_prefix))

    # ── Step 4: Detokenize response ────────────────────────────────
    tokens_in_response = _extract_tokens(llm_response, settings.token_prefix)
    resolved = resolve_tokens(body.session_id, tokens_in_response)
    clean_response = _replace_tokens(llm_response, resolved)

    logger.info(
        "\n%s\n"
        "  DETOKENIZED: %d/%d tokens restored\n"
        "  CLEAN RESP : %s\n"
        "%s",
        "=" * 60,
        len(resolved),
        len(tokens_in_response),
        clean_response[:120] + ("…" if len(clean_response) > 120 else ""),
        "=" * 60,
    )

    # ── Step 5: Return ─────────────────────────────────────────────
    report = None
    if os.getenv("DEBUG"):
        report = MaskingReport(
            tokens_created=len(masking_result.token_to_original),
            pii_types_found=masking_result.pii_types_found,
        )

    return ChatResponse(
        session_id=body.session_id,
        response=clean_response,
        masking_report=report,
    )


# ---------------------------------------------------------------------------
# LLM call (OpenAI-compatible — works with Groq, OpenAI, Azure, etc.)
# ---------------------------------------------------------------------------

async def _call_llm(
    masked_prompt: str,
    system_prompt: str | None,
    settings: Settings,
) -> str:
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": masked_prompt})

    api_key = settings.effective_api_key()
    base_url = settings.openai_base_url.rstrip("/")
    model = settings.model_name

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.post(
            f"{base_url}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model, "messages": messages, "temperature": 0.7},
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Token utilities
# ---------------------------------------------------------------------------

def _extract_tokens(text: str, prefix: str) -> list[str]:
    pattern = re.compile(rf"\b{re.escape(prefix)}_[A-Z]+_[0-9A-F]{{4,16}}\b")
    return list(set(pattern.findall(text)))


def _replace_tokens(text: str, token_map: dict[str, str]) -> str:
    for token, original in token_map.items():
        text = text.replace(token, original)
    return text


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok"}
