"""
models.py — Pydantic schemas for /chat endpoint.
"""
from pydantic import BaseModel, Field
from typing import Optional


class ChatRequest(BaseModel):
    session_id: str = Field(
        ...,
        min_length=4,
        max_length=64,
        description="Caller-supplied session identifier (UUID recommended)."
    )
    prompt: str = Field(
        ...,
        min_length=1,
        max_length=8000,
        description="Raw user prompt — may contain PII."
    )
    system_prompt: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Optional system context (not masked — keep PII-free)."
    )


class MaskingReport(BaseModel):
    """Returned for audit / debugging — never logged in production."""
    tokens_created: int
    pii_types_found: list[str]


class ChatResponse(BaseModel):
    session_id: str
    response: str = Field(..., description="Clean LLM response with real values restored.")
    masking_report: Optional[MaskingReport] = Field(
        default=None,
        description="Present only when DEBUG=true."
    )
