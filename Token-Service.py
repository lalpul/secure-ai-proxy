"""
token_service.py — Persist and retrieve token ↔ EncryptedBlob mappings.

Storage model (PostgreSQL):
  table: token_mappings
    id            UUID PK
    session_id    TEXT NOT NULL          ← scope tokens to a session
    token         TEXT NOT NULL UNIQUE   ← e.g. TKN_NAME_8F2A
    ciphertext_key TEXT NOT NULL         ← OCI-wrapped DEK (b64)
    iv            TEXT NOT NULL
    ciphertext    TEXT NOT NULL
    tag           TEXT NOT NULL
    created_at    TIMESTAMPTZ DEFAULT now()
    expires_at    TIMESTAMPTZ             ← optional TTL

All values are TEXT (b64-encoded bytes). No raw PII is ever written.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg

from app.config import get_settings
from app.crypto_manager import CryptoManager, EncryptedBlob

logger = logging.getLogger(__name__)
settings = get_settings()

# Token TTL — purge after 24 h (adjust per compliance requirements)
_TOKEN_TTL_HOURS = 24


class TokenService:
    """
    Async service — requires an asyncpg connection pool.
    Inject via FastAPI dependency.
    """

    def __init__(self, pool: asyncpg.Pool, crypto: CryptoManager) -> None:
        self._pool = pool
        self._crypto = crypto

    # ------------------------------------------------------------------
    # Write path (called during masking)
    # ------------------------------------------------------------------

    async def store_tokens(
        self,
        session_id: str,
        token_to_original: dict[str, str],
    ) -> None:
        """
        Encrypt each original value and persist token → blob in DB.
        Runs inside a single transaction for atomicity.
        """
        if not token_to_original:
            return

        expires_at = datetime.now(timezone.utc) + timedelta(hours=_TOKEN_TTL_HOURS)

        async with self._pool.acquire() as conn:
            async with conn.transaction():
                for token, original in token_to_original.items():
                    # Encryption is CPU-bound — for large batches consider
                    # asyncio.to_thread; fine for typical PII counts (<20)
                    blob: EncryptedBlob = self._crypto.encrypt(original)

                    await conn.execute(
                        """
                        INSERT INTO token_mappings
                          (id, session_id, token, ciphertext_key, iv, ciphertext, tag, expires_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        ON CONFLICT (token) DO NOTHING
                        """,
                        str(uuid.uuid4()),
                        session_id,
                        token,
                        blob.ciphertext_key_b64,
                        blob.iv_b64,
                        blob.ciphertext_b64,
                        blob.tag_b64,
                        expires_at,
                    )

        logger.info(
            "Stored %d token(s) for session %s", len(token_to_original), session_id
        )

    # ------------------------------------------------------------------
    # Read path (called during detokenization)
    # ------------------------------------------------------------------

    async def resolve_tokens(
        self,
        session_id: str,
        tokens: list[str],
    ) -> dict[str, str]:
        """
        For each token, fetch the EncryptedBlob, decrypt, and return
        { token: plaintext_original }.

        Tokens not found (expired / unknown) are silently skipped —
        the caller will leave them as-is in the response.
        """
        if not tokens:
            return {}

        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT token, ciphertext_key, iv, ciphertext, tag
                FROM token_mappings
                WHERE session_id = $1
                  AND token = ANY($2::text[])
                  AND (expires_at IS NULL OR expires_at > now())
                """,
                session_id,
                tokens,
            )

        result: dict[str, str] = {}
        for row in rows:
            blob = EncryptedBlob(
                ciphertext_key_b64=row["ciphertext_key"],
                iv_b64=row["iv"],
                ciphertext_b64=row["ciphertext"],
                tag_b64=row["tag"],
            )
            try:
                result[row["token"]] = self._crypto.decrypt(blob)
            except Exception:
                logger.exception("Decryption failed for token %s", row["token"])
                # Leave the token unreplaced rather than crashing the response

        return result

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    async def purge_expired(self) -> int:
        """Delete expired tokens. Call from a scheduled background task."""
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM token_mappings WHERE expires_at < now()"
            )
        deleted = int(result.split()[-1])
        logger.info("Purged %d expired token(s)", deleted)
        return deleted
