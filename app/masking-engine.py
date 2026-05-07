"""
masking_engine.py — Stateless PII detection via compiled regex patterns.

Detects: full names, Israeli IDs, salaries, emails, phone numbers, credit cards.
Returns a MaskingResult containing the masked text and a token → original mapping.

Design: single-pass substitution using re.sub with a counter closure,
so the same PII value in one prompt gets the same token (de-duplication).
"""

import re
import os
import logging
from dataclasses import dataclass, field

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class MaskingResult:
    masked_text: str
    # { "TKN_NAME_8F2A": "ישראל ישראלי" }
    token_to_original: dict[str, str] = field(default_factory=dict)
    pii_types_found: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# PII pattern registry — extend here for new entity types
# ---------------------------------------------------------------------------

# Named tuple would work too; dataclass keeps it extensible
@dataclass
class PiiPattern:
    name: str            # Human-readable entity type (for audit logs)
    token_tag: str       # Short code used in TKN_<TAG>_<HEX> tokens
    pattern: re.Pattern  # Compiled regex


_PATTERNS: list[PiiPattern] = [
    PiiPattern(
        name="israeli_id",
        token_tag="ID",
        # 9-digit Israeli ID (Teudat Zehut)
        pattern=re.compile(r"\b\d{9}\b"),
    ),
    PiiPattern(
        name="credit_card",
        token_tag="CC",
        # 13-19 digit card numbers, optional dashes/spaces
        pattern=re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    ),
    PiiPattern(
        name="email",
        token_tag="EMAIL",
        pattern=re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
    ),
    PiiPattern(
        name="phone_il",
        token_tag="PHONE",
        # Israeli mobile / landline: 05x-xxxxxxx or 0x-xxxxxxx
        pattern=re.compile(r"\b0(?:5[0-9]|[2-9])-?\d{7}\b"),
    ),
    PiiPattern(
        name="salary",
        token_tag="SALARY",
        # "₪15,000" / "15000 ₪" / "15,000 NIS" / "$75,000"
        pattern=re.compile(
            r"(?:₪\s?|NIS\s?|\$\s?)[\d,]+(?:\.\d{1,2})?"
            r"|[\d,]+(?:\.\d{1,2})?\s?(?:₪|NIS)",
            re.IGNORECASE,
        ),
    ),
    PiiPattern(
        name="full_name_hebrew",
        token_tag="NAME",
        # Two or three Hebrew words (first + last [+ family suffix])
        pattern=re.compile(
            r"\b[\u05d0-\u05ea]{2,}(?:\s[\u05d0-\u05ea]{2,}){1,2}\b"
        ),
    ),
    PiiPattern(
        name="full_name_latin",
        token_tag="NAME",
        # Two capitalised Latin words — intentionally conservative
        pattern=re.compile(r"\b[A-Z][a-z]{1,30}\s[A-Z][a-z]{1,30}\b"),
    ),
]


class MaskingEngine:
    """
    Thread-safe and stateless — safe to share across requests.
    """

    def __init__(self) -> None:
        self._patterns = _PATTERNS

    def mask(self, text: str) -> MaskingResult:
        """
        Detect PII in `text`, replace each occurrence with a stable token,
        and return a MaskingResult.

        Same value → same token within one call (deduplication).
        Different sessions may produce different tokens (token_bytes random).
        """
        token_map: dict[str, str] = {}       # original_value → token
        reverse_map: dict[str, str] = {}     # token → original_value
        pii_types: set[str] = set()

        masked = text

        for pii in self._patterns:
            def _replacer(m: re.Match, _pii=pii) -> str:
                original = m.group(0)
                if original in token_map:
                    return token_map[original]
                token = self._generate_token(_pii.token_tag)
                token_map[original] = token
                reverse_map[token] = original
                pii_types.add(_pii.name)
                return token

            masked = pii.pattern.sub(_replacer, masked)

        logger.debug(
            "Masking complete — %d tokens created, types: %s",
            len(reverse_map), list(pii_types),
        )

        return MaskingResult(
            masked_text=masked,
            token_to_original=reverse_map,
            pii_types_found=sorted(pii_types),
        )

    @staticmethod
    def _generate_token(tag: str) -> str:
        """
        Produce a unique token like TKN_NAME_8F2A.
        hex_suffix = token_bytes * 2 characters.
        """
        hex_suffix = os.urandom(settings.token_bytes).hex().upper()
        return f"{settings.token_prefix}_{tag}_{hex_suffix}"
