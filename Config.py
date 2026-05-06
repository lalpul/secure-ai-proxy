"""
config.py — Simplified settings for Groq/OpenAI-compatible backend.
No OCI Vault or PostgreSQL required for this deployment.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # LLM Backend
    llm_backend: str = "openai"           # "openai" = any OpenAI-compatible API
    openai_api_key: str = ""              # Groq key or OpenAI key
    openai_base_url: str = "https://api.openai.com/v1"  # Override for Groq
    model_name: str = "gpt-4o"           # e.g. llama3-8b-8192 for Groq

    # Optional Groq alias (maps GROQ_API_KEY → openai_api_key)
    groq_api_key: str = ""

    # OCI — all optional (not required for Groq deployment)
    oci_config_file: str = "~/.oci/config"
    oci_profile: str = "DEFAULT"
    oci_vault_id: str = ""
    oci_key_id: str = ""
    oci_compartment_id: str = ""
    oci_genai_endpoint: str = ""
    oci_genai_model: str = "cohere.command-r-plus"

    # DB — optional (in-memory token store used if not configured)
    db_host: str = ""
    db_port: int = 5432
    db_name: str = "ai_proxy"
    db_user: str = ""
    db_password: str = ""

    # Token config
    token_prefix: str = "TKN"
    token_bytes: int = 4

    def effective_api_key(self) -> str:
        """Return Groq key if set, otherwise OpenAI key."""
        return self.groq_api_key or self.openai_api_key

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"   # ← ignore unknown keys in .env


@lru_cache
def get_settings() -> Settings:
    return Settings()
