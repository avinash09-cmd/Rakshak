import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = "sqlite:///./rakshak.db"
    stix_path: str = "data/enterprise-attack.json"
    max_field_chars: int = 4000
    # LLM provider: mock | ollama | openai_compat | anthropic
    llm_provider: str = "mock"
    anthropic_model: str = "claude-sonnet-5-5"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2:3b"
    openai_base_url: str = ""   # any OpenAI-compatible endpoint (Groq, Gemini, OpenRouter, ...)
    openai_api_key: str = ""
    openai_model: str = ""


def get_settings() -> Settings:
    provider = os.getenv("LLM_PROVIDER", "").strip().lower()
    if os.getenv("RAKSHAK_MOCK_LLM", "").lower() in ("1", "true", "yes"):
        provider = "mock"
    if not provider:  # backwards compatible default: Claude if a key exists, else free mock
        provider = "anthropic" if os.getenv("ANTHROPIC_API_KEY") else "mock"
    return Settings(
        database_url=os.getenv("DATABASE_URL", "sqlite:///./rakshak.db"),
        stix_path=os.getenv("STIX_PATH", "data/enterprise-attack.json"),
        max_field_chars=int(os.getenv("MAX_FIELD_CHARS", "4000")),
        llm_provider=provider,
        anthropic_model=os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5"),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.2:3b"),
        openai_base_url=os.getenv("OPENAI_BASE_URL", ""),
        openai_api_key=os.getenv("OPENAI_API_KEY", ""),
        openai_model=os.getenv("OPENAI_MODEL", ""),
    )
