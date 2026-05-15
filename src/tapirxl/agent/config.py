"""Model configuration — the ONLY file that reads models.toml."""
from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel


class _LmConfig(BaseModel):
    model: str
    context_window: int = 8192
    max_tokens: int = 1024
    temperature: float = 0.2


class _FallbackConfig(BaseModel):
    model: str
    context_window: int = 32768
    max_tokens: int = 128
    temperature: float = 0.0


class _SubLmConfig(_LmConfig):
    fallback: _FallbackConfig | None = None


class ModelConfig(BaseModel):
    ollama_url: str = "http://localhost:11434"
    lm: _LmConfig
    sub_lm: _SubLmConfig


def load_model_config(path: Path | None = None) -> ModelConfig:
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    candidates.extend([
        Path.cwd() / "models.toml",
        Path(__file__).parent.parent.parent.parent / "models.toml",
    ])
    for candidate in candidates:
        if candidate.exists():
            raw = tomllib.loads(candidate.read_text())
            return ModelConfig(
                ollama_url=raw.get("provider", {}).get("endpoint", "http://localhost:11434"),
                lm=_LmConfig(**raw["lm"]),
                sub_lm=_SubLmConfig(**{
                    k: v for k, v in raw["sub_lm"].items() if k != "fallback"
                } | (
                    {"fallback": raw["sub_lm"]["fallback"]}
                    if "fallback" in raw["sub_lm"]
                    else {}
                )),
            )
    raise FileNotFoundError(f"models.toml not found; searched: {[str(c) for c in candidates]}")
