"""Pydantic v2 model for FusionOutput (ARCHITECTURE.md §3.8)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class FusionOutput(BaseModel):
    host_id: str
    mac: str
    ip: str
    path: Literal[
        "DETERMINISTIC_FINAL",
        "NORMALIZED_FINAL",
        "FUSED",
        "FUSED_RLM",
        "STAMP_LOW",
    ]
    device_class: str | None
    confidence: Literal["HIGH", "MEDIUM", "LOW"]
    reasoning_trace: str
    open_questions: list[str] = Field(default_factory=list)
    contradiction: bool = False
    contradictions: list[str] = Field(default_factory=list)
