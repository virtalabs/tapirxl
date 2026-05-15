"""Ollama LM construction — the ONLY file that constructs dspy.LM."""
from __future__ import annotations

import dspy

from tapirxl.agent.config import ModelConfig


def build_lm_pair(cfg: ModelConfig) -> tuple[object, object]:
    """Return (fuse_lm, norm_lm) configured from ModelConfig."""
    fuse_lm = dspy.LM(
        cfg.lm.model,
        temperature=cfg.lm.temperature,
        max_tokens=cfg.lm.max_tokens,
        num_ctx=cfg.lm.context_window,
    )
    norm_lm = dspy.LM(
        cfg.sub_lm.model,
        temperature=cfg.sub_lm.temperature,
        max_tokens=cfg.sub_lm.max_tokens,
        num_ctx=cfg.sub_lm.context_window,
    )
    return fuse_lm, norm_lm
