from __future__ import annotations

import dspy

from tapirxl.agent.signatures.fuse import FuseSignals, FuseSignalsRLM


class FuseModule(dspy.Module):
    def __init__(self):
        self.predict = dspy.ChainOfThought(FuseSignals)

    def forward(
        self,
        signal_register,
        contradiction_flag,
        contradictions,
        floor_triggers,
        expert_flags,
    ):
        return self.predict(
            signal_register=signal_register,
            contradiction_flag=contradiction_flag,
            contradictions=contradictions,
            floor_triggers=floor_triggers,
            expert_flags=expert_flags,
        )


class FuseModuleRLM(dspy.Module):
    """Single RLM pass replacing ContradictSignals + FuseSignals."""

    def __init__(self, norm_lm):
        self.rlm = dspy.RLM(
            FuseSignalsRLM,
            sub_lm=norm_lm,
            max_iterations=8,
            max_llm_calls=10,
        )

    def forward(self, signal_register, floor_triggers, expert_flags):
        return self.rlm(
            signal_register=signal_register,
            floor_triggers=floor_triggers,
            expert_flags=expert_flags,
        )
