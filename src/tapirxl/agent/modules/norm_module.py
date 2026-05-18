from __future__ import annotations

import dspy

from tapirxl.agent.signatures.normalize import NormalizeSignal


class NormModule(dspy.Module):
    def __init__(self):
        self.predict = dspy.Predict(NormalizeSignal)

    def forward(self, ambiguous_field_bundle: str, envelope_context: str):
        return self.predict(
            ambiguous_field_bundle=ambiguous_field_bundle,
            envelope_context=envelope_context,
        )
