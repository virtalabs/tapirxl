"""NormalizeSignal DSPy signature — do NOT rename fields (ABI break for compiled modules)."""
from __future__ import annotations

import dspy


class NormalizeSignal(dspy.Signature):
    """Pick N verbatim normalization tier for Passive Device ID v2.

    Input `ambiguous_field_bundle` is ONE JSON dict with keys:
      raw_value, source_protocol, field_path, candidate_labels (JSON array strings),
      host_context.

    Canonical pick rule:
      OUTPUT normalized_value MUST be EXACTLY one of candidate_labels verbatim,
      unless none apply — then OUTPUT exactly `OTHER:` + sanitized short free text.

      Never invent vendor-specific labels not present in candidate_labels.

    Confidence:
      HIGH if verbatim match trivial (single obvious candidate listed),
      MEDIUM if heuristic guess among curated list,
      LOW if forced OTHER free-text.
    """

    ambiguous_field_bundle: str = dspy.InputField(
        desc="JSON object for ONE ambiguous_fields[] entry."
    )
    envelope_context: str = dspy.InputField(
        desc="JSON snippet of sanitized host envelope (excluding PHI)."
    )
    normalized_value: str = dspy.OutputField(
        desc="EXACT verbatim element from candidate_labels OR OTHER:<short sanitized reason>"
    )
    confidence: str = dspy.OutputField(
        desc="Exactly one of: HIGH | MEDIUM | LOW for this normalization"
    )
