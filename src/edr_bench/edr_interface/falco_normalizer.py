"""Normalizer for Falco alert JSON."""
from __future__ import annotations

from typing import Any

from edr_bench.edr_interface.normalizer import FindingNormalizer
from edr_bench.models.finding import Finding


class FalcoNormalizer(FindingNormalizer):
    """Normalize Falco JSON output into canonical :class:`Finding` instances.

    Falco's JSON output has top-level fields (``rule``, ``priority``,
    ``output``, ``time``) and an ``output_fields`` dict with process / file /
    container details (``proc.name``, ``fd.name``, ``container.id``, etc.).
    This normalizer lifts ``output_fields`` to the top level so the base alias
    lookup can match them.
    """

    def normalize_json(self, raw: dict[str, Any]) -> Finding:
        flat = dict(raw)
        # Lift output_fields to top level for alias matching
        output_fields = flat.pop("output_fields", None)
        if isinstance(output_fields, dict):
            flat.update(output_fields)
        # Falco uses "time" instead of "timestamp"
        if "time" in flat and "timestamp" not in flat:
            flat["timestamp"] = flat["time"]
        return self._build_finding(flat)
