"""Normalizer for Wazuh alert JSON."""
from __future__ import annotations

from typing import Any

from edr_bench.edr_interface.normalizer import FindingNormalizer
from edr_bench.models.finding import Finding


def _flatten_dict(d: dict[str, Any], parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    """Recursively flatten a nested dict to dot-delimited keys.

    Single-item lists are unwrapped to their first element so that
    ``{"rule": {"mitre": {"id": ["T1059"]}}}`` becomes
    ``{"rule.mitre.id": "T1059"}``.
    """
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep).items())
        elif isinstance(v, list) and len(v) == 1:
            items.append((new_key, v[0]))
        else:
            items.append((new_key, v))
    return dict(items)


# Map Wazuh rule.level (0-15) to the severity strings the base normalizer
# already understands.
_WAZUH_LEVEL_TO_SEVERITY: dict[range, str] = {
    range(0, 4): "info",
    range(4, 7): "low",
    range(7, 10): "medium",
    range(10, 13): "high",
    range(13, 16): "critical",
}


def _map_wazuh_level(level: Any) -> str:
    """Convert a Wazuh numeric level (0-15) to a severity string."""
    try:
        num = int(level)
    except (ValueError, TypeError):
        return str(level)
    for r, sev in _WAZUH_LEVEL_TO_SEVERITY.items():
        if num in r:
            return sev
    return "medium"


class WazuhNormalizer(FindingNormalizer):
    """Normalize Wazuh alert JSON into canonical :class:`Finding` instances.

    Wazuh alerts are deeply nested (``rule.description``, ``rule.mitre.id``,
    ``data.command``, etc.).  This normalizer flattens the dict to dot-delimited
    keys so the base alias lookup works, and pre-maps the 0-15 severity level.
    """

    def normalize_json(self, raw: dict[str, Any]) -> Finding:
        flat = _flatten_dict(raw)
        # Pre-map Wazuh's numeric level to a severity string
        if "rule.level" in flat:
            flat["rule.level"] = _map_wazuh_level(flat["rule.level"])
        # Wazuh may return multiple MITRE IDs as a list; take the first one
        mitre_id = flat.get("rule.mitre.id")
        if isinstance(mitre_id, list):
            flat["rule.mitre.id"] = mitre_id[0] if mitre_id else None
        return self._build_finding(flat)
