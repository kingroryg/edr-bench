"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from edr_bench.models.metrics import BenchmarkReport

logger = structlog.get_logger()


class JSONReporter:
    """Write benchmark reports as machine-readable JSON."""

    def write(self, report: BenchmarkReport, output_path: Path) -> None:
        """Serialize report to JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = report.model_dump(mode="json")
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info("json_report_written", path=str(output_path))

    def to_string(self, report: BenchmarkReport) -> str:
        """Serialize report to JSON string."""
        data = report.model_dump(mode="json")
        return json.dumps(data, indent=2, default=str)
