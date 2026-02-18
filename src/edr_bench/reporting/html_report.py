"""HTML report generator using Jinja2."""

from __future__ import annotations

from pathlib import Path

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from edr_bench.models.metrics import BenchmarkReport

logger = structlog.get_logger()

TEMPLATES_DIR = Path(__file__).parent / "templates"


class HTMLReporter:
    """Generate HTML benchmark reports with MITRE ATT&CK heatmap."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        self.templates_dir = templates_dir or TEMPLATES_DIR
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(["html"]),
        )

    def write(self, report: BenchmarkReport, output_path: Path) -> None:
        """Render and write HTML report."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        template = self.env.get_template("report.html.j2")
        html = template.render(
            report=report,
            technique_scores=report.technique_scores,
            platform_breakdown=report.platform_breakdown,
            attack_type_breakdown=report.attack_type_breakdown,
        )

        output_path.write_text(html)

        # Copy static assets alongside the report
        static_src = self.templates_dir.parent / "static"
        if static_src.exists():
            static_dst = output_path.parent / "static"
            static_dst.mkdir(exist_ok=True)
            for f in static_src.iterdir():
                (static_dst / f.name).write_text(f.read_text())

        logger.info("html_report_written", path=str(output_path))

    def render_heatmap(self, report: BenchmarkReport) -> str:
        """Render just the MITRE ATT&CK heatmap fragment."""
        template = self.env.get_template("heatmap.html.j2")
        return template.render(technique_scores=report.technique_scores)

    def render_scenario_detail(self, report: BenchmarkReport, scenario_id: str) -> str:
        """Render detail view for a single scenario."""
        result = next(
            (r for r in report.scenario_results if r.scenario_id == scenario_id), None
        )
        if not result:
            raise ValueError(f"Scenario {scenario_id} not found in report")
        template = self.env.get_template("scenario_detail.html.j2")
        return template.render(result=result, report=report)
