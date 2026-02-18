"""Typer CLI for EDR-Bench."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from edr_bench import __version__

app = typer.Typer(
    name="edr-bench",
    help="EDR benchmarking suite with simulated attacks and ground truth scoring.",
    no_args_is_help=True,
)
console = Console()


@app.callback()
def main(version: bool = typer.Option(False, "--version", "-v", help="Show version")) -> None:
    if version:
        console.print(f"edr-bench {__version__}")
        raise typer.Exit()


@app.command()
def run(
    platform: str = typer.Option("linux", "--platform", "-p", help="Target platform"),
    scenarios_dir: Path = typer.Option(
        "data/scenarios", "--scenarios", "-s", help="Scenarios directory"
    ),
    config: Path | None = typer.Option(None, "--config", "-c", help="Config YAML file"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate and plan without executing"),
    edr_name: str = typer.Option("Unknown EDR", "--edr-name", help="EDR product name"),
) -> None:
    """Run benchmark scenarios against an EDR."""
    from edr_bench.config.schema import load_config
    from edr_bench.models.enums import Platform
    from edr_bench.orchestrator.engine import BenchmarkOrchestrator
    from edr_bench.reporting.json_report import JSONReporter
    from edr_bench.utils.csv_loader import CSVLoader
    from edr_bench.utils.logging import configure_logging

    settings = load_config(config)
    settings.dry_run = dry_run
    settings.scenarios_dir = scenarios_dir
    if edr_name != "Unknown EDR":
        settings.edr.name = edr_name
    configure_logging(settings.log_level)

    platform_enum = Platform(platform)
    loader = CSVLoader()
    scenarios = loader.load_directory(scenarios_dir)

    if not scenarios:
        console.print("[red]No scenarios found.[/red]")
        raise typer.Exit(1)

    console.print(f"Loaded {len(scenarios)} scenarios from {scenarios_dir}")
    orchestrator = BenchmarkOrchestrator(settings)

    if dry_run:
        asyncio.run(orchestrator.run_dry(scenarios, platform_enum))
        console.print("[green]Dry run complete.[/green]")
    else:
        report = asyncio.run(orchestrator.run_benchmark(scenarios, platform_enum))
        output = settings.report_output_dir / f"{report.report_id}.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        reporter = JSONReporter()
        reporter.write(report, output)
        console.print(f"[green]Benchmark complete. Report: {output}[/green]")


@app.command()
def validate(
    scenarios_dir: Path = typer.Argument(..., help="Path to scenarios directory or CSV file"),
) -> None:
    """Validate scenario CSV files."""
    from edr_bench.utils.csv_loader import CSVLoader

    loader = CSVLoader()
    if scenarios_dir.is_file():
        scenarios = loader.load_scenarios(scenarios_dir)
    else:
        scenarios = loader.load_directory(scenarios_dir)

    errors = loader.validate_scenarios(scenarios)
    if errors:
        console.print("[red]Validation errors:[/red]")
        for err in errors:
            console.print(f"  - {err}")
        raise typer.Exit(1)

    table = Table(title="Validated Scenarios")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Platform")
    table.add_column("Attack Type")
    table.add_column("Steps")

    for s in scenarios:
        table.add_row(s.id, s.name, s.platform.value, s.attack_type.value, str(len(s.simulation_steps)))

    console.print(table)
    console.print(f"[green]{len(scenarios)} scenarios validated successfully.[/green]")


@app.command()
def report(
    report_file: Path = typer.Argument(..., help="Path to JSON report file"),
    output: Path = typer.Option("report.html", "--output", "-o", help="Output HTML file"),
) -> None:
    """Generate HTML report from a JSON benchmark report."""
    import json

    from edr_bench.models.metrics import BenchmarkReport
    from edr_bench.reporting.html_report import HTMLReporter

    with open(report_file) as f:
        data = json.load(f)
    bench_report = BenchmarkReport.model_validate(data)
    reporter = HTMLReporter()
    reporter.write(bench_report, output)
    console.print(f"[green]HTML report written to {output}[/green]")


@app.command()
def infra(
    action: str = typer.Argument(..., help="Action: up, down, ps, logs"),
    profile: str = typer.Option("linux", "--profile", "-p", help="Compose profile"),
) -> None:
    """Manage Docker infrastructure."""
    import subprocess

    compose_cmd = ["docker", "compose", "-f", "docker/docker-compose.yml", "--profile", profile]

    if action == "up":
        subprocess.run([*compose_cmd, "up", "-d"], check=True)
    elif action == "down":
        subprocess.run([*compose_cmd, "down", "-v"], check=True)
    elif action == "ps":
        subprocess.run([*compose_cmd, "ps"], check=True)
    elif action == "logs":
        subprocess.run([*compose_cmd, "logs", "-f"], check=False)
    else:
        console.print(f"[red]Unknown action: {action}. Use: up, down, ps, logs[/red]")
        raise typer.Exit(1)
