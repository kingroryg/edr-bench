"""Rich-based live progress display for benchmark runs."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from rich.console import Console
from rich.progress import BarColumn, Progress, TaskID, TextColumn, TimeElapsedColumn
from rich.table import Table

from edr_bench.models.metrics import ScenarioResult


@runtime_checkable
class ProgressCallback(Protocol):
    """Callback protocol for benchmark progress reporting."""

    def on_scenario_start(self, scenario_id: str, scenario_name: str, index: int, total: int) -> None: ...
    def on_scenario_complete(self, scenario_id: str, result: ScenarioResult) -> None: ...
    def on_scenario_error(self, scenario_id: str, error: str) -> None: ...
    def finalize(self) -> None: ...


class RichProgressDisplay:
    """Live progress display using Rich."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()
        self._progress = Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self._console,
        )
        self._task_id: TaskID | None = None
        self._completed_results: list[tuple[str, ScenarioResult | None, str | None]] = []
        self._detection_rates: list[float] = []
        self._started = False
        self._finalized = False

    def on_scenario_start(self, scenario_id: str, scenario_name: str, index: int, total: int) -> None:
        if not self._started:
            self._progress.start()
            self._task_id = self._progress.add_task("Running benchmark", total=total)
            self._started = True
        avg_dr = sum(self._detection_rates) / len(self._detection_rates) if self._detection_rates else 0.0
        self._progress.update(
            self._task_id,  # type: ignore[arg-type]
            description=f"[{index}/{total}] {scenario_id}: {scenario_name[:50]}  (avg DR: {avg_dr:.0%})",
        )

    def on_scenario_complete(self, scenario_id: str, result: ScenarioResult) -> None:
        self._completed_results.append((scenario_id, result, None))
        self._detection_rates.append(result.detection_rate)
        if self._task_id is not None:
            self._progress.advance(self._task_id)

    def on_scenario_error(self, scenario_id: str, error: str) -> None:
        self._completed_results.append((scenario_id, None, error))
        if self._task_id is not None:
            self._progress.advance(self._task_id)

    def finalize(self) -> None:
        if self._finalized:
            return
        self._finalized = True
        if self._started:
            self._progress.stop()

        table = Table(title="Benchmark Results", show_lines=True)
        table.add_column("Scenario", style="bold")
        table.add_column("Detection Rate", justify="right")
        table.add_column("TTD", justify="right")
        table.add_column("Completeness", justify="right")
        table.add_column("Status", justify="center")

        for scenario_id, result, error in self._completed_results:
            if error is not None:
                table.add_row(scenario_id, "—", "—", "—", "[red]ERROR[/red]")
            elif result is not None:
                dr = f"{result.detection_rate:.0%}"
                ttd = f"{result.time_to_detect_seconds:.1f}s" if result.time_to_detect_seconds is not None else "—"
                comp = f"{result.execution_completeness:.0%}"
                status = "[green]PASS[/green]" if not result.errors else "[yellow]WARN[/yellow]"
                table.add_row(scenario_id, dr, ttd, comp, status)

        self._console.print(table)

        total = len(self._completed_results)
        errors = sum(1 for _, _, e in self._completed_results if e is not None)
        passed = total - errors
        avg_dr = sum(self._detection_rates) / len(self._detection_rates) if self._detection_rates else 0.0
        self._console.print(
            f"\n[bold]{passed}[/bold] passed, [bold red]{errors}[/bold red] errors "
            f"| avg detection rate: [bold]{avg_dr:.1%}[/bold]"
        )
