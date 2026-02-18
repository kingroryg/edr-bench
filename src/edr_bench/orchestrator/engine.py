"""BenchmarkOrchestrator -- the hub of the hub-and-spoke architecture."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import structlog

from edr_bench.config.settings import Settings
from edr_bench.executors.base import AttackExecutor
from edr_bench.executors.cli_executor import CLIExecutor
from edr_bench.executors.phishing_executor import PhishingExecutor
from edr_bench.executors.terraform_executor import TerraformExecutor
from edr_bench.executors.ui_executor import UIExecutor
from edr_bench.executors.usb_simulator import USBSimulatorExecutor
from edr_bench.ground_truth.collector import GroundTruthCollector
from edr_bench.models.enums import Platform, Role
from edr_bench.models.ground_truth import GroundTruthEvent
from edr_bench.models.metrics import BenchmarkReport, ScenarioResult, StepResult
from edr_bench.models.scenario import Scenario, SimulationStep
from edr_bench.orchestrator.lifecycle import DockerLifecycleManager
from edr_bench.orchestrator.scheduler import ScenarioScheduler
from edr_bench.scoring.engine import ScoringEngine
from edr_bench.utils.timing import Timer

logger = structlog.get_logger()


class BenchmarkOrchestrator:
    """Central orchestrator managing the complete benchmark lifecycle."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.lifecycle = DockerLifecycleManager(settings)
        self.scheduler = ScenarioScheduler()
        self.scoring = ScoringEngine(settings)
        self.ground_truth_collector = GroundTruthCollector(settings)
        self._cli_executor: CLIExecutor | None = None
        self._ui_executor: UIExecutor | None = None
        self._phishing_executor: PhishingExecutor | None = None
        self._terraform_executor: TerraformExecutor | None = None
        self._usb_executor: USBSimulatorExecutor | None = None

    async def run_benchmark(
        self,
        scenarios: list[Scenario],
        platform: Platform | None = None,
    ) -> BenchmarkReport:
        """Execute a full benchmark run."""
        run_id = uuid4().hex[:12]
        logger.info("benchmark_starting", run_id=run_id, scenario_count=len(scenarios))

        plan = self.scheduler.get_execution_plan(scenarios, platform)
        if not plan:
            raise ValueError("No scenarios to execute")

        profile = platform.value if platform else "full"

        if not self.settings.dry_run:
            await self.lifecycle.start_services(profile)

        results: list[ScenarioResult] = []
        try:
            for scenario in plan:
                result = await self._execute_scenario(scenario)
                results.append(result)
        finally:
            if not self.settings.dry_run:
                await self.lifecycle.stop_services(profile)

        report = self._build_report(run_id, results)
        logger.info(
            "benchmark_complete",
            run_id=run_id,
            detection_rate=report.overall_detection_rate,
        )
        return report

    async def run_dry(self, scenarios: list[Scenario], platform: Platform | None = None) -> None:
        """Dry run: validate scenarios and log execution plan without running."""
        plan = self.scheduler.get_execution_plan(scenarios, platform)
        for scenario in plan:
            logger.info(
                "dry_run_scenario",
                id=scenario.id,
                name=scenario.name,
                platform=scenario.platform,
                steps=len(scenario.simulation_steps),
                ui=scenario.is_ui_scenario,
            )

    async def _execute_scenario(self, scenario: Scenario) -> ScenarioResult:
        """Execute a single scenario and collect results."""
        logger.info("scenario_starting", scenario_id=scenario.id, name=scenario.name)
        timer = Timer()
        timer.start()
        errors: list[str] = []
        ground_truth_events: list[GroundTruthEvent] = []

        step_results: list[StepResult] = []

        if self.settings.dry_run:
            timer.stop()
            return ScenarioResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                platform=scenario.platform,
                attack_type=scenario.attack_type,
                mitre_technique_id=scenario.mitre_technique_id,
                detection_rate=0.0,
                contextual_accuracy=0.0,
                blocking_efficacy=0.0,
                noise_ratio=0.0,
                ground_truth_count=0,
                findings_count=0,
                matched_count=0,
                false_positive_count=0,
                execution_started=timer.start_time,
                execution_finished=timer.end_time,
            )

        # Start ground truth collection
        gt_task = asyncio.create_task(
            self.ground_truth_collector.collect(scenario.id)
        )

        # Execute each step, tracking per-step results
        for step in scenario.simulation_steps:
            step_start = time.monotonic()
            step_status = "success"
            step_error: str | None = None
            try:
                executor = self._get_executor(step)
                await asyncio.wait_for(
                    executor.execute(step, scenario),
                    timeout=step.timeout_seconds if hasattr(step, "timeout_seconds") and step.timeout_seconds else None,
                )
            except asyncio.TimeoutError:
                step_status = "timeout"
                step_error = f"Step {step.order} timed out"
                error_msg = f"Step {step.order} timed out"
                logger.error(
                    "step_timeout",
                    scenario_id=scenario.id,
                    step=step.order,
                    role=step.role,
                )
                errors.append(error_msg)
            except Exception as e:
                step_status = "failed"
                step_error = str(e)
                error_msg = f"Step {step.order} failed: {e}"
                logger.error(
                    "step_failed",
                    scenario_id=scenario.id,
                    step=step.order,
                    role=step.role,
                    error=str(e),
                )
                errors.append(error_msg)
            finally:
                step_duration = time.monotonic() - step_start
                step_result = StepResult(
                    step_order=step.order,
                    role=step.role,
                    status=step_status,
                    error_message=step_error,
                    duration_seconds=round(step_duration, 3),
                )
                step_results.append(step_result)
                logger.info(
                    "step_result",
                    scenario_id=scenario.id,
                    step_order=step.order,
                    role=step.role,
                    status=step_status,
                    duration_seconds=round(step_duration, 3),
                )

        # Wait for ground truth events to settle
        await asyncio.sleep(5.0)
        ground_truth_events = await self.ground_truth_collector.stop_and_collect()
        gt_task.cancel()

        timer.stop()

        # Score the scenario
        result = await self.scoring.score_scenario(scenario, ground_truth_events)
        result.execution_started = timer.start_time
        result.execution_finished = timer.end_time
        result.errors = errors
        result.step_results = step_results

        succeeded = sum(1 for s in step_results if s.status == "success")
        logger.info(
            "scenario_complete",
            scenario_id=scenario.id,
            detection_rate=result.detection_rate,
            ground_truth=result.ground_truth_count,
            findings=result.findings_count,
            steps_total=len(step_results),
            steps_succeeded=succeeded,
            execution_completeness=result.execution_completeness,
        )
        return result

    def _get_executor(self, step: SimulationStep) -> AttackExecutor:
        """Get the appropriate executor for a simulation step.

        Each role maps to a dedicated executor that knows how to drive
        that particular attack surface (shell commands, browser automation,
        phishing campaigns, cloud provisioning, or USB device simulation).
        """
        if step.role == Role.CLI:
            if not self._cli_executor:
                self._cli_executor = CLIExecutor(self.settings)
            return self._cli_executor
        if step.role == Role.UI:
            if not self._ui_executor:
                self._ui_executor = UIExecutor(self.settings)
            return self._ui_executor
        if step.role == Role.PHISHING:
            if not self._phishing_executor:
                self._phishing_executor = PhishingExecutor(self.settings)
            return self._phishing_executor
        if step.role == Role.CLOUD:
            if not self._terraform_executor:
                self._terraform_executor = TerraformExecutor(self.settings)
            return self._terraform_executor
        if step.role == Role.USB:
            if not self._usb_executor:
                self._usb_executor = USBSimulatorExecutor(self.settings)
            return self._usb_executor
        raise ValueError(f"No executor registered for role: {step.role!r}")

    def _build_report(self, run_id: str, results: list[ScenarioResult]) -> BenchmarkReport:
        """Aggregate scenario results into a benchmark report."""
        now = datetime.now(timezone.utc)
        total_gt = sum(r.ground_truth_count for r in results)
        total_findings = sum(r.findings_count for r in results)
        total_matched = sum(r.matched_count for r in results)
        total_fp = sum(r.false_positive_count for r in results)
        total_errors = sum(len(r.errors) for r in results)

        detection_rates = [r.detection_rate for r in results]
        overall_dr = sum(detection_rates) / len(detection_rates) if detection_rates else 0.0

        accuracies = [r.contextual_accuracy for r in results]
        overall_acc = sum(accuracies) / len(accuracies) if accuracies else 0.0

        ttds = [r.time_to_detect_seconds for r in results if r.time_to_detect_seconds is not None]
        avg_ttd = sum(ttds) / len(ttds) if ttds else None

        blocking = [r.blocking_efficacy for r in results]
        overall_block = sum(blocking) / len(blocking) if blocking else 0.0

        noise = [r.noise_ratio for r in results]
        overall_noise = sum(noise) / len(noise) if noise else 0.0

        return BenchmarkReport(
            report_id=run_id,
            generated_at=now,
            edr_name=self.settings.edr.name,
            edr_version=self.settings.edr.version,
            scenario_results=results,
            overall_detection_rate=overall_dr,
            overall_contextual_accuracy=overall_acc,
            average_time_to_detect=avg_ttd,
            overall_blocking_efficacy=overall_block,
            overall_noise_ratio=overall_noise,
            total_scenarios=len(results),
            total_ground_truth_events=total_gt,
            total_findings=total_findings,
            total_errors=total_errors,
        )
