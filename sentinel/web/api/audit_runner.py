"""
WebOrchestrator - subclass of Orchestrator that streams progress to a queue.

Overrides log(), _print_cost_status(), print_summary(), and run() to push
structured messages instead of printing to Rich console.
"""

import asyncio
import queue as stdlib_queue
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from src.agents.orchestrator import Orchestrator
from src.core.llm import get_llm_client, LLMClient
from src.core.types import Finding, Severity


@dataclass
class AuditJob:
    job_id: str
    status: str = "pending"  # pending, running, complete, error
    phase: Optional[str] = None
    queue: stdlib_queue.Queue = field(default_factory=stdlib_queue.Queue)
    error: Optional[str] = None
    report: Optional[str] = None
    findings: list[dict] = field(default_factory=list)
    testing_diagram: Optional[str] = None
    test_setup: Optional[str] = None
    input_source: Optional[str] = None
    cost: float = 0.0
    duration: float = 0.0
    started_at: Optional[datetime] = None
    thread: Optional[threading.Thread] = None
    temp_dir: Optional[Path] = None


# In-memory job store. One audit at a time.
jobs: dict[str, AuditJob] = {}
_current_job_id: Optional[str] = None
_lock = threading.Lock()


def is_audit_running() -> bool:
    with _lock:
        if _current_job_id is None:
            return False
        job = jobs.get(_current_job_id)
        return job is not None and job.status == "running"


def set_current_job(job_id: Optional[str]) -> None:
    global _current_job_id
    with _lock:
        _current_job_id = job_id


class WebOrchestrator(Orchestrator):
    """Orchestrator that pushes progress messages to a thread-safe queue."""

    def __init__(self, msg_queue: stdlib_queue.Queue, **kwargs):
        self.msg_queue = msg_queue
        kwargs["verbose"] = False
        super().__init__(**kwargs)

    def _emit(self, msg_type: str, data: dict) -> None:
        self.msg_queue.put({
            "type": msg_type,
            "timestamp": datetime.now().isoformat(),
            "data": data,
        })

    def log(self, message: str, style: str = "white") -> None:
        self._emit("log", {"message": message, "style": style})
        self.state.add_log(f"[Orchestrator] {message}")

    def _print_cost_status(self, phase_label: str = "") -> None:
        stats = self.llm.get_stats()
        self._emit("cost_update", {
            "total_cost": stats["total_cost"],
            "total_input_tokens": stats["total_input_tokens"],
            "total_output_tokens": stats["total_output_tokens"],
            "total_thinking_tokens": stats["total_thinking_tokens"],
            "prompt_cache_savings": stats["prompt_cache_savings"],
            "cache_hits": stats["cache_hits"],
            "phase_label": phase_label,
        })

    def print_summary(self) -> None:
        """Suppress Rich summary output."""
        pass

    def _emit_finding(self, finding: Finding) -> None:
        self._emit("finding", {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "vulnerability_type": finding.vulnerability_type.value,
            "contract": finding.contract,
            "function": finding.function,
            "description": finding.description[:500],
            "impact": finding.impact[:300] if finding.impact else "",
            "recommendation": finding.recommendation[:300] if finding.recommendation else "",
            "confidence": finding.confidence,
            "validated": finding.validated,
        })

    async def run_phase_recon(self) -> None:
        self._emit("phase_start", {"phase": "Reconnaissance"})
        await super().run_phase_recon()
        self._emit("phase_complete", {
            "phase": "Reconnaissance",
            "contracts_found": len(self.state.contracts),
        })

    async def run_phase_static_analysis(self) -> None:
        self._emit("phase_start", {"phase": "Static Analysis"})
        await super().run_phase_static_analysis()
        self._emit("phase_complete", {
            "phase": "Static Analysis",
            "issues_found": len(self.state.slither_results),
        })

    async def run_phase_cross_contract_analysis(self) -> None:
        self._emit("phase_start", {"phase": "Cross-Contract Analysis"})
        await super().run_phase_cross_contract_analysis()
        edges = len(self.state.dependency_graph.edges) if self.state.dependency_graph else 0
        self._emit("phase_complete", {
            "phase": "Cross-Contract Analysis",
            "edges_found": edges,
        })

    async def run_phase_test_plan(self) -> None:
        self._emit("phase_start", {"phase": "Test Plan"})
        await super().run_phase_test_plan()
        self._emit("phase_complete", {"phase": "Test Plan"})

    async def run_phase_protocol_intent(self) -> None:
        self._emit("phase_start", {"phase": "Protocol Intent"})
        await super().run_phase_protocol_intent()
        self._emit("phase_complete", {"phase": "Protocol Intent"})

    async def run_phase_deep_analysis(self) -> None:
        self._emit("phase_start", {"phase": "Deep Analysis"})
        findings_before = len(self.state.findings)
        await super().run_phase_deep_analysis()
        findings_after = len(self.state.findings)
        new_findings = findings_after - findings_before
        # Emit each new finding
        for f in self.state.findings[findings_before:]:
            self._emit_finding(f)
        self._emit("phase_complete", {
            "phase": "Deep Analysis",
            "findings_found": new_findings,
        })

    async def run_phase_validation(self) -> None:
        self._emit("phase_start", {"phase": "Validation"})
        await super().run_phase_validation()
        self._emit("phase_complete", {
            "phase": "Validation",
            "findings_remaining": len(self.state.findings),
        })

    async def run_phase_c4_gate(self) -> None:
        self._emit("phase_start", {"phase": "C4 Severity Gate"})
        await super().run_phase_c4_gate()
        self._emit("phase_complete", {
            "phase": "C4 Severity Gate",
            "findings_remaining": len(self.state.findings),
        })

    async def run_phase_attack_synthesis(self) -> None:
        self._emit("phase_start", {"phase": "Attack Synthesis"})
        await super().run_phase_attack_synthesis()
        self._emit("phase_complete", {"phase": "Attack Synthesis"})

    async def run_phase_poc_generation(self) -> None:
        self._emit("phase_start", {"phase": "PoC Generation"})
        await super().run_phase_poc_generation()
        verified = sum(1 for f in self.state.findings if f.validated)
        self._emit("phase_complete", {
            "phase": "PoC Generation",
            "verified_count": verified,
        })

    async def run_phase_reporting(self) -> None:
        self._emit("phase_start", {"phase": "Report Generation"})
        # Don't call super() — it calls print_summary() which uses Rich.
        # Instead, do the minimal work: set end_time and generate report.
        self.state.end_time = datetime.now()
        report = self.generate_report()

        # Capture testing artifacts if they were generated
        testing_diagram = None
        test_setup = None
        diagram_path = self.target_path / "testing-diagram.md"
        setup_path = self.target_path / "test-setup.md"
        if diagram_path.exists():
            testing_diagram = diagram_path.read_text()
        if setup_path.exists():
            test_setup = setup_path.read_text()

        self._emit("artifact", {
            "type": "report",
            "content": report,
        })
        if testing_diagram:
            self._emit("artifact", {
                "type": "testing_diagram",
                "content": testing_diagram,
            })
        if test_setup:
            self._emit("artifact", {
                "type": "test_setup",
                "content": test_setup,
            })

        self._emit("phase_complete", {"phase": "Report Generation"})

    async def run(self, resume_from=None, poc_only=False):
        """Override run() to suppress Rich console output from the base class."""
        # The parent run() calls console.print(Panel(...)) directly.
        # We replicate the phase flow but without Rich output.
        CREDIT_ERROR = "credit balance is too low"

        try:
            if resume_from:
                from src.core.types import AuditState
                self.state = AuditState.load_checkpoint(Path(resume_from))
                self.log(f"Resumed from checkpoint: {len(self.state.findings)} findings loaded")
            else:
                await self.run_phase_recon()
                self._print_cost_status("Recon")

                from src.knowledge.vulnerability_registry import VulnerabilityRegistry
                registry = VulnerabilityRegistry.get_instance()
                self.state.vulnerability_cheatsheet = registry.generate_cheatsheet(
                    language=self.language.value, depth=self.depth,
                )

                await self.run_phase_static_analysis()

                if self.depth in ("standard", "deep"):
                    await self.run_phase_cross_contract_analysis()
                self._print_cost_status("Static + Cross-Contract")

                await self.run_phase_test_plan()
                self._print_cost_status("Test Plan")

                if self.depth in ("standard", "deep"):
                    await self.run_phase_protocol_intent()
                    self._print_cost_status("Protocol Intent")

                await self.run_phase_deep_analysis()
                self._print_cost_status("Hunters")

                self._save_checkpoint("hunters")

            self._deduplicate_findings()
            self._enrich_call_chains()

            if self.depth in ("standard", "deep"):
                await self._confirm_findings()
                self._print_cost_status("Finding Confirmation")

            if poc_only:
                self.log("--poc-only: Skipping validation and attack synthesis")
            else:
                if self.depth in ("standard", "deep"):
                    await self.run_phase_validation()
                    self._print_cost_status("Validation")

                await self.run_phase_c4_gate()
                self._print_cost_status("C4 Gate")

                if self.depth == "deep":
                    await self.run_phase_attack_synthesis()
                    self._print_cost_status("Attack Synthesis")

            if self.depth in ("standard", "deep") and self.state.findings:
                await self.run_phase_poc_generation()
                self._print_cost_status("PoC Generation")

            self._save_checkpoint("pre_report")
            await self.run_phase_reporting()

        except Exception as e:
            error_msg = str(e)
            is_credit_error = CREDIT_ERROR in error_msg.lower()

            if is_credit_error:
                self.log("Credit balance exhausted. Saving partial report...")
            else:
                self.log(f"Audit failed: {e}")

            try:
                self._save_checkpoint("partial")
                self.state.end_time = datetime.now()
                report = self.generate_report()
                self._emit("artifact", {"type": "report", "content": report})
            except Exception:
                pass

            if is_credit_error:
                return self.state
            raise

        return self.state


def run_audit_in_thread(job: AuditJob, target_path: Path, depth: str, model: str) -> None:
    """Run an audit in a new thread with its own event loop."""
    try:
        job.status = "running"
        job.started_at = datetime.now()

        # Reset the LLM client singleton for fresh cost tracking
        import src.core.llm as llm_module
        llm_module._llm_client = None
        get_llm_client(model=model)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        orchestrator = WebOrchestrator(
            msg_queue=job.queue,
            target_path=target_path,
            depth=depth,
        )

        state = loop.run_until_complete(orchestrator.run())

        # Collect results
        job.cost = orchestrator.llm.get_stats()["total_cost"]
        job.duration = (datetime.now() - job.started_at).total_seconds()
        job.report = orchestrator.generate_report()
        job.findings = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "vulnerability_type": f.vulnerability_type.value,
                "contract": f.contract,
                "function": f.function,
                "description": f.description,
                "impact": f.impact,
                "recommendation": f.recommendation,
                "confidence": f.confidence,
                "validated": f.validated,
                "poc_code": f.poc.code if f.poc else None,
                "poc_output": f.poc.output if f.poc else None,
            }
            for f in state.findings
        ]

        # Capture testing artifacts
        diagram_path = target_path / "testing-diagram.md"
        setup_path = target_path / "test-setup.md"
        if diagram_path.exists():
            job.testing_diagram = diagram_path.read_text()
        if setup_path.exists():
            job.test_setup = setup_path.read_text()

        job.status = "complete"
        job.queue.put({
            "type": "complete",
            "timestamp": datetime.now().isoformat(),
            "data": {
                "total_findings": len(job.findings),
                "cost": job.cost,
                "duration": job.duration,
            },
        })

    except Exception as e:
        job.status = "error"
        job.error = str(e)
        job.queue.put({
            "type": "error",
            "timestamp": datetime.now().isoformat(),
            "data": {"message": str(e)},
        })

    finally:
        loop.close()
        set_current_job(None)
