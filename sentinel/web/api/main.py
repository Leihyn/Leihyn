"""
FastAPI app for Sentinel Web.

Endpoints:
- POST /api/audit         Start an audit (returns job_id + ws_url)
- GET  /api/audit/{id}    Get job status
- WS   /api/audit/{id}/stream   Stream progress via WebSocket
- GET  /api/audit/{id}/report   Get final report + findings
"""

import queue as stdlib_queue
import shutil
import tempfile
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .schemas import AuditMode, AuditReport, AuditRequest, AuditResponse, FindingSummary, JobStatus
from .audit_runner import AuditJob, jobs, is_audit_running, set_current_job, run_audit_in_thread
from .github_cloner import clone_repo, cleanup_clone

app = FastAPI(title="Sentinel Web API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def cleanup_orphaned_temps():
    """Clean up any leftover sentinel_ temp dirs from previous runs."""
    tmp = Path(tempfile.gettempdir())
    for d in tmp.glob("sentinel_*"):
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)


@app.post("/api/audit", response_model=AuditResponse)
async def start_audit(request: AuditRequest):
    """Start a new audit. Returns 409 if one is already running."""
    if is_audit_running():
        raise HTTPException(status_code=409, detail="An audit is already running")

    job_id = uuid.uuid4().hex[:12]
    job = AuditJob(job_id=job_id)
    jobs[job_id] = job

    # Prepare the target
    if request.mode == AuditMode.GITHUB_URL:
        if not request.github_url:
            raise HTTPException(status_code=400, detail="github_url required for github_url mode")
        try:
            clone_result = await clone_repo(request.github_url)
            target_path = clone_result.audit_path
            job.temp_dir = clone_result.repo_dir
        except Exception as e:
            del jobs[job_id]
            raise HTTPException(status_code=400, detail=f"Failed to clone repo: {e}")

    elif request.mode == AuditMode.CODE_PASTE:
        if not request.code:
            raise HTTPException(status_code=400, detail="code required for code_paste mode")
        tmp_dir = Path(tempfile.mkdtemp(prefix="sentinel_"))
        target_path = tmp_dir / "contracts"
        target_path.mkdir()
        (target_path / request.filename).write_text(request.code)
        job.temp_dir = tmp_dir
        job.input_source = request.code
    else:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {request.mode}")

    set_current_job(job_id)

    # Start audit in background thread
    thread = threading.Thread(
        target=run_audit_in_thread,
        args=(job, target_path, request.depth, request.model),
        daemon=True,
    )
    job.thread = thread
    thread.start()

    return AuditResponse(
        job_id=job_id,
        ws_url=f"/api/audit/{job_id}/stream",
    )


@app.get("/api/audit/{job_id}", response_model=JobStatus)
async def get_job_status(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    return JobStatus(
        job_id=job.job_id,
        status=job.status,
        phase=job.phase,
        total_findings=len(job.findings),
        cost=job.cost,
        error=job.error,
    )


@app.websocket("/api/audit/{job_id}/stream")
async def audit_stream(websocket: WebSocket, job_id: str):
    """Stream audit progress via WebSocket."""
    job = jobs.get(job_id)
    if not job:
        await websocket.close(code=4004, reason="Job not found")
        return

    await websocket.accept()

    try:
        while True:
            try:
                msg = job.queue.get_nowait()
                await websocket.send_json(msg)

                # Update job phase from phase_start events
                if msg["type"] == "phase_start":
                    job.phase = msg["data"].get("phase")

                # Close after complete or error
                if msg["type"] in ("complete", "error"):
                    break

            except stdlib_queue.Empty:
                if job.status in ("complete", "error") and job.queue.empty():
                    break
                # Small sleep to avoid busy loop
                import asyncio
                await asyncio.sleep(0.1)

    except WebSocketDisconnect:
        pass


@app.get("/api/audit/{job_id}/report", response_model=AuditReport)
async def get_report(job_id: str):
    job = jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status not in ("complete", "error"):
        raise HTTPException(status_code=425, detail="Audit not yet complete")

    findings = [
        FindingSummary(
            id=f["id"],
            title=f["title"],
            severity=f["severity"],
            vulnerability_type=f["vulnerability_type"],
            contract=f["contract"],
            function=f.get("function"),
            description=f["description"],
            impact=f.get("impact", ""),
            recommendation=f.get("recommendation", ""),
            confidence=f.get("confidence", 0.0),
            validated=f.get("validated", False),
            poc_code=f.get("poc_code"),
            poc_output=f.get("poc_output"),
        )
        for f in job.findings
    ]

    return AuditReport(
        job_id=job_id,
        report_markdown=job.report or "",
        findings=findings,
        testing_diagram=job.testing_diagram,
        test_setup=job.test_setup,
        input_source=job.input_source,
        cost=job.cost,
        duration_seconds=job.duration,
    )
