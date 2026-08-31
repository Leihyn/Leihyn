"""FastAPI surface for the Caseworker demo and Cloud Run service."""

import base64
import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .agent import MODEL
from .case_service import ApprovalRequiredError, CaseService, InvalidTransitionError
from .repository import CaseNotFoundError, create_repository


service = CaseService(create_repository())
api = FastAPI(title="Caseworker API", version="0.1.0")
cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CASEWORKER_CORS_ORIGINS",
        "http://127.0.0.1:4173,http://localhost:4173",
    ).split(",")
    if origin.strip()
]
api.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class ApprovalBody(BaseModel):
    decided_by: str = "Maya Okeke"


class AgentAnalysisBody(BaseModel):
    case_id: str = "CW-1042"
    question: str = "Verify the material contradiction and recommend one bounded next action."


def translate_error(error: Exception) -> HTTPException:
    if isinstance(error, CaseNotFoundError):
        return HTTPException(status_code=404, detail="Case not found.")
    if isinstance(error, ApprovalRequiredError):
        return HTTPException(status_code=403, detail=str(error))
    if isinstance(error, InvalidTransitionError):
        return HTTPException(status_code=409, detail=str(error))
    return HTTPException(status_code=500, detail="The case operation failed.")


@api.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "caseworker", "agent_framework": "google-adk"}


@api.get("/api/config/public")
def public_config() -> dict[str, str]:
    return {
        "agent_framework": "google-adk",
        "model": MODEL,
        "repository": os.getenv("CASEWORKER_REPOSITORY", "memory"),
        "runtime": "cloud-run" if os.getenv("K_SERVICE") else "local",
    }


@api.post("/api/agent/analyze")
async def agent_analyze(body: AgentAnalysisBody) -> dict[str, str]:
    try:
        from .agent_runtime import analyze_case

        service.get_case(body.case_id)
        return await analyze_case(body.case_id, body.question)
    except Exception as error:
        raise translate_error(error) from error


@api.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    try:
        return service.get_case(case_id)
    except Exception as error:
        raise translate_error(error) from error


@api.post("/api/cases/demo")
def reset_demo() -> dict[str, Any]:
    return service.reset_demo()


@api.post("/api/cases/{case_id}/actions/approve")
def approve_action(case_id: str, body: ApprovalBody) -> dict[str, Any]:
    try:
        return service.approve_current_action(case_id, body.decided_by)
    except Exception as error:
        raise translate_error(error) from error


@api.post("/api/cases/{case_id}/actions/execute")
def execute_action(case_id: str) -> dict[str, Any]:
    try:
        return service.execute_current_action(case_id)
    except Exception as error:
        raise translate_error(error) from error


@api.post("/api/cases/{case_id}/events/demo-denial")
def demo_denial(case_id: str) -> dict[str, Any]:
    try:
        return service.ingest_demo_denial(case_id)
    except Exception as error:
        raise translate_error(error) from error


@api.post("/api/cases/{case_id}/events/demo-resolution")
def demo_resolution(case_id: str) -> dict[str, Any]:
    try:
        return service.ingest_demo_resolution(case_id)
    except Exception as error:
        raise translate_error(error) from error


@api.post("/api/events/pubsub")
async def pubsub_event(request: Request) -> dict[str, bool]:
    verify_pubsub_identity(request)
    envelope = await request.json()
    try:
        encoded = envelope["message"]["data"]
        event = json.loads(base64.b64decode(encoded).decode("utf-8"))
        case_id = str(event["case_id"])
        event_id = str(event["event_id"])
        event_type = str(event["event_type"])
        if event_type == "merchant_denial":
            service.ingest_demo_denial(case_id, event_id)
        elif event_type == "dispute_resolution":
            service.ingest_demo_resolution(case_id, event_id)
        else:
            raise ValueError("Unsupported event type")
    except Exception as error:
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub event.") from error
    return {"accepted": True}


def verify_pubsub_identity(request: Request) -> None:
    """Verify Pub/Sub's OIDC token when a production audience is configured."""

    audience = os.getenv("CASEWORKER_PUBSUB_AUDIENCE")
    if not audience:
        return
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Pub/Sub identity token.")
    try:
        from google.auth.transport.requests import Request as GoogleRequest
        from google.oauth2 import id_token

        claims = id_token.verify_oauth2_token(
            authorization.removeprefix("Bearer "),
            GoogleRequest(),
            audience=audience,
        )
    except Exception as error:
        raise HTTPException(status_code=401, detail="Invalid Pub/Sub identity token.") from error
    allowed_email = os.getenv("CASEWORKER_PUBSUB_SERVICE_ACCOUNT")
    if allowed_email and claims.get("email") != allowed_email:
        raise HTTPException(status_code=403, detail="Unexpected Pub/Sub service account.")


static_dir = Path(os.getenv("CASEWORKER_STATIC_DIR", Path(__file__).resolve().parents[2] / "dist"))
if static_dir.is_dir():
    api.mount("/", StaticFiles(directory=static_dir, html=True), name="web")
