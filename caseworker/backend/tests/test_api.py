import base64
import json

from fastapi.testclient import TestClient

from app.api import api


client = TestClient(api)


def test_health_and_public_config() -> None:
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["agent_framework"] == "google-adk"

    config = client.get("/api/config/public")
    assert config.status_code == 200
    assert config.json()["repository"] == "memory"


def test_http_workflow_reaches_dormant_checkpoint() -> None:
    assert client.post("/api/cases/demo").status_code == 200
    assert client.post(
        "/api/cases/CW-1042/actions/approve",
        json={"decided_by": "Maya Okeke"},
    ).status_code == 200

    executed = client.post("/api/cases/CW-1042/actions/execute")
    assert executed.status_code == 200
    assert executed.json()["status"] == "awaiting_response"


def test_pubsub_envelope_resumes_case_once() -> None:
    client.post("/api/cases/demo")
    client.post("/api/cases/CW-1042/actions/approve", json={})
    client.post("/api/cases/CW-1042/actions/execute")

    event = {
        "case_id": "CW-1042",
        "event_id": "api-event-42",
        "event_type": "merchant_denial",
    }
    encoded = base64.b64encode(json.dumps(event).encode()).decode()
    envelope = {"message": {"data": encoded}}

    first = client.post("/api/events/pubsub", json=envelope)
    second = client.post("/api/events/pubsub", json=envelope)
    assert first.status_code == second.status_code == 200

    case = client.get("/api/cases/CW-1042").json()
    assert case["status"] == "escalation_ready"
    assert case["processed_event_ids"].count("api-event-42") == 1
