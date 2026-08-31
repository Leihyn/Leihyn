import pytest

from app.case_service import ApprovalRequiredError, CaseService
from app.repository import InMemoryCaseRepository


def test_external_action_requires_approval() -> None:
    service = CaseService()
    with pytest.raises(ApprovalRequiredError):
        service.execute_current_action("CW-1042")


def test_complete_demo_path() -> None:
    service = CaseService()

    approved = service.approve_current_action("CW-1042")
    assert approved["current_action"]["status"] == "approved"

    waiting = service.execute_current_action("CW-1042")
    assert waiting["status"] == "awaiting_response"
    assert waiting["deadlines"][0]["wake_topic"] == "caseworker-wake"

    escalating = service.ingest_demo_denial("CW-1042")
    assert escalating["status"] == "escalation_ready"
    assert escalating["current_action"]["action_type"] == "escalate"

    service.approve_current_action("CW-1042")
    service.execute_current_action("CW-1042")
    resolved = service.ingest_demo_resolution("CW-1042")

    assert resolved["status"] == "resolved"
    assert resolved["resolution"]["amount"] == 184.20


def test_wake_event_is_idempotent() -> None:
    service = CaseService()
    service.approve_current_action("CW-1042")
    service.execute_current_action("CW-1042")

    first = service.ingest_demo_denial("CW-1042", "event-42")
    second = service.ingest_demo_denial("CW-1042", "event-42")

    assert first["revision"] == second["revision"]
    assert [item["id"] for item in second["correspondence"]].count("MSG-05") == 1


def test_approved_payload_cannot_change_before_execution() -> None:
    repository = InMemoryCaseRepository()
    service = CaseService(repository)
    service.approve_current_action("CW-1042")

    tampered = repository.get("CW-1042")
    tampered["current_action"]["draft_body"] += " Invented policy claim."
    repository.save(tampered)

    with pytest.raises(ApprovalRequiredError, match="requires a new approval"):
        service.execute_current_action("CW-1042")

    held = service.get_case("CW-1042")
    assert held["current_action"]["status"] == "approval_required"
    assert "approved_payload_hash" not in held["current_action"]


def test_existing_repository_is_not_reset_on_service_restart() -> None:
    repository = InMemoryCaseRepository()
    first_service = CaseService(repository)
    first_service.approve_current_action("CW-1042")

    restarted_service = CaseService(repository)
    assert restarted_service.get_case("CW-1042")["current_action"]["status"] == "approved"
