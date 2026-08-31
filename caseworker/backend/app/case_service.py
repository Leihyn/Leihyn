"""Case transitions with approval and idempotency enforcement."""

from datetime import UTC, datetime, timedelta
from typing import Any

from .integrity import action_payload_hash
from .repository import CaseNotFoundError, CaseRepository, InMemoryCaseRepository


class InvalidTransitionError(ValueError):
    pass


class ApprovalRequiredError(PermissionError):
    pass


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class CaseService:
    def __init__(self, repository: CaseRepository | None = None) -> None:
        self.repository = repository or InMemoryCaseRepository()
        try:
            self.repository.get("CW-1042")
        except CaseNotFoundError:
            self.repository.reset_demo()

    def reset_demo(self) -> dict[str, Any]:
        return self.repository.reset_demo()

    def get_case(self, case_id: str) -> dict[str, Any]:
        return self.repository.get(case_id)

    def approve_current_action(self, case_id: str, decided_by: str = "Maya Okeke") -> dict[str, Any]:
        case = self.repository.get(case_id)
        action = case.get("current_action")
        if not isinstance(action, dict) or action.get("status") != "approval_required":
            raise InvalidTransitionError("The current action is not awaiting approval.")

        action["status"] = "approved"
        action["approved_at"] = now_iso()
        action["approved_by"] = decided_by
        action["approved_payload_hash"] = action_payload_hash(action)
        action["payload_hash"] = action["approved_payload_hash"]
        case.setdefault("audit", []).append(
            {
                "id": f"AUD-{len(case['audit']) + 1:02d}",
                "agent": "human_approval",
                "summary": f"{decided_by} approved the exact {action['action_type']} payload.",
                "at": now_iso(),
            }
        )
        return self._save(case)

    def execute_current_action(self, case_id: str) -> dict[str, Any]:
        case = self.repository.get(case_id)
        action = case.get("current_action")
        if not isinstance(action, dict):
            raise InvalidTransitionError("There is no executable action.")
        if action.get("status") != "approved":
            raise ApprovalRequiredError("External correspondence requires approval.")
        current_hash = action_payload_hash(action)
        if action.get("approved_payload_hash") != current_hash or action.get("payload_hash") != current_hash:
            action["status"] = "approval_required"
            action.pop("approved_at", None)
            action.pop("approved_by", None)
            action.pop("approved_payload_hash", None)
            action["payload_hash"] = current_hash
            self._save(case)
            raise ApprovalRequiredError("The approved payload changed and requires a new approval.")

        action["status"] = "succeeded"
        action["executed_at"] = now_iso()
        case.setdefault("correspondence", []).append(
            {
                "id": f"MSG-{len(case['correspondence']) + 1:02d}",
                "direction": "outbound",
                "actor_id": action["target_actor_id"],
                "actor_name": action["target_name"],
                "subject": action["subject"],
                "body": action["draft_body"],
                "evidence_ids": action["evidence_ids"],
                "at": now_iso(),
            }
        )
        is_escalation = action.get("action_type") == "escalate"
        due_at = datetime.now(UTC) + timedelta(days=5 if is_escalation else 2)
        case["deadlines"] = [
            {
                "id": "DL-01",
                "label": "Payment-provider response check" if is_escalation else "Merchant response check",
                "due_at": due_at.isoformat().replace("+00:00", "Z"),
                "status": "scheduled",
                "wake_topic": "caseworker-wake",
            }
        ]
        case["status"] = "awaiting_response"
        case.setdefault("audit", []).append(
            {
                "id": f"AUD-{len(case['audit']) + 1:02d}",
                "agent": "correspondence_agent",
                "summary": f"Sent the approved {action['action_type']} payload and scheduled a response wake event.",
                "at": now_iso(),
            }
        )
        return self._save(case)

    def ingest_demo_denial(self, case_id: str, event_id: str = "DEMO-DENIAL-01") -> dict[str, Any]:
        case = self.repository.get(case_id)
        processed = case.setdefault("processed_event_ids", [])
        if event_id in processed:
            return case
        if case.get("status") != "awaiting_response":
            raise InvalidTransitionError("A denial can only resume an awaiting case.")

        processed.append(event_id)
        case.setdefault("correspondence", []).append(
            {
                "id": "MSG-05",
                "direction": "inbound",
                "actor_id": "A-MERCHANT",
                "actor_name": "Northstar Market",
                "subject": "Re: Order NS-88214",
                "body": "Tracking confirms delivery. We cannot issue a refund. Please resolve this directly with SwiftDrop.",
                "evidence_ids": [],
                "at": now_iso(),
            }
        )
        case["deadlines"] = []
        case["status"] = "escalation_ready"
        case["current_action"] = {
            "id": "ACT-02",
            "action_type": "escalate",
            "status": "approval_required",
            "target_actor_id": "A-PAYMENT",
            "target_name": "Card provider",
            "reason": "The merchant repeated the delivered scan without addressing the conflicting address evidence or opening the courier investigation only it can initiate.",
            "subject": "Goods not received — order NS-88214",
            "draft_body": (
                "I am disputing the $184.20 Northstar Market transaction for goods not received. The order "
                "address is number 18 [EV-01], while the courier proof shows number 16 [EV-02]. The courier "
                "says Northstar must open the investigation [EV-04], but Northstar declined and redirected me "
                "to the courier [MSG-05]. The attached record contains the original evidence and correspondence."
            ),
            "evidence_ids": ["EV-01", "EV-02", "EV-03", "EV-04", "MSG-05"],
            "payload_hash": "",
        }
        case["current_action"]["payload_hash"] = action_payload_hash(case["current_action"])
        case.setdefault("audit", []).extend(
            [
                {
                    "id": f"AUD-{len(case['audit']) + 1:02d}",
                    "agent": "response_agent",
                    "summary": "Pub/Sub wake resumed the dormant case and classified the merchant reply as a denial that does not address the material contradiction.",
                    "at": now_iso(),
                },
                {
                    "id": f"AUD-{len(case['audit']) + 2:02d}",
                    "agent": "verifier_agent",
                    "summary": "Verified the escalation packet against five source items; no unsupported law or policy claims remain.",
                    "at": now_iso(),
                },
            ]
        )
        return self._save(case)

    def _save(self, case: dict[str, Any]) -> dict[str, Any]:
        case["revision"] = int(case.get("revision", 0)) + 1
        case["updated_at"] = now_iso()
        return self.repository.save(case)

    def ingest_demo_resolution(self, case_id: str, event_id: str = "DEMO-RESOLUTION-01") -> dict[str, Any]:
        case = self.repository.get(case_id)
        processed = case.setdefault("processed_event_ids", [])
        if event_id in processed:
            return case
        if case.get("status") != "awaiting_response" or not case.get("correspondence"):
            raise InvalidTransitionError("Resolution requires an executed approved escalation.")

        processed.append(event_id)
        case.setdefault("correspondence", []).append(
            {
                "id": "MSG-07",
                "direction": "inbound",
                "actor_id": "A-PAYMENT",
                "actor_name": "Card provider",
                "subject": "Dispute resolved",
                "body": "Your $184.20 dispute has been resolved in your favor. The credit is now final.",
                "evidence_ids": [],
                "at": now_iso(),
            }
        )
        case["status"] = "resolved"
        case["resolved_at"] = now_iso()
        case["resolution"] = {
            "outcome": "Full refund",
            "amount": 184.20,
            "currency": "USD",
            "summary": "The card provider resolved the goods-not-received dispute in Maya's favor.",
        }
        case["deadlines"] = []
        case["current_action"] = None
        case.setdefault("audit", []).append(
            {
                "id": f"AUD-{len(case['audit']) + 1:02d}",
                "agent": "response_agent",
                "summary": "Verified the inbound resolution and closed the case with a full refund.",
                "at": now_iso(),
            }
        )
        return self._save(case)
