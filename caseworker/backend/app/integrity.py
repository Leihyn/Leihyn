"""Canonical hashes for human-approved external actions."""

import hashlib
import json
from typing import Any


APPROVED_ACTION_FIELDS = (
    "action_type",
    "target_actor_id",
    "target_name",
    "subject",
    "draft_body",
    "evidence_ids",
)


def action_payload_hash(action: dict[str, Any]) -> str:
    """Hash only the fields whose contents the user is approving."""

    payload = {field: action.get(field) for field in APPROVED_ACTION_FIELDS}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"
