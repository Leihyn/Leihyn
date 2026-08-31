"""Case repositories for local demos and restart-safe Cloud Run deployments."""

from copy import deepcopy
import os
from threading import RLock
from typing import Any, Protocol

from .demo_case import new_demo_case


class CaseNotFoundError(KeyError):
    pass


class CaseRepository(Protocol):
    def reset_demo(self) -> dict[str, Any]: ...

    def get(self, case_id: str) -> dict[str, Any]: ...

    def save(self, case: dict[str, Any]) -> dict[str, Any]: ...


class InMemoryCaseRepository:
    def __init__(self) -> None:
        self._lock = RLock()
        self._cases: dict[str, dict[str, Any]] = {}

    def reset_demo(self) -> dict[str, Any]:
        with self._lock:
            case = new_demo_case()
            self._cases[str(case["id"])] = case
            return deepcopy(case)

    def get(self, case_id: str) -> dict[str, Any]:
        with self._lock:
            if case_id not in self._cases:
                raise CaseNotFoundError(case_id)
            return deepcopy(self._cases[case_id])

    def save(self, case: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._cases[str(case["id"])] = deepcopy(case)
            return deepcopy(case)


class FirestoreCaseRepository:
    """Firestore-backed repository used when CASEWORKER_REPOSITORY=firestore."""

    def __init__(self, project: str | None = None, collection: str = "caseworker_cases") -> None:
        from google.cloud import firestore

        self._client = firestore.Client(project=project)
        self._collection = self._client.collection(collection)

    def reset_demo(self) -> dict[str, Any]:
        case = new_demo_case()
        self._collection.document(str(case["id"])).set(case)
        return deepcopy(case)

    def get(self, case_id: str) -> dict[str, Any]:
        snapshot = self._collection.document(case_id).get()
        if not snapshot.exists:
            raise CaseNotFoundError(case_id)
        case = snapshot.to_dict()
        if not isinstance(case, dict):
            raise CaseNotFoundError(case_id)
        return deepcopy(case)

    def save(self, case: dict[str, Any]) -> dict[str, Any]:
        self._collection.document(str(case["id"])).set(case)
        return deepcopy(case)


def create_repository() -> CaseRepository:
    mode = os.getenv("CASEWORKER_REPOSITORY", "memory").strip().lower()
    if mode == "memory":
        return InMemoryCaseRepository()
    if mode == "firestore":
        return FirestoreCaseRepository(
            project=os.getenv("GOOGLE_CLOUD_PROJECT") or None,
            collection=os.getenv("CASEWORKER_FIRESTORE_COLLECTION", "caseworker_cases"),
        )
    raise ValueError("CASEWORKER_REPOSITORY must be 'memory' or 'firestore'.")
