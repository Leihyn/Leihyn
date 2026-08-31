"""Caseworker ADK application package.

The lazy export keeps domain tests runnable before optional cloud dependencies
are installed while preserving ``from app import app`` for ADK discovery.
"""

from typing import Any

__all__ = ["app", "root_agent"]


def __getattr__(name: str) -> Any:
    if name not in __all__:
        raise AttributeError(name)
    from .agent import app, root_agent

    return {"app": app, "root_agent": root_agent}[name]
