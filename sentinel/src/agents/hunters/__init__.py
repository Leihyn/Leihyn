"""
Sentinel Hunter Agents - Specialized vulnerability detection.

Each hunter is an expert in detecting specific vulnerability classes
across multiple smart contract languages.
"""

from .reentrancy import ReentrancyHunter
from .access_control import AccessControlHunter
from .oracle import OracleManipulationHunter
from .flash_loan import FlashLoanHunter

__all__ = [
    "ReentrancyHunter",
    "AccessControlHunter",
    "OracleManipulationHunter",
    "FlashLoanHunter",
]


# Hunter registry for dynamic loading
HUNTERS = {
    "reentrancy": ReentrancyHunter,
    "access_control": AccessControlHunter,
    "oracle": OracleManipulationHunter,
    "flash_loan": FlashLoanHunter,
}


def get_hunter(name: str):
    """Get a hunter class by name."""
    return HUNTERS.get(name)


def get_all_hunters() -> list:
    """Get all available hunter classes."""
    return list(HUNTERS.values())


def get_hunter_names() -> list[str]:
    """Get names of all available hunters."""
    return list(HUNTERS.keys())
