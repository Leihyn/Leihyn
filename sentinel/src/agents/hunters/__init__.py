"""
Sentinel Hunter Agents - Specialized vulnerability detection.

Each hunter is an expert in detecting specific vulnerability classes
across multiple smart contract languages.
"""

from .reentrancy import ReentrancyHunter
from .access_control import AccessControlHunter
from .oracle import OracleManipulationHunter
from .flash_loan import FlashLoanHunter
from .parameter_validation import ParameterValidationHunter
from .math_verification import MathVerificationHunter
from .slippage import SlippageHunter
from .algebraic_verification import AlgebraicVerificationHunter
from .invariant_fuzzer import InvariantFuzzerHunter
from .sequence_explorer import SequenceExplorerHunter
from .halmos_prover import HalmosProverHunter
from .known_bug_replay import KnownBugReplayHunter

__all__ = [
    "ReentrancyHunter",
    "AccessControlHunter",
    "OracleManipulationHunter",
    "FlashLoanHunter",
    "ParameterValidationHunter",
    "MathVerificationHunter",
    "SlippageHunter",
    "AlgebraicVerificationHunter",
    "InvariantFuzzerHunter",
    "SequenceExplorerHunter",
    "HalmosProverHunter",
    "KnownBugReplayHunter",
]


# Hunter registry for dynamic loading
HUNTERS = {
    "reentrancy": ReentrancyHunter,
    "access_control": AccessControlHunter,
    "oracle": OracleManipulationHunter,
    "flash_loan": FlashLoanHunter,
    "parameter_validation": ParameterValidationHunter,
    "math_verification": MathVerificationHunter,
    "slippage": SlippageHunter,
    "algebraic_verification": AlgebraicVerificationHunter,
    "invariant_fuzzer": InvariantFuzzerHunter,
    "sequence_explorer": SequenceExplorerHunter,
    "halmos_prover": HalmosProverHunter,
    "known_bug_replay": KnownBugReplayHunter,
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
