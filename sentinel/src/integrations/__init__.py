"""
External integrations for Sentinel.

- Immunefi: Bug bounty program data
- Etherscan: Verified contract source code
- Sourcify: Alternative source verification
"""

from .immunefi import ImmunefiClient, BountyProgram
from .etherscan import EtherscanClient, VerifiedContract

__all__ = [
    "ImmunefiClient",
    "BountyProgram",
    "EtherscanClient",
    "VerifiedContract",
]
