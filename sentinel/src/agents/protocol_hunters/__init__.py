"""
Protocol-Specific Hunters - Deep expertise for major DeFi protocols.

Each hunter has:
- Deep knowledge of protocol architecture
- Known vulnerability patterns
- Protocol-specific invariants
- Integration edge cases
- Enhanced ultrathink prompts with protocol context
- Historical exploit references

Supported Protocols:
- Aave V3: Lending, eMode, liquidations
- Uniswap V3/V4: AMM, TWAP, hooks
- Curve: StableSwap, read-only reentrancy
- GMX: Perpetuals, price impact, funding
- Compound V3: Comet, absorption, interest
- Balancer: Rate providers, flash loans
- Lido: stETH rebasing, wstETH
"""

from .aave_hunter import AaveV3Hunter, AaveHunterConfig
from .uniswap_hunter import UniswapV3Hunter, UniswapV4Hunter, UniswapHunterConfig
from .curve_hunter import CurveHunter, CurveHunterConfig
from .gmx_hunter import GMXHunter, GMXHunterConfig
from .compound_hunter import CompoundV3Hunter, CompoundHunterConfig
from .balancer_hunter import BalancerHunter, BalancerHunterConfig
from .lido_hunter import LidoHunter, LidoHunterConfig

__all__ = [
    # Aave
    "AaveV3Hunter",
    "AaveHunterConfig",
    # Uniswap
    "UniswapV3Hunter",
    "UniswapV4Hunter",
    "UniswapHunterConfig",
    # Curve
    "CurveHunter",
    "CurveHunterConfig",
    # GMX
    "GMXHunter",
    "GMXHunterConfig",
    # Compound
    "CompoundV3Hunter",
    "CompoundHunterConfig",
    # Balancer
    "BalancerHunter",
    "BalancerHunterConfig",
    # Lido
    "LidoHunter",
    "LidoHunterConfig",
]
