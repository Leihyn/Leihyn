"""
SENTINEL Agents - World-class smart contract security auditing.

Core Agents:
- Orchestrator: Main audit coordination
- ReconAgent: Initial reconnaissance
- DeepHunterAgent: Deep vulnerability analysis with ultrathink
- InvariantAgent: Invariant-based vulnerability detection
- AttackSynthesizerAgent: Combine findings into attack chains
- PoCGeneratorAgent: Generate Foundry PoCs
- DevilsAdvocateAgent: Validate and challenge findings
- HunterSwarm: Multi-agent parallel hunting

Protocol-Specific Hunters:
- AaveV3Hunter: Aave V3 integration vulnerabilities
- UniswapV3Hunter: Uniswap V3 integration vulnerabilities
- UniswapV4Hunter: Uniswap V4 hook vulnerabilities
- CurveHunter: Curve Finance integration vulnerabilities
"""

from .orchestrator import Orchestrator, run_audit
from .recon import ReconAgent
from .deep_hunter import DeepHunterAgent, DeepAnalysisConfig, deep_hunt
from .invariant_agent import InvariantAgent, InvariantConfig, hunt_invariants
from .attack_synthesizer import AttackSynthesizerAgent, AttackSynthesisConfig, synthesize_attacks
from .poc_generator import PoCGeneratorAgent, PoCConfig, generate_pocs
from .devils_advocate import DevilsAdvocateAgent, DevilsAdvocateConfig, validate_findings
from .hunter_swarm import HunterSwarm, SwarmConfig, hunt_with_swarm

# Protocol-specific hunters
from .protocol_hunters import (
    AaveV3Hunter,
    UniswapV3Hunter,
    UniswapV4Hunter,
    CurveHunter,
)

__all__ = [
    # Core
    "Orchestrator",
    "run_audit",
    "ReconAgent",
    # Deep Analysis
    "DeepHunterAgent",
    "DeepAnalysisConfig",
    "deep_hunt",
    # Invariants
    "InvariantAgent",
    "InvariantConfig",
    "hunt_invariants",
    # Attack Synthesis
    "AttackSynthesizerAgent",
    "AttackSynthesisConfig",
    "synthesize_attacks",
    # PoC Generation
    "PoCGeneratorAgent",
    "PoCConfig",
    "generate_pocs",
    # Validation
    "DevilsAdvocateAgent",
    "DevilsAdvocateConfig",
    "validate_findings",
    # Multi-Agent
    "HunterSwarm",
    "SwarmConfig",
    "hunt_with_swarm",
    # Protocol Hunters
    "AaveV3Hunter",
    "UniswapV3Hunter",
    "UniswapV4Hunter",
    "CurveHunter",
]
