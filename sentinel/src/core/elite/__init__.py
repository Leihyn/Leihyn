"""
SENTINEL Elite - The Absolute Maximum

These modules represent the cutting edge of automated security analysis.
They go beyond what any single auditor can do.

Components:
- live_exploit_db: Real-time exploit monitoring and learning
- onchain_sim: Fork mainnet, simulate attacks on real state
- multi_llm: Ensemble of multiple LLMs for consensus
- auto_poc: Automated PoC compilation and execution
- self_improve: Learning from past audits and results
- competition_intel: Contest-specific optimization
"""

from .live_exploit_db import (
    ExploitDatabase,
    ExploitMonitor,
    get_recent_exploits,
    match_to_known_exploit,
)

from .onchain_sim import (
    OnChainSimulator,
    fork_and_test,
    simulate_attack,
    get_contract_state,
)

from .multi_llm import (
    MultiLLMConsensus,
    ConsensusResult,
    get_consensus_finding,
)

from .auto_poc import (
    AutoPoCExecutor,
    compile_and_run,
    validate_poc_onchain,
    PoCExecutionResult,
)

from .self_improve import (
    AuditFeedbackLoop,
    learn_from_result,
    get_historical_accuracy,
)

__all__ = [
    # Live Exploits
    "ExploitDatabase",
    "ExploitMonitor",
    "get_recent_exploits",
    "match_to_known_exploit",
    # On-Chain Simulation
    "OnChainSimulator",
    "fork_and_test",
    "simulate_attack",
    "get_contract_state",
    # Multi-LLM
    "MultiLLMConsensus",
    "ConsensusResult",
    "get_consensus_finding",
    # Auto PoC
    "AutoPoCExecutor",
    "compile_and_run",
    "validate_poc_onchain",
    "PoCExecutionResult",
    # Self-Improvement
    "AuditFeedbackLoop",
    "learn_from_result",
    "get_historical_accuracy",
]
