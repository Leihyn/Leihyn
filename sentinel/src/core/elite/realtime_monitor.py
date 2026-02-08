"""
Real-Time Blockchain Monitoring

Watch the blockchain as it happens:
- New contract deployments
- Pending transactions (mempool)
- Exploit attempts in progress
- Suspicious patterns

This is how you catch exploits BEFORE they drain funds.
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
from enum import Enum
from datetime import datetime
import re


class Chain(Enum):
    ETHEREUM = "ethereum"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    BASE = "base"
    BSC = "bsc"
    POLYGON = "polygon"
    AVALANCHE = "avalanche"


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EXPLOIT_IN_PROGRESS = "exploit_in_progress"


@dataclass
class DeploymentEvent:
    """New contract deployment detected."""
    chain: Chain
    deployer: str
    contract_address: str
    bytecode: str
    timestamp: datetime
    block_number: int
    tx_hash: str


@dataclass
class MempoolTransaction:
    """Pending transaction from mempool."""
    chain: Chain
    from_address: str
    to_address: str
    value: int
    data: str
    gas_price: int
    gas_limit: int
    nonce: int
    tx_hash: str
    first_seen: datetime


@dataclass
class ExploitAlert:
    """Alert for potential exploit."""
    severity: AlertSeverity
    chain: Chain
    alert_type: str
    description: str
    tx_hash: Optional[str]
    addresses_involved: list[str]
    estimated_impact_usd: float
    timestamp: datetime
    recommended_action: str


# =============================================================================
# RPC PROVIDERS
# =============================================================================

RPC_ENDPOINTS = {
    Chain.ETHEREUM: [
        "https://eth.llamarpc.com",
        "https://rpc.ankr.com/eth",
        "https://ethereum.publicnode.com",
    ],
    Chain.ARBITRUM: [
        "https://arb1.arbitrum.io/rpc",
        "https://rpc.ankr.com/arbitrum",
    ],
    Chain.OPTIMISM: [
        "https://mainnet.optimism.io",
        "https://rpc.ankr.com/optimism",
    ],
    Chain.BASE: [
        "https://mainnet.base.org",
        "https://base.llamarpc.com",
    ],
    Chain.BSC: [
        "https://bsc-dataseed.binance.org",
        "https://rpc.ankr.com/bsc",
    ],
    Chain.POLYGON: [
        "https://polygon-rpc.com",
        "https://rpc.ankr.com/polygon",
    ],
}

MEMPOOL_PROVIDERS = {
    "flashbots": "https://protect.flashbots.net",
    "bloxroute": "wss://virginia.eth.blxrbdn.com/ws",
    "blocknative": "wss://api.blocknative.com/v0",
}


# =============================================================================
# DEPLOYMENT MONITOR
# =============================================================================

class DeploymentMonitor:
    """
    Monitor new contract deployments across chains.

    Instantly analyze every new contract for vulnerabilities.
    """

    # Known vulnerable bytecode patterns
    VULNERABLE_BYTECODE_PATTERNS = {
        # Selfdestruct
        "selfdestruct": "ff",
        # Delegatecall
        "delegatecall": "f4",
        # Call with value
        "call_with_value": "f1",
    }

    # Known proxy patterns
    PROXY_PATTERNS = {
        "eip1967": "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
        "eip1822": "c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7",
        "transparent": "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    }

    def __init__(self, chains: list[Chain] = None):
        self.chains = chains or list(Chain)
        self.callbacks: list[Callable[[DeploymentEvent], None]] = []
        self.running = False

    def on_deployment(self, callback: Callable[[DeploymentEvent], None]):
        """Register callback for new deployments."""
        self.callbacks.append(callback)

    async def start(self):
        """Start monitoring deployments."""
        self.running = True

        tasks = []
        for chain in self.chains:
            task = asyncio.create_task(self._monitor_chain(chain))
            tasks.append(task)

        await asyncio.gather(*tasks)

    async def stop(self):
        """Stop monitoring."""
        self.running = False

    async def _monitor_chain(self, chain: Chain):
        """Monitor a single chain for deployments."""

        rpc_urls = RPC_ENDPOINTS.get(chain, [])
        if not rpc_urls:
            return

        rpc_url = rpc_urls[0]

        while self.running:
            try:
                # Get latest block
                block = await self._get_latest_block(rpc_url)

                # Find contract creations
                for tx in block.get("transactions", []):
                    if self._is_contract_creation(tx):
                        event = await self._process_deployment(chain, tx, block)
                        if event:
                            for callback in self.callbacks:
                                callback(event)

                await asyncio.sleep(12)  # ~1 block

            except Exception as e:
                await asyncio.sleep(5)

    async def _get_latest_block(self, rpc_url: str) -> dict:
        """Get latest block with transactions."""
        # Would use aiohttp for async HTTP
        # For now, return mock
        return {"transactions": [], "number": 0}

    def _is_contract_creation(self, tx: dict) -> bool:
        """Check if transaction creates a contract."""
        return tx.get("to") is None and tx.get("input", "0x") != "0x"

    async def _process_deployment(
        self,
        chain: Chain,
        tx: dict,
        block: dict,
    ) -> Optional[DeploymentEvent]:
        """Process a deployment transaction."""

        # Get contract address from receipt
        # receipt = await self._get_receipt(tx["hash"])
        # contract_address = receipt.get("contractAddress")

        return DeploymentEvent(
            chain=chain,
            deployer=tx.get("from", ""),
            contract_address="",  # Would get from receipt
            bytecode=tx.get("input", ""),
            timestamp=datetime.now(),
            block_number=block.get("number", 0),
            tx_hash=tx.get("hash", ""),
        )

    def analyze_bytecode(self, bytecode: str) -> list[str]:
        """Quick analysis of bytecode for red flags."""

        findings = []

        for name, pattern in self.VULNERABLE_BYTECODE_PATTERNS.items():
            if pattern in bytecode.lower():
                findings.append(f"Contains {name} opcode")

        for name, slot in self.PROXY_PATTERNS.items():
            if slot in bytecode.lower():
                findings.append(f"Proxy pattern: {name}")

        return findings


# =============================================================================
# MEMPOOL MONITOR
# =============================================================================

class MempoolMonitor:
    """
    Monitor pending transactions in the mempool.

    Detect:
    - Sandwich attack setups
    - Flash loan preparations
    - Governance manipulation attempts
    - Suspicious large transfers
    """

    # Patterns that indicate potential attacks
    ATTACK_SIGNATURES = {
        # Flash loan functions
        "aave_flash_loan": "ab9c4b5d",  # flashLoan
        "balancer_flash_loan": "5c38449e",  # flashLoan
        "uniswap_flash": "490e6cbc",  # flash

        # DEX swaps (potential sandwich)
        "uniswap_v2_swap": "38ed1739",  # swapExactTokensForTokens
        "uniswap_v3_swap": "414bf389",  # exactInputSingle
        "sushiswap": "38ed1739",

        # Governance
        "compound_vote": "56781388",  # castVote
        "oz_governor_vote": "56781388",  # castVote

        # Bridge operations
        "bridge_deposit": "deposit",
        "bridge_withdraw": "withdraw",
    }

    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        "large_swap": {"min_value_eth": 100},
        "flash_loan": {"always_suspicious": True},
        "governance_vote": {"check_token_movement": True},
        "multiple_dex_interactions": {"threshold": 3},
    }

    def __init__(self, chains: list[Chain] = None):
        self.chains = chains or [Chain.ETHEREUM]
        self.callbacks: list[Callable[[MempoolTransaction], None]] = []
        self.alert_callbacks: list[Callable[[ExploitAlert], None]] = []
        self.pending_txs: dict[str, MempoolTransaction] = {}
        self.running = False

    def on_transaction(self, callback: Callable[[MempoolTransaction], None]):
        """Register callback for pending transactions."""
        self.callbacks.append(callback)

    def on_alert(self, callback: Callable[[ExploitAlert], None]):
        """Register callback for exploit alerts."""
        self.alert_callbacks.append(callback)

    async def start(self):
        """Start mempool monitoring."""
        self.running = True

        # Connect to mempool providers
        tasks = [
            self._monitor_flashbots(),
            self._analyze_pending_loop(),
        ]

        await asyncio.gather(*tasks)

    async def stop(self):
        """Stop monitoring."""
        self.running = False

    async def _monitor_flashbots(self):
        """Monitor Flashbots Protect for private transactions."""
        # Would connect to Flashbots API
        pass

    async def _analyze_pending_loop(self):
        """Continuously analyze pending transactions."""

        while self.running:
            # Analyze all pending transactions for patterns
            alerts = self._detect_attack_patterns()

            for alert in alerts:
                for callback in self.alert_callbacks:
                    callback(alert)

            await asyncio.sleep(1)

    def _detect_attack_patterns(self) -> list[ExploitAlert]:
        """Detect attack patterns in pending transactions."""

        alerts = []
        pending = list(self.pending_txs.values())

        # Group transactions by sender
        by_sender: dict[str, list[MempoolTransaction]] = {}
        for tx in pending:
            by_sender.setdefault(tx.from_address, []).append(tx)

        # Check for sandwich attacks
        for sender, txs in by_sender.items():
            if len(txs) >= 2:
                # Multiple pending txs from same sender
                alert = self._check_sandwich_setup(txs)
                if alert:
                    alerts.append(alert)

        # Check for flash loan + swap combos
        for tx in pending:
            if self._is_flash_loan(tx):
                alert = ExploitAlert(
                    severity=AlertSeverity.WARNING,
                    chain=tx.chain,
                    alert_type="flash_loan_detected",
                    description=f"Flash loan transaction detected from {tx.from_address[:10]}...",
                    tx_hash=tx.tx_hash,
                    addresses_involved=[tx.from_address, tx.to_address],
                    estimated_impact_usd=0,
                    timestamp=datetime.now(),
                    recommended_action="Monitor for follow-up transactions",
                )
                alerts.append(alert)

        return alerts

    def _check_sandwich_setup(self, txs: list[MempoolTransaction]) -> Optional[ExploitAlert]:
        """Check if transactions look like sandwich attack setup."""

        # Look for buy-then-sell pattern
        swap_txs = [tx for tx in txs if self._is_swap(tx)]

        if len(swap_txs) >= 2:
            return ExploitAlert(
                severity=AlertSeverity.WARNING,
                chain=txs[0].chain,
                alert_type="potential_sandwich",
                description="Multiple swap transactions from same address - potential sandwich attack",
                tx_hash=txs[0].tx_hash,
                addresses_involved=[tx.from_address for tx in txs],
                estimated_impact_usd=0,
                timestamp=datetime.now(),
                recommended_action="Check for victim transaction between these",
            )

        return None

    def _is_flash_loan(self, tx: MempoolTransaction) -> bool:
        """Check if transaction is a flash loan."""
        for name, sig in self.ATTACK_SIGNATURES.items():
            if "flash" in name and tx.data.startswith(f"0x{sig}"):
                return True
        return False

    def _is_swap(self, tx: MempoolTransaction) -> bool:
        """Check if transaction is a swap."""
        for name, sig in self.ATTACK_SIGNATURES.items():
            if "swap" in name and tx.data.startswith(f"0x{sig}"):
                return True
        return False


# =============================================================================
# EXPLOIT DETECTOR
# =============================================================================

class ExploitDetector:
    """
    Detect exploits in real-time from transaction data.

    Monitors for:
    - Large unexpected fund movements
    - Protocol invariant violations
    - Known exploit patterns
    """

    # Known exploit transaction patterns
    EXPLOIT_PATTERNS = {
        "reentrancy": {
            "pattern": "Multiple calls to same address in single tx",
            "detection": "internal_tx_count > 10 AND unique_addresses < 3",
        },
        "flash_loan_attack": {
            "pattern": "Flash loan followed by large profit",
            "detection": "flash_loan AND profit > loan_amount * 0.01",
        },
        "governance_attack": {
            "pattern": "Token transfer + vote in same block",
            "detection": "token_transfer AND vote_cast AND same_block",
        },
        "price_manipulation": {
            "pattern": "Large swap + interaction + reverse swap",
            "detection": "swap_size > pool_tvl * 0.1 AND follow_up_action",
        },
    }

    # Protocols to monitor
    MONITORED_PROTOCOLS = {
        "uniswap_v2": {
            "factory": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f",
            "events": ["Swap", "Sync"],
        },
        "uniswap_v3": {
            "factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
            "events": ["Swap", "Flash"],
        },
        "aave_v3": {
            "pool": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
            "events": ["FlashLoan", "Borrow", "Liquidation"],
        },
        "curve": {
            "registry": "0x90E00ACe148ca3b23Ac1bC8C240C2a7Dd9c2d7f5",
            "events": ["TokenExchange", "RemoveLiquidity"],
        },
    }

    def __init__(self):
        self.alert_history: list[ExploitAlert] = []

    def analyze_transaction(self, tx_hash: str, chain: Chain) -> Optional[ExploitAlert]:
        """
        Analyze a transaction for exploit patterns.

        Returns alert if exploit detected.
        """

        # Get transaction details
        # tx = await self._get_transaction(tx_hash, chain)
        # receipt = await self._get_receipt(tx_hash, chain)
        # trace = await self._get_trace(tx_hash, chain)

        # For demo, return None
        return None

    def analyze_block(self, block_number: int, chain: Chain) -> list[ExploitAlert]:
        """Analyze all transactions in a block for exploits."""

        alerts = []

        # Would get all transactions in block and analyze each
        # for tx in block.transactions:
        #     alert = self.analyze_transaction(tx.hash, chain)
        #     if alert:
        #         alerts.append(alert)

        return alerts

    def _detect_reentrancy(self, trace: dict) -> bool:
        """Detect reentrancy from transaction trace."""

        call_stack = trace.get("calls", [])

        # Count calls to each address
        call_counts: dict[str, int] = {}
        for call in call_stack:
            addr = call.get("to", "")
            call_counts[addr] = call_counts.get(addr, 0) + 1

        # Reentrancy if same address called many times
        for addr, count in call_counts.items():
            if count > 5:
                return True

        return False

    def _detect_price_manipulation(self, tx: dict, trace: dict) -> bool:
        """Detect price manipulation pattern."""

        # Look for: large swap -> action -> reverse swap
        swaps = [c for c in trace.get("calls", []) if self._is_swap_call(c)]

        if len(swaps) >= 2:
            # Check if swaps are in opposite directions
            first_swap = swaps[0]
            last_swap = swaps[-1]

            # If tokens are reversed, likely manipulation
            if self._swaps_reversed(first_swap, last_swap):
                return True

        return False

    def _is_swap_call(self, call: dict) -> bool:
        """Check if call is a swap."""
        return "swap" in call.get("input", "").lower()

    def _swaps_reversed(self, swap1: dict, swap2: dict) -> bool:
        """Check if two swaps are in opposite directions."""
        # Would analyze swap parameters
        return False


# =============================================================================
# UNIFIED REAL-TIME MONITOR
# =============================================================================

class RealTimeBlockchainMonitor:
    """
    Unified real-time monitoring interface.

    Combines:
    - Deployment monitoring
    - Mempool monitoring
    - Exploit detection
    """

    def __init__(self, chains: list[Chain] = None):
        self.chains = chains or [Chain.ETHEREUM, Chain.ARBITRUM, Chain.BASE]
        self.deployment_monitor = DeploymentMonitor(self.chains)
        self.mempool_monitor = MempoolMonitor(self.chains)
        self.exploit_detector = ExploitDetector()

        self.running = False
        self.alerts: list[ExploitAlert] = []

    def on_alert(self, callback: Callable[[ExploitAlert], None]):
        """Register global alert callback."""
        self.mempool_monitor.on_alert(callback)

    def on_deployment(self, callback: Callable[[DeploymentEvent], None]):
        """Register deployment callback."""
        self.deployment_monitor.on_deployment(callback)

    async def start(self):
        """Start all monitoring."""
        self.running = True

        print(f"Starting real-time monitoring on {[c.value for c in self.chains]}...")

        await asyncio.gather(
            self.deployment_monitor.start(),
            self.mempool_monitor.start(),
        )

    async def stop(self):
        """Stop all monitoring."""
        self.running = False
        await self.deployment_monitor.stop()
        await self.mempool_monitor.stop()

    def get_recent_alerts(self, limit: int = 100) -> list[ExploitAlert]:
        """Get recent alerts."""
        return self.alerts[-limit:]


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def start_monitoring(
    chains: list[Chain] = None,
    on_alert: Callable[[ExploitAlert], None] = None,
):
    """Start real-time monitoring with callback."""

    monitor = RealTimeBlockchainMonitor(chains)

    if on_alert:
        monitor.on_alert(on_alert)
    else:
        # Default: print alerts
        monitor.on_alert(lambda a: print(f"ALERT: {a.alert_type} - {a.description}"))

    await monitor.start()


def analyze_pending_tx(tx_data: dict) -> Optional[ExploitAlert]:
    """Analyze a single pending transaction."""
    detector = ExploitDetector()
    return detector.analyze_transaction(tx_data.get("hash"), Chain.ETHEREUM)
