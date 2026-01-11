"""
SENTINEL Elite - Historical Attack Replication

Integrates with DeFiHackLabs and other attack databases to:
- Replay historical exploits against new contracts
- Identify similar vulnerability patterns
- Generate regression tests from real attacks
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from datetime import datetime
import re
import json


class AttackCategory(Enum):
    """Categories of DeFi attacks"""
    REENTRANCY = "reentrancy"
    FLASH_LOAN = "flash_loan"
    ORACLE_MANIPULATION = "oracle_manipulation"
    ACCESS_CONTROL = "access_control"
    PRICE_MANIPULATION = "price_manipulation"
    GOVERNANCE = "governance"
    BRIDGE = "bridge"
    LOGIC_ERROR = "logic_error"
    FRONT_RUNNING = "front_running"
    SIGNATURE = "signature"
    UPGRADE = "upgrade"
    INTEGER_OVERFLOW = "integer_overflow"
    ROUNDING = "rounding"
    FIRST_DEPOSITOR = "first_depositor"
    READ_ONLY_REENTRANCY = "read_only_reentrancy"


@dataclass
class HistoricalAttack:
    """Documented historical attack"""
    name: str
    date: str
    chain: str
    protocol: str
    loss_usd: int
    category: AttackCategory
    description: str
    root_cause: str
    attack_tx: Optional[str]
    attacker_contract: Optional[str]
    target_contract: str
    poc_url: Optional[str]
    foundry_test: Optional[str]
    vulnerability_pattern: str
    fix_pattern: str
    tags: List[str] = field(default_factory=list)


class DeFiHackLabsDB:
    """
    Database of historical attacks from DeFiHackLabs

    Source: https://github.com/SunWeb3Sec/DeFiHackLabs
    """

    # Notable attacks with full details
    ATTACKS: List[HistoricalAttack] = [
        HistoricalAttack(
            name="Euler Finance",
            date="2023-03-13",
            chain="ethereum",
            protocol="Euler Finance",
            loss_usd=197_000_000,
            category=AttackCategory.FLASH_LOAN,
            description="Flash loan attack exploiting donation mechanism in liquidation",
            root_cause="donateToReserves allowed inflating debt without proper checks",
            attack_tx="0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d",
            attacker_contract="0xeBC29199C817Dc47BA12E3F86102564D640CBf99",
            target_contract="0x27182842E098f60e3D576794A5bFFb0777E025d3",
            poc_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/Euler_exp.sol",
            vulnerability_pattern=r"donate.*reserve|inflate.*debt",
            fix_pattern="Validate collateral ratios after donations",
            foundry_test='''
// Euler Finance Exploit - March 2023
contract EulerExploit is Test {
    function testExploit() public {
        vm.createSelectFork("mainnet", 16817995);

        // 1. Flash loan DAI from Aave
        // 2. Deposit to Euler, get eDAI
        // 3. Borrow 10x via self-liquidation
        // 4. Donate to reserves to inflate debt
        // 5. Liquidate at profit
    }
}
''',
            tags=["flash_loan", "liquidation", "donation"]
        ),

        HistoricalAttack(
            name="Curve/Vyper Reentrancy",
            date="2023-07-30",
            chain="ethereum",
            protocol="Curve Finance",
            loss_usd=73_000_000,
            category=AttackCategory.READ_ONLY_REENTRANCY,
            description="Vyper compiler bug in reentrancy lock allowed read-only reentrancy",
            root_cause="Vyper 0.2.15-0.3.0 had faulty reentrancy lock implementation",
            attack_tx="0xa84aa065ce61dbb1eb50ab6ae67fc31a9da50dd2c74eefd561661bfce2f1620c",
            attacker_contract=None,
            target_contract="0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511",  # CRV/ETH
            poc_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/Curve_exp.sol",
            vulnerability_pattern=r"@nonreentrant|get_virtual_price.*callback",
            fix_pattern="Upgrade Vyper compiler, add cross-function reentrancy guards",
            foundry_test='''
// Curve Vyper Reentrancy - July 2023
contract CurveExploit is Test {
    function testExploit() public {
        vm.createSelectFork("mainnet", 17806055);

        // 1. Call remove_liquidity
        // 2. In ETH callback, reenter via add_liquidity
        // 3. get_virtual_price returns stale value
        // 4. Profit from price discrepancy
    }
}
''',
            tags=["vyper", "reentrancy", "compiler_bug"]
        ),

        HistoricalAttack(
            name="Ronin Bridge",
            date="2022-03-23",
            chain="ethereum",
            protocol="Ronin Network",
            loss_usd=624_000_000,
            category=AttackCategory.ACCESS_CONTROL,
            description="Compromised validator private keys allowed unauthorized withdrawals",
            root_cause="5 of 9 validator keys compromised via social engineering",
            attack_tx="0xc28fad5e8d5e0ce6a2eaf67b6687be5d58113e16be590824d6cfa1a94467d0b7",
            attacker_contract=None,
            target_contract="0x8407dc57739bcda7aa53ca6f12f82f9d51c2f21e",
            poc_url=None,
            vulnerability_pattern=r"(validator|multisig).*threshold",
            fix_pattern="Increase validator count, improve key security",
            foundry_test=None,
            tags=["bridge", "social_engineering", "multisig"]
        ),

        HistoricalAttack(
            name="Wormhole",
            date="2022-02-02",
            chain="solana",
            protocol="Wormhole",
            loss_usd=326_000_000,
            category=AttackCategory.SIGNATURE,
            description="Signature verification bypass in Solana program",
            root_cause="verify_signatures used deprecated function that didn't validate signer",
            attack_tx=None,
            attacker_contract=None,
            target_contract="wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb",
            poc_url=None,
            vulnerability_pattern=r"verify_signature|secp256k1_recover",
            fix_pattern="Use proper signature verification, validate all signers",
            foundry_test=None,
            tags=["bridge", "solana", "signature"]
        ),

        HistoricalAttack(
            name="Beanstalk",
            date="2022-04-17",
            chain="ethereum",
            protocol="Beanstalk",
            loss_usd=182_000_000,
            category=AttackCategory.GOVERNANCE,
            description="Flash loan governance attack bypassed voting period",
            root_cause="emergencyCommit allowed immediate execution with enough votes",
            attack_tx="0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7",
            attacker_contract="0x79224bc0bf70ec34f0ef56ed8251619499a59def",
            target_contract="0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5",
            poc_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/Beanstalk_exp.sol",
            vulnerability_pattern=r"emergencyCommit|flash.*vote|propose.*execute",
            fix_pattern="Add time delay between proposal and execution, snapshot voting",
            foundry_test='''
// Beanstalk Governance Attack - April 2022
contract BeanstalkExploit is Test {
    function testExploit() public {
        vm.createSelectFork("mainnet", 14595905);

        // 1. Flash loan BEAN tokens
        // 2. Deposit to Silo for voting power
        // 3. Submit malicious BIP
        // 4. emergencyCommit to execute immediately
        // 5. Drain funds
    }
}
''',
            tags=["governance", "flash_loan", "dao"]
        ),

        HistoricalAttack(
            name="Mango Markets",
            date="2022-10-11",
            chain="solana",
            protocol="Mango Markets",
            loss_usd=114_000_000,
            category=AttackCategory.ORACLE_MANIPULATION,
            description="Oracle price manipulation via thin liquidity markets",
            root_cause="Used spot MNGO price as oracle, easily manipulable",
            attack_tx=None,
            attacker_contract=None,
            target_contract="mv3ekLzLbnVPNxjSKvqBpU3ZeZXPQdEC3bp5MDEBG68",
            poc_url=None,
            vulnerability_pattern=r"spot.*price|getPrice.*pool|oracle.*amm",
            fix_pattern="Use TWAP oracles, multiple price sources",
            foundry_test=None,
            tags=["oracle", "solana", "price_manipulation"]
        ),

        HistoricalAttack(
            name="Nomad Bridge",
            date="2022-08-01",
            chain="ethereum",
            protocol="Nomad",
            loss_usd=190_000_000,
            category=AttackCategory.LOGIC_ERROR,
            description="Faulty upgrade initialized trusted root as zero, accepting any message",
            root_cause="Initialization set confirmAt[0x0] = 1, making all proofs valid",
            attack_tx="0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460",
            attacker_contract=None,
            target_contract="0x5D94309E5a0090b165FA4181519701637B6DAEBA",
            poc_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/Nomad_exp.sol",
            vulnerability_pattern=r"confirmAt\[.*\]\s*=|initialize.*root|trusted.*0x0",
            fix_pattern="Validate initialization parameters, never trust zero values",
            foundry_test='''
// Nomad Bridge Exploit - August 2022
contract NomadExploit is Test {
    function testExploit() public {
        vm.createSelectFork("mainnet", 15259100);

        // 1. Create fake message with zero proof
        // 2. process() accepts because confirmAt[0x0] = 1
        // 3. Bridge releases funds
    }
}
''',
            tags=["bridge", "initialization", "upgrade"]
        ),

        HistoricalAttack(
            name="Wintermute",
            date="2022-09-20",
            chain="ethereum",
            protocol="Wintermute",
            loss_usd=160_000_000,
            category=AttackCategory.ACCESS_CONTROL,
            description="Profanity vanity address private key compromised",
            root_cause="Profanity tool had weak PRNG, keys could be reverse-engineered",
            attack_tx="0xedd31e2a949b7957f79b90a6d16387de1232af5135505e316aa8f3cd4a36c8e3",
            attacker_contract=None,
            target_contract="0x0000000fe6a514a32abdcdfcc076c85243de899b",
            poc_url=None,
            vulnerability_pattern=r"0x0000000|vanity.*address|profanity",
            fix_pattern="Use secure key generation, rotate compromised keys",
            foundry_test=None,
            tags=["private_key", "vanity_address"]
        ),

        HistoricalAttack(
            name="BonqDAO",
            date="2023-02-01",
            chain="polygon",
            protocol="BonqDAO",
            loss_usd=120_000_000,
            category=AttackCategory.ORACLE_MANIPULATION,
            description="Tellor oracle price manipulation via staking",
            root_cause="Tellor required only 10 TRB ($175) to submit prices",
            attack_tx="0x31957ecc43774d19f54d9968e95c69c882b6a85e3600a0c9e5387b8f7b2e1893",
            attacker_contract=None,
            target_contract="0x8f55d884cad66b79e1a131f6bcb0e66f4fd84d5b",
            poc_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/BonqDAO_exp.sol",
            vulnerability_pattern=r"tellor|submitValue|oracle.*stake",
            fix_pattern="Use multiple oracles, add dispute period",
            foundry_test='''
// BonqDAO Oracle Manipulation - February 2023
contract BonqExploit is Test {
    function testExploit() public {
        vm.createSelectFork("polygon", 38831098);

        // 1. Stake 10 TRB on Tellor
        // 2. Submit inflated price for WALBT
        // 3. Borrow max against inflated collateral
        // 4. Submit zero price
        // 5. Liquidate others at profit
    }
}
''',
            tags=["oracle", "tellor", "polygon"]
        ),

        HistoricalAttack(
            name="Sentiment",
            date="2023-04-04",
            chain="arbitrum",
            protocol="Sentiment",
            loss_usd=1_000_000,
            category=AttackCategory.READ_ONLY_REENTRANCY,
            description="Read-only reentrancy in Balancer pool price calculation",
            root_cause="Used getRate() during Balancer callback when pool was imbalanced",
            attack_tx="0xa9ff2b587e2741575daf893864710a5cbb44bb64ccdc487a100fa20741e0f74d",
            attacker_contract="0x9f62ee65a8395824Ee0821eF2Dc4C947a23F0f25",
            target_contract="0x17b07cfbaB33C0024040e7C299f8048F4a49679B",
            poc_url="https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/Sentiment_exp.sol",
            vulnerability_pattern=r"getRate\(\)|balancer.*callback|join.*exit.*callback",
            fix_pattern="Check for reentrancy before reading pool state",
            foundry_test='''
// Sentiment Read-Only Reentrancy - April 2023
contract SentimentExploit is Test {
    function testExploit() public {
        vm.createSelectFork("arbitrum", 78683387);

        // 1. Flash loan ETH
        // 2. Join Balancer pool
        // 3. In callback, getRate() returns stale value
        // 4. Borrow against inflated LP price
        // 5. Exit pool, repay flash loan
    }
}
''',
            tags=["read_only_reentrancy", "balancer", "arbitrum"]
        ),
    ]

    # Attack pattern signatures for matching
    PATTERN_SIGNATURES = {
        AttackCategory.REENTRANCY: [
            r"\.call\{.*\}\s*\(",
            r"transfer\s*\([^)]*\)\s*;",
            r"send\s*\([^)]*\)",
        ],
        AttackCategory.FLASH_LOAN: [
            r"flashLoan",
            r"executeOperation",
            r"onFlashLoan",
            r"uniswapV\dFlashCallback",
        ],
        AttackCategory.ORACLE_MANIPULATION: [
            r"getPrice|latestAnswer",
            r"get_virtual_price",
            r"getRate\(\)",
            r"oracle.*price",
        ],
        AttackCategory.GOVERNANCE: [
            r"propose|execute|queue",
            r"votingPower|votes",
            r"emergencyCommit",
        ],
        AttackCategory.ACCESS_CONTROL: [
            r"onlyOwner|require.*owner",
            r"msg\.sender\s*==",
            r"authorized|whitelist",
        ],
        AttackCategory.FIRST_DEPOSITOR: [
            r"totalSupply\s*==\s*0",
            r"shares.*deposit|deposit.*shares",
            r"previewDeposit|previewMint",
        ],
    }

    @classmethod
    def get_all_attacks(cls) -> List[HistoricalAttack]:
        """Get all documented attacks"""
        return cls.ATTACKS

    @classmethod
    def get_attacks_by_category(cls, category: AttackCategory) -> List[HistoricalAttack]:
        """Get attacks by category"""
        return [a for a in cls.ATTACKS if a.category == category]

    @classmethod
    def get_attacks_by_chain(cls, chain: str) -> List[HistoricalAttack]:
        """Get attacks on specific chain"""
        return [a for a in cls.ATTACKS if a.chain.lower() == chain.lower()]

    @classmethod
    def get_top_losses(cls, n: int = 10) -> List[HistoricalAttack]:
        """Get top N attacks by loss amount"""
        return sorted(cls.ATTACKS, key=lambda a: a.loss_usd, reverse=True)[:n]


class AttackReplicator:
    """Replicate historical attacks against new contracts"""

    def __init__(self):
        self.db = DeFiHackLabsDB()

    def find_similar_patterns(self, code: str) -> List[Tuple[HistoricalAttack, float]]:
        """Find historical attacks with similar patterns in the code"""

        matches = []

        for attack in self.db.ATTACKS:
            similarity = self._calculate_similarity(code, attack)
            if similarity > 0.3:  # 30% threshold
                matches.append((attack, similarity))

        return sorted(matches, key=lambda x: x[1], reverse=True)

    def _calculate_similarity(self, code: str, attack: HistoricalAttack) -> float:
        """Calculate similarity between code and attack pattern"""

        score = 0.0

        # Check vulnerability pattern
        if attack.vulnerability_pattern:
            if re.search(attack.vulnerability_pattern, code, re.IGNORECASE):
                score += 0.5

        # Check category signatures
        category_patterns = self.db.PATTERN_SIGNATURES.get(attack.category, [])
        matches = sum(1 for p in category_patterns if re.search(p, code, re.IGNORECASE))
        if category_patterns:
            score += 0.3 * (matches / len(category_patterns))

        # Check tags
        for tag in attack.tags:
            if tag.lower() in code.lower():
                score += 0.1

        return min(score, 1.0)

    def generate_regression_test(
        self,
        attack: HistoricalAttack,
        target_contract: str,
        target_address: str
    ) -> str:
        """Generate a regression test based on historical attack"""

        if attack.foundry_test:
            # Adapt existing PoC to new target
            test = attack.foundry_test
            test = test.replace(attack.target_contract, target_address)
            return test

        # Generate generic test
        return f'''// Regression Test: {attack.name} Pattern
// Original Attack: {attack.date} - ${attack.loss_usd:,} lost
// Category: {attack.category.value}

contract {attack.name.replace(" ", "")}RegressionTest is Test {{
    address constant TARGET = {target_address};

    function setUp() public {{
        // Fork at current block
        vm.createSelectFork(vm.envString("RPC_URL"));
    }}

    function test_{attack.category.value}_pattern() public {{
        // Root cause: {attack.root_cause}
        //
        // Attack steps:
        // {attack.description}
        //
        // Fix pattern: {attack.fix_pattern}

        // TODO: Implement test based on attack pattern
        // Vulnerability pattern: {attack.vulnerability_pattern}
    }}
}}
'''

    def generate_all_regression_tests(
        self,
        code: str,
        contract_name: str,
        address: str
    ) -> List[Tuple[str, str]]:
        """Generate regression tests for all matching patterns"""

        tests = []
        matches = self.find_similar_patterns(code)

        for attack, similarity in matches[:5]:  # Top 5 matches
            test_name = f"{contract_name}_{attack.name.replace(' ', '_')}_test.sol"
            test_code = self.generate_regression_test(attack, contract_name, address)
            tests.append((test_name, test_code))

        return tests


class AttackAnalyzer:
    """Analyze code for historical attack patterns"""

    def __init__(self):
        self.replicator = AttackReplicator()

    def analyze(self, code: str) -> Dict[str, Any]:
        """Full analysis against historical attacks"""

        matches = self.replicator.find_similar_patterns(code)

        result = {
            "vulnerable_patterns": [],
            "similar_attacks": [],
            "total_historical_loss": 0,
            "recommendations": []
        }

        for attack, similarity in matches:
            result["similar_attacks"].append({
                "name": attack.name,
                "date": attack.date,
                "loss_usd": attack.loss_usd,
                "similarity": similarity,
                "category": attack.category.value,
                "root_cause": attack.root_cause,
                "fix_pattern": attack.fix_pattern
            })
            result["total_historical_loss"] += attack.loss_usd

            result["recommendations"].append({
                "based_on": attack.name,
                "recommendation": attack.fix_pattern,
                "priority": "HIGH" if attack.loss_usd > 50_000_000 else "MEDIUM"
            })

        return result


# Convenience functions
def find_attack_patterns(code: str) -> List[Dict[str, Any]]:
    """Find historical attack patterns in code"""
    analyzer = AttackAnalyzer()
    return analyzer.analyze(code)["similar_attacks"]


def generate_regression_tests(
    code: str,
    contract_name: str,
    address: str = "0x0000000000000000000000000000000000000000"
) -> List[Tuple[str, str]]:
    """Generate regression tests from historical attacks"""
    replicator = AttackReplicator()
    return replicator.generate_all_regression_tests(code, contract_name, address)


def get_attack_database() -> List[HistoricalAttack]:
    """Get full attack database"""
    return DeFiHackLabsDB.get_all_attacks()
