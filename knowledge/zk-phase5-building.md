# Phase 5: Building Privacy Applications

Put it all together. Build real applications.

---

## Overview

This phase is project-based. You'll build increasingly complex privacy applications, combining the technologies from previous phases.

| Project | Technologies | Difficulty |
|---------|--------------|------------|
| 1. ZK Membership | Circom, Solidity | Beginner |
| 2. Private Voting | Semaphore | Intermediate |
| 3. Confidential DeFi | FHE/ZK/TEE | Advanced |
| 4. Open Source Contribution | Various | Advanced |

---

## Project 1: ZK Membership Proof

### Goal
Prove you're a member of a group (e.g., DAO, allowlist) without revealing which member you are.

### Architecture

```
┌─────────────────────────────────────────────────┐
│                   Frontend                       │
│  - Generate proof locally                        │
│  - Submit proof to contract                      │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│               Circom Circuit                     │
│  - Merkle tree membership                        │
│  - Input: leaf, path, root                       │
│  - Proves: leaf is in tree with root             │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│             Verifier Contract                    │
│  - Groth16 verification                          │
│  - If valid, grant access                        │
└─────────────────────────────────────────────────┘
```

### Step 1: Create the Circuit

```circom
// circuits/membership.circom
pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";

template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    component hashers[levels];
    signal hashes[levels + 1];
    hashes[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        hashers[i] = Poseidon(2);

        // If pathIndex is 0, hash(current, sibling)
        // If pathIndex is 1, hash(sibling, current)
        var left = pathIndices[i] == 0 ? hashes[i] : pathElements[i];
        var right = pathIndices[i] == 0 ? pathElements[i] : hashes[i];

        hashers[i].inputs[0] <== left;
        hashers[i].inputs[1] <== right;
        hashes[i + 1] <== hashers[i].out;
    }

    root <== hashes[levels];
}

template MembershipVerifier(levels) {
    signal input leaf;              // private: which member
    signal input pathElements[levels];  // private: merkle path
    signal input pathIndices[levels];   // private: path direction
    signal input expectedRoot;      // public: known merkle root

    component merkle = MerkleProof(levels);
    merkle.leaf <== leaf;
    for (var i = 0; i < levels; i++) {
        merkle.pathElements[i] <== pathElements[i];
        merkle.pathIndices[i] <== pathIndices[i];
    }

    // Verify computed root matches expected
    expectedRoot === merkle.root;
}

component main {public [expectedRoot]} = MembershipVerifier(20);
```

### Step 2: Compile and Setup

```bash
# Compile
circom circuits/membership.circom --r1cs --wasm --sym -o build

# Powers of tau (use existing ceremony for production)
snarkjs powersoftau new bn128 15 pot15_0000.ptau
snarkjs powersoftau contribute pot15_0000.ptau pot15_final.ptau
snarkjs powersoftau prepare phase2 pot15_final.ptau pot15_final.ptau

# Circuit-specific setup
snarkjs groth16 setup build/membership.r1cs pot15_final.ptau membership_0000.zkey
snarkjs zkey contribute membership_0000.zkey membership_final.zkey
snarkjs zkey export verificationkey membership_final.zkey verification_key.json

# Export Solidity verifier
snarkjs zkey export solidityverifier membership_final.zkey contracts/MembershipVerifier.sol
```

### Step 3: Deploy Verifier

```solidity
// contracts/PrivateDAO.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MembershipVerifier.sol";

contract PrivateDAO {
    MembershipVerifier public verifier;
    bytes32 public merkleRoot;

    mapping(bytes32 => bool) public nullifiers;

    event MemberAction(bytes32 indexed nullifier);

    constructor(address _verifier, bytes32 _merkleRoot) {
        verifier = MembershipVerifier(_verifier);
        merkleRoot = _merkleRoot;
    }

    function proveAndAct(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[1] memory input,
        bytes32 nullifier
    ) external {
        // Verify the proof
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");
        require(input[0] == uint256(merkleRoot), "Wrong root");

        // Prevent double-spending with nullifier
        require(!nullifiers[nullifier], "Already used");
        nullifiers[nullifier] = true;

        // Perform action
        emit MemberAction(nullifier);
    }
}
```

### Step 4: Frontend Proof Generation

```typescript
// frontend/src/prove.ts
import { groth16 } from 'snarkjs';

interface MerkleProof {
    leaf: string;
    pathElements: string[];
    pathIndices: number[];
}

export async function generateMembershipProof(
    membershipProof: MerkleProof,
    expectedRoot: string
) {
    const input = {
        leaf: membershipProof.leaf,
        pathElements: membershipProof.pathElements,
        pathIndices: membershipProof.pathIndices,
        expectedRoot: expectedRoot,
    };

    const { proof, publicSignals } = await groth16.fullProve(
        input,
        'circuits/membership.wasm',
        'circuits/membership_final.zkey'
    );

    // Format for Solidity
    const calldata = await groth16.exportSolidityCallData(proof, publicSignals);

    return { proof, publicSignals, calldata };
}
```

### Deliverables
- [ ] Working Circom circuit
- [ ] Deployed verifier contract
- [ ] Frontend that generates proofs
- [ ] End-to-end test

---

## Project 2: Private Voting with Semaphore

### Goal
Anonymous voting where:
- Only group members can vote
- Each member can vote once
- Vote choices are private until reveal

### Semaphore Concepts

```
Identity = hash(trapdoor, nullifier)
├── trapdoor: secret, used to generate proofs
├── nullifier: unique per action, prevents double-voting
└── commitment: public, added to group

Group = Merkle tree of identity commitments

Proof = "I'm in the group" + "This is my unique vote"
```

### Setup

```bash
npm init -y
npm install @semaphore-protocol/core @semaphore-protocol/contracts
npm install hardhat ethers
```

### Contracts

```solidity
// contracts/PrivateVoting.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";

contract PrivateVoting {
    ISemaphore public semaphore;
    uint256 public groupId;

    mapping(uint256 => uint256) public voteCounts;
    uint256 public proposalCount;

    event VoteCast(uint256 indexed proposalId, uint256 indexed choice);

    constructor(address _semaphore) {
        semaphore = ISemaphore(_semaphore);
        groupId = semaphore.createGroup();
    }

    function addMember(uint256 identityCommitment) external {
        semaphore.addMember(groupId, identityCommitment);
    }

    function createProposal() external returns (uint256) {
        return proposalCount++;
    }

    function vote(
        uint256 proposalId,
        uint256 choice, // 0 = no, 1 = yes
        ISemaphore.SemaphoreProof calldata proof
    ) external {
        // Signal encodes proposalId and choice
        uint256 signal = uint256(keccak256(abi.encode(proposalId, choice)));

        // Verify proof (also checks nullifier for double-voting)
        semaphore.validateProof(groupId, proof);

        // Count vote
        voteCounts[proposalId * 2 + choice]++;

        emit VoteCast(proposalId, choice);
    }

    function getResults(uint256 proposalId) external view returns (uint256 no, uint256 yes) {
        no = voteCounts[proposalId * 2];
        yes = voteCounts[proposalId * 2 + 1];
    }
}
```

### Frontend

```typescript
// frontend/src/vote.ts
import { Identity } from "@semaphore-protocol/core";
import { Group } from "@semaphore-protocol/group";
import { generateProof } from "@semaphore-protocol/proof";

// Create identity (store securely!)
const identity = new Identity();
console.log("Commitment:", identity.commitment.toString());

// Add to group (done by contract owner)
// group.addMember(identity.commitment);

// Generate vote proof
async function castVote(
    identity: Identity,
    group: Group,
    proposalId: number,
    choice: number
) {
    const signal = BigInt(
        ethers.keccak256(
            ethers.AbiCoder.defaultAbiCoder().encode(
                ["uint256", "uint256"],
                [proposalId, choice]
            )
        )
    );

    const proof = await generateProof(identity, group, signal, groupId);

    // Submit to contract
    await votingContract.vote(proposalId, choice, {
        merkleTreeDepth: proof.merkleTreeDepth,
        merkleTreeRoot: proof.merkleTreeRoot,
        nullifier: proof.nullifier,
        message: proof.message,
        scope: proof.scope,
        points: proof.points,
    });
}
```

### Resources

| Resource | Link |
|----------|------|
| [Semaphore Docs](https://docs.semaphore.pse.dev/) | Official |
| [Semaphore Boilerplate](https://github.com/semaphore-protocol/boilerplate) | Starter |

### Deliverables
- [ ] Voting contract deployed
- [ ] Identity generation UI
- [ ] Vote casting with proof
- [ ] Results display

---

## Project 3: Confidential DeFi

### Choose Your Adventure

Pick one and build it:

#### Option A: Dark Pool (FHE)
Private order book where orders are encrypted.

```solidity
contract DarkPool {
    struct Order {
        euint64 price;
        euint64 amount;
        ebool isBuy;
        address trader;
    }

    Order[] private orders;

    function placeOrder(
        einput encPrice,
        einput encAmount,
        einput encIsBuy,
        bytes calldata proof
    ) external {
        orders.push(Order({
            price: TFHE.asEuint64(encPrice, proof),
            amount: TFHE.asEuint64(encAmount, proof),
            isBuy: TFHE.asEbool(encIsBuy, proof),
            trader: msg.sender
        }));
    }

    function matchOrders(uint256 i, uint256 j) external {
        // Encrypted matching logic
        ebool canMatch = TFHE.and(
            orders[i].isBuy,
            TFHE.not(orders[j].isBuy)
        );
        canMatch = TFHE.and(
            canMatch,
            TFHE.ge(orders[i].price, orders[j].price)
        );
        // ... execute if canMatch is true
    }
}
```

#### Option B: Sealed-Bid Auction (MPC or FHE)
Bidders submit encrypted bids, winner revealed only at end.

```
1. Commit phase: Submit encrypted bids
2. Reveal phase: Decrypt and find winner
3. Settlement: Winner pays, gets item
```

#### Option C: Private Lending Score (ZK)
Prove creditworthiness without revealing financial details.

```circom
template CreditScore() {
    signal input balance;       // private
    signal input txCount;       // private
    signal input accountAge;    // private
    signal input minRequired;   // public

    signal output qualified;

    // Compute score (simplified)
    signal score;
    score <== balance / 1000 + txCount + accountAge * 10;

    // Check threshold
    component gte = GreaterEqThan(64);
    gte.in[0] <== score;
    gte.in[1] <== minRequired;
    qualified <== gte.out;
}
```

### Architecture Considerations

| Approach | Tech | Tradeoffs |
|----------|------|-----------|
| Encrypted state | FHE | Slow, expensive, but on-chain privacy |
| Prove off-chain | ZK | Fast verify, complex circuits |
| Trusted compute | TEE | Fast, hardware trust required |
| Hybrid | Mix | Best of each, more complexity |

### Deliverables
- [ ] Design document with tech choices
- [ ] Smart contracts
- [ ] Frontend/SDK
- [ ] Tests
- [ ] Security considerations documented

---

## Project 4: Open Source Contribution

### Why Contribute?

- Learn from production code
- Build reputation
- Give back to ecosystem
- Potential job opportunities

### Good First Issues

| Project | Focus | Link |
|---------|-------|------|
| Semaphore | ZK identity | [GitHub](https://github.com/semaphore-protocol/semaphore) |
| Noir | ZK language | [GitHub](https://github.com/noir-lang/noir) |
| ZAMA fhEVM | FHE | [GitHub](https://github.com/zama-ai/fhevm) |
| circom | ZK circuits | [GitHub](https://github.com/iden3/circom) |
| PSE projects | Various | [GitHub](https://github.com/privacy-scaling-explorations) |

### Contribution Flow

```
1. Find interesting project
2. Read CONTRIBUTING.md
3. Set up development environment
4. Find "good first issue" or bug
5. Discuss approach in issue
6. Submit PR
7. Address review feedback
8. Get merged!
```

### Areas to Contribute

- **Documentation**: Always needed
- **Tests**: Increase coverage
- **Bug fixes**: Start small
- **New features**: After building trust
- **Security**: If you find issues, responsible disclosure

### Deliverables
- [ ] Chosen a project
- [ ] Set up dev environment
- [ ] Opened or addressed an issue
- [ ] Submitted at least one PR

---

## Portfolio Projects Summary

After completing Phase 5, you should have:

| Project | Demonstrates |
|---------|--------------|
| ZK Membership | Circom circuits, Solidity verifiers |
| Private Voting | Semaphore, anonymous credentials |
| Confidential DeFi | FHE or ZK in practice |
| OSS Contribution | Production code quality |

---

## Career Paths

### ZK Engineer
- Focus: Circuit development, proof systems
- Skills: Math, Rust/Circom, cryptography
- Projects: L2s, privacy protocols

### Privacy Protocol Developer
- Focus: Full-stack privacy apps
- Skills: Smart contracts, frontend, UX
- Projects: Private DeFi, identity

### Cryptography Researcher
- Focus: Novel constructions, security proofs
- Skills: Deep math, academic writing
- Projects: New proof systems, FHE schemes

### Security Auditor (Privacy Focus)
- Focus: Finding bugs in ZK circuits, FHE code
- Skills: Attack vectors, formal verification
- Projects: Audit reports, tools

---

## Staying Current

### Follow

| Resource | Type |
|----------|------|
| [Zero Knowledge Podcast](https://zeroknowledge.fm/) | Podcast |
| [ZK Hack](https://zkhack.dev/) | Hackathons |
| [PSE Blog](https://pse.dev/blog) | Research |
| [ZAMA Blog](https://www.zama.ai/blog) | FHE |
| [a16z Crypto](https://a16zcrypto.com/) | Industry |

### Communities

- ZK Hack Discord
- Noir Discord
- ZAMA Discord
- ETH Research forum

### Conferences

- ZK Summit
- ETH Denver (ZK track)
- Devcon
- ZuConnect/Zuzalu

---

## Phase 5 Completion Checklist

### Projects Built
- [ ] ZK Membership proof system
- [ ] Private voting dApp
- [ ] Confidential DeFi application
- [ ] At least one OSS contribution

### Portfolio
- [ ] GitHub repos with clean READMEs
- [ ] Deployed demos where applicable
- [ ] Documentation of design decisions

### Knowledge
- [ ] Can architect privacy-preserving systems
- [ ] Know when to use ZK vs FHE vs TEE vs MPC
- [ ] Understand security tradeoffs
- [ ] Connected with community

---

## Congratulations!

You've completed the ZK/Privacy/TEE learning path.

You now have:
- Deep understanding of privacy technologies
- Hands-on experience with multiple systems
- Portfolio of projects
- Foundation for continued learning

The field is evolving rapidly. Keep building, keep learning.

---

## Quick Reference: Technology Selection

```
Need to prove something without revealing it?
└── Use ZK

Need encrypted computation on-chain?
└── Use FHE

Need multiple parties to jointly compute?
└── Use MPC

Need fast confidential compute?
└── Use TEE

Need maximum trust minimization?
└── Use ZK or FHE

Need practical performance today?
└── Use TEE or MPC

Building for long-term (quantum)?
└── Use STARKs or lattice-based FHE
```

---

*Last updated: January 2026*
