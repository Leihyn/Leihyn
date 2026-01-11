# Phase 4: MPC & FHE

Compute on secrets without revealing them.

---

## Overview

| Topic | Weeks | Outcome |
|-------|-------|---------|
| MPC Fundamentals | 27-28 | Secret sharing, threshold crypto |
| MPC Practice | 29-30 | MPC wallets, Partisia |
| FHE Theory | 31-32 | Homomorphic encryption basics |
| fhEVM | 33-34 | Build encrypted smart contracts |
| Fhenix | 35-36 | Deploy to FHE L2 |

---

## MPC vs FHE vs ZK vs TEE

| Tech | What It Does | Trust Model | Speed |
|------|--------------|-------------|-------|
| **MPC** | Multiple parties jointly compute | Honest majority | Medium |
| **FHE** | Compute on encrypted data | Math | Slow |
| **ZK** | Prove without revealing | Math | Medium |
| **TEE** | Hardware isolation | Hardware | Fast |

**When to use each:**
- **MPC**: Key management, threshold signing, multi-party auctions
- **FHE**: Encrypted computation, confidential smart contracts
- **ZK**: Prove membership, verify computation, privacy preserving proofs
- **TEE**: Fast confidential compute, block building

---

## Week 27-28: MPC Fundamentals

### What is MPC?

Multi-Party Computation allows n parties to jointly compute a function over their inputs while keeping inputs private.

```
Party A has: x
Party B has: y
Party C has: z

They want: f(x, y, z)

Without MPC: Someone learns all inputs
With MPC: Each party learns only the output
```

### Secret Sharing

**Shamir's Secret Sharing:**

Split a secret S into n shares where any k shares can reconstruct it.

```python
# Intuition: Secret is encoded as polynomial
# S is the constant term (f(0) = S)
# Shares are points on the polynomial

# Example: 2-of-3 threshold
# Polynomial: f(x) = S + ax (degree 1, need 2 points)

# S = 1234 (secret)
# a = 166 (random)
# f(x) = 1234 + 166x

# Shares:
# Share 1: f(1) = 1234 + 166(1) = 1400
# Share 2: f(2) = 1234 + 166(2) = 1566
# Share 3: f(3) = 1234 + 166(3) = 1732

# Any 2 shares can reconstruct via Lagrange interpolation
# No single share reveals anything about S
```

**Code Example:**
```python
import random
from functools import reduce

def make_shares(secret, k, n, prime):
    """Create n shares with threshold k"""
    # Random polynomial coefficients
    coeffs = [secret] + [random.randrange(prime) for _ in range(k-1)]

    def eval_poly(x):
        return sum(c * pow(x, i, prime) for i, c in enumerate(coeffs)) % prime

    return [(i, eval_poly(i)) for i in range(1, n+1)]

def reconstruct(shares, prime):
    """Reconstruct secret from k shares"""
    def lagrange_basis(i, x_coords):
        xi = x_coords[i]
        num = reduce(lambda a, b: a * b % prime,
                    (0 - xj for j, xj in enumerate(x_coords) if j != i), 1)
        den = reduce(lambda a, b: a * b % prime,
                    (xi - xj for j, xj in enumerate(x_coords) if j != i), 1)
        return num * pow(den, prime - 2, prime) % prime

    x_coords = [s[0] for s in shares]
    y_coords = [s[1] for s in shares]

    return sum(y * lagrange_basis(i, x_coords)
              for i, y in enumerate(y_coords)) % prime

# Example usage
prime = 2**127 - 1  # Mersenne prime
secret = 1234567890
shares = make_shares(secret, k=3, n=5, prime=prime)
print(f"Shares: {shares}")

# Reconstruct from any 3 shares
reconstructed = reconstruct(shares[:3], prime)
print(f"Reconstructed: {reconstructed}")
assert reconstructed == secret
```

### Threshold Signatures

**Problem:** Single key = single point of failure
**Solution:** Split key across n parties, require k to sign

**Types:**
- **Threshold ECDSA**: Complex, requires MPC protocols
- **Threshold BLS**: Simpler due to linearity
- **Threshold Schnorr**: MuSig, FROST protocols

**BLS Threshold Example:**
```
Key shares: sk₁, sk₂, sk₃ (3-of-5)
Public key: PK = sk₁·G + sk₂·G + sk₃·G (combined)

To sign message m:
1. Each party creates partial sig: σᵢ = skᵢ · H(m)
2. Combine: σ = σ₁ + σ₂ + σ₃
3. Verify: e(σ, G) = e(H(m), PK)
```

### MPC Protocols

**Garbled Circuits (2PC):**
- Alice "garbles" circuit with random labels
- Bob evaluates with his input
- Oblivious Transfer for input selection

**GMW Protocol:**
- Secret share all values
- Compute gate-by-gate
- AND gates require interaction

**SPDZ:**
- Practical for many parties
- Preprocessing + online phases
- Used in production systems

### Checkpoint

- [ ] Implement Shamir secret sharing
- [ ] Understand threshold signatures concept
- [ ] Know difference between 2PC and MPC
- [ ] Can explain when MPC is better than alternatives

---

## Week 29-30: MPC Practice

### MPC Wallets

**How they work:**
```
Traditional Wallet:
Private Key → Single device → Risk

MPC Wallet:
Key Share 1 → Device 1 ─┐
Key Share 2 → Device 2 ──┼→ Sign together
Key Share 3 → Server ───┘

No single party ever has full key
```

**Benefits:**
- No single point of failure
- Key rotation without changing address
- Flexible access policies

**Popular MPC Wallets:**
- Fireblocks (institutional)
- ZenGo (consumer)
- Lit Protocol (programmable)
- Dfns (infrastructure)

### Lit Protocol

Decentralized key management with MPC:

```typescript
import { LitNodeClient } from '@lit-protocol/lit-node-client';
import { LitContracts } from '@lit-protocol/contracts-sdk';

// Connect to Lit network
const client = new LitNodeClient({ litNetwork: 'cayenne' });
await client.connect();

// Generate distributed key (PKP)
const pkp = await litContracts.pkpNftContractUtils.mint();
console.log('PKP Public Key:', pkp.publicKey);

// Sign with MPC
const signature = await client.pkpSign({
  pubKey: pkp.publicKey,
  toSign: messageHash,
  authSig: authSig, // Proves you control the PKP
});
```

### Partisia Blockchain

**What it is:**
- Layer 0+1+2 with built-in MPC
- Privacy-preserving computation layer
- Supports both MPC and FHE

**Architecture:**
```
┌─────────────────────────────────────┐
│     Application Layer               │
├─────────────────────────────────────┤
│     MPC Computation Layer           │
│  (Secret sharing across nodes)      │
├─────────────────────────────────────┤
│     Consensus Layer                 │
│  (Sharding for scalability)         │
└─────────────────────────────────────┘
```

**Use Cases:**
- Private auctions
- Confidential voting
- Private data analytics

### MPC Tradeoffs

| Aspect | MPC | Consideration |
|--------|-----|---------------|
| **Latency** | Multiple rounds | Each operation needs communication |
| **Trust** | Honest majority | Usually 2/3 or 1/2 honest |
| **Computation** | Any function | But complex = more rounds |
| **Collusion** | Main risk | If threshold collude, secret leaked |

### Resources

| Resource | Type |
|----------|------|
| [Alchemy MPC Guide](https://www.alchemy.com/overviews/what-is-a-multi-party-computation-mpc-wallet) | Overview |
| [Lit Protocol Docs](https://developer.litprotocol.com/) | Practical |
| [Partisia Docs](https://partisiablockchain.gitlab.io/documentation/) | Protocol |

### Checkpoint

- [ ] Understand MPC wallet architecture
- [ ] Know major MPC wallet providers
- [ ] Studied Lit or Partisia
- [ ] Understand collusion risks

---

## Week 31-32: FHE Theory

### What is FHE?

Fully Homomorphic Encryption allows computation on encrypted data:

```
Encrypt(a) ⊕ Encrypt(b) = Encrypt(a + b)
Encrypt(a) ⊗ Encrypt(b) = Encrypt(a × b)

Cloud sees only ciphertext
Computes on ciphertext
Returns encrypted result
User decrypts final answer
```

### The FHE Revolution

**History:**
- 2009: Gentry's breakthrough (first FHE scheme)
- 2010s: Efficiency improvements (BGV, BFV, CKKS, TFHE)
- 2020s: Practical implementations (ZAMA, Fhenix)

### FHE Schemes

| Scheme | Strengths | Use Case |
|--------|-----------|----------|
| **TFHE** | Fast bootstrapping, bit operations | Smart contracts |
| **BGV/BFV** | Integer arithmetic | Batched computations |
| **CKKS** | Approximate arithmetic | ML inference |

### Key Concepts

**1. Noise:**
```
Ciphertext has "noise" that grows with operations
Too much noise → decryption fails
Bootstrapping: "refresh" ciphertext (expensive)
```

**2. Bootstrapping:**
```
FHE.decrypt(FHE.encrypt(ciphertext))
Reduces noise but expensive
TFHE: ~10ms per bootstrap
```

**3. Leveled FHE:**
```
Without bootstrapping:
Limited depth of computation
Faster but less flexible
```

### FHE Operations

```
// Pseudocode for FHE operations
encrypted_a = FHE.encrypt(5)
encrypted_b = FHE.encrypt(3)

// Addition (fast)
encrypted_sum = FHE.add(encrypted_a, encrypted_b)  // Encrypts 8

// Multiplication (noise grows faster)
encrypted_product = FHE.mul(encrypted_a, encrypted_b)  // Encrypts 15

// Comparison (uses bit decomposition)
encrypted_lt = FHE.lt(encrypted_a, encrypted_b)  // Encrypts 0 (false)

// If-then-else (conditional on encrypted condition)
encrypted_result = FHE.select(condition, encrypted_a, encrypted_b)
```

### Performance Reality

| Operation | Time (TFHE) |
|-----------|-------------|
| Addition | ~0.1 ms |
| Multiplication | ~10 ms |
| Comparison | ~50 ms |
| Bootstrap | ~10 ms |

**Implication:** FHE is 100x-1000x slower than plaintext

### Concrete (ZAMA Library)

```rust
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

fn main() {
    // Setup
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    // Encrypt
    let a = FheUint8::encrypt(5u8, &client_key);
    let b = FheUint8::encrypt(3u8, &client_key);

    // Compute on encrypted values
    let sum = &a + &b;
    let product = &a * &b;

    // Decrypt
    let decrypted_sum: u8 = sum.decrypt(&client_key);
    let decrypted_product: u8 = product.decrypt(&client_key);

    println!("5 + 3 = {}", decrypted_sum);   // 8
    println!("5 * 3 = {}", decrypted_product); // 15
}
```

### Resources

| Resource | Type |
|----------|------|
| [ZAMA Blog](https://www.zama.ai/blog) | Concepts |
| [FHE.org](https://fhe.org/) | Community |
| [Concrete Docs](https://docs.zama.ai/concrete) | Library |

### Checkpoint

- [ ] Explain what homomorphic means
- [ ] Understand noise and bootstrapping
- [ ] Know the main FHE schemes (TFHE, BGV, CKKS)
- [ ] Realistic about FHE performance

---

## Week 33-34: fhEVM Practice

### What is fhEVM?

ZAMA's framework for FHE smart contracts:
- Write Solidity with encrypted types
- EVM-compatible
- Encrypted state, inputs, outputs

### Setup

```bash
# Clone quickstart
git clone https://github.com/zama-ai/fhevm-quickstart
cd fhevm-quickstart

# Install dependencies
npm install

# Start local FHE node (Docker)
docker compose up -d

# Deploy and test
npx hardhat test
```

### First Encrypted Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import "fhevm/config/EthereumConfig.sol";

contract EncryptedCounter is EthereumConfig {
    // Encrypted state
    euint32 private counter;

    constructor() {
        // Initialize encrypted counter to 0
        counter = TFHE.asEuint32(0);
    }

    // Increment by encrypted amount
    function increment(einput encryptedAmount, bytes calldata inputProof) public {
        euint32 amount = TFHE.asEuint32(encryptedAmount, inputProof);
        counter = TFHE.add(counter, amount);
    }

    // Get counter (returns encrypted value)
    function getCounter() public view returns (euint32) {
        return counter;
    }

    // Decrypt for authorized viewer
    function revealCounter() public view returns (uint32) {
        return TFHE.decrypt(counter);
    }
}
```

### Encrypted Types

```solidity
// Available encrypted types
ebool    // Encrypted boolean
euint4   // 4-bit unsigned integer
euint8   // 8-bit unsigned integer
euint16  // 16-bit unsigned integer
euint32  // 32-bit unsigned integer
euint64  // 64-bit unsigned integer
euint128 // 128-bit unsigned integer
euint256 // 256-bit unsigned integer
eaddress // Encrypted address
```

### FHE Operations

```solidity
// Arithmetic
TFHE.add(a, b)      // a + b
TFHE.sub(a, b)      // a - b
TFHE.mul(a, b)      // a * b
TFHE.div(a, b)      // a / b
TFHE.rem(a, b)      // a % b
TFHE.min(a, b)      // min(a, b)
TFHE.max(a, b)      // max(a, b)

// Comparison (returns ebool)
TFHE.eq(a, b)       // a == b
TFHE.ne(a, b)       // a != b
TFHE.lt(a, b)       // a < b
TFHE.le(a, b)       // a <= b
TFHE.gt(a, b)       // a > b
TFHE.ge(a, b)       // a >= b

// Bitwise
TFHE.and(a, b)      // a & b
TFHE.or(a, b)       // a | b
TFHE.xor(a, b)      // a ^ b
TFHE.not(a)         // ~a
TFHE.shl(a, b)      // a << b
TFHE.shr(a, b)      // a >> b

// Conditional
TFHE.select(cond, a, b)  // cond ? a : b
```

### Confidential ERC20

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "fhevm/lib/TFHE.sol";
import "fhevm/config/EthereumConfig.sol";

contract ConfidentialERC20 is EthereumConfig {
    mapping(address => euint64) private balances;
    euint64 private totalSupply;

    event Transfer(address indexed from, address indexed to);

    constructor(uint64 initialSupply) {
        balances[msg.sender] = TFHE.asEuint64(initialSupply);
        totalSupply = TFHE.asEuint64(initialSupply);
        TFHE.allowThis(balances[msg.sender]);
    }

    function transfer(
        address to,
        einput encryptedAmount,
        bytes calldata inputProof
    ) public {
        euint64 amount = TFHE.asEuint64(encryptedAmount, inputProof);

        // Check balance >= amount (encrypted comparison)
        ebool hasEnough = TFHE.ge(balances[msg.sender], amount);

        // Conditional transfer
        balances[msg.sender] = TFHE.select(
            hasEnough,
            TFHE.sub(balances[msg.sender], amount),
            balances[msg.sender]
        );
        balances[to] = TFHE.add(balances[to], amount);

        // Set permissions
        TFHE.allowThis(balances[msg.sender]);
        TFHE.allowThis(balances[to]);
        TFHE.allow(balances[to], to);

        emit Transfer(msg.sender, to);
    }

    function balanceOf(address account) public view returns (euint64) {
        return balances[account];
    }
}
```

### Access Control

```solidity
// Grant decryption access
TFHE.allow(encryptedValue, userAddress);    // User can decrypt
TFHE.allowThis(encryptedValue);              // Contract can use
TFHE.allowTransient(encryptedValue, addr);   // Temporary access

// Check access
TFHE.isAllowed(encryptedValue, addr);        // Returns bool
```

### Testing

```typescript
import { expect } from "chai";
import { ethers } from "hardhat";
import { createInstance } from "fhevmjs";

describe("ConfidentialERC20", function () {
    it("should transfer encrypted amounts", async function () {
        const [owner, recipient] = await ethers.getSigners();

        // Deploy
        const Token = await ethers.getContractFactory("ConfidentialERC20");
        const token = await Token.deploy(1000000);

        // Create FHE instance for encryption
        const instance = await createInstance({
            networkUrl: "http://localhost:8545",
            gatewayUrl: "http://localhost:7077",
        });

        // Encrypt transfer amount
        const encryptedAmount = instance.encrypt64(100);

        // Transfer
        await token.transfer(
            recipient.address,
            encryptedAmount.handles[0],
            encryptedAmount.inputProof
        );

        // Verify (would need decryption in real scenario)
    });
});
```

### Resources

| Resource | Type |
|----------|------|
| [fhEVM Docs](https://docs.zama.org/protocol/) | Official |
| [fhEVM GitHub](https://github.com/zama-ai/fhevm) | Code |
| [Quick Start Tutorial](https://docs.zama.org/protocol/solidity-guides/getting-started/quick-start-tutorial) | Tutorial |

### Checkpoint

- [ ] Set up fhEVM development environment
- [ ] Deployed encrypted counter contract
- [ ] Understand encrypted types and operations
- [ ] Built confidential ERC20

---

## Week 35-36: Fhenix

### What is Fhenix?

- FHE-powered L2 on Ethereum
- Uses CoFHE (Confidential FHE)
- More decentralized key management than basic fhEVM

### Privacy Stages

Fhenix introduced a framework for evaluating FHE implementations:

| Stage | Description | Trust |
|-------|-------------|-------|
| **Stage 0** | TEE-only | Hardware trust |
| **Stage 1** | FHE with training wheels | Some trusted operators |
| **Stage 2** | Full decentralization | Distributed key management |

### Setup

```bash
# Install Fhenix Hardhat plugin
npm install @fhenixprotocol/hardhat-fhenix

# Configure hardhat.config.ts
import "@fhenixprotocol/hardhat-fhenix";

const config: HardhatUserConfig = {
    networks: {
        fhenix: {
            url: "https://api.nitrogen.fhenix.zone",
            accounts: [process.env.PRIVATE_KEY!],
        },
    },
};
```

### Fhenix Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@fhenixprotocol/contracts/FHE.sol";

contract PrivateVoting {
    mapping(uint256 => euint32) private voteCounts;
    mapping(address => mapping(uint256 => ebool)) private hasVoted;

    function vote(uint256 proposalId, inEuint32 calldata encryptedChoice) public {
        // Check hasn't voted
        require(!FHE.decrypt(hasVoted[msg.sender][proposalId]), "Already voted");

        // Add encrypted vote
        euint32 choice = FHE.asEuint32(encryptedChoice);
        voteCounts[proposalId] = FHE.add(voteCounts[proposalId], choice);

        // Mark as voted
        hasVoted[msg.sender][proposalId] = FHE.asEbool(true);
    }

    function getResults(uint256 proposalId) public view returns (uint32) {
        return FHE.decrypt(voteCounts[proposalId]);
    }
}
```

### Deploy to Testnet

```bash
# Get testnet tokens
# Visit: https://faucet.fhenix.zone

# Deploy
npx hardhat run scripts/deploy.ts --network fhenix

# Verify
npx hardhat verify --network fhenix <CONTRACT_ADDRESS>
```

### Resources

| Resource | Type |
|----------|------|
| [Fhenix Docs](https://docs.fhenix.io/) | Official |
| [Fhenix Faucet](https://faucet.fhenix.zone/) | Testnet |
| [Privacy Stages](https://www.fhenix.io/blog/the-different-stages-of-privacy-a-taxonomy) | Concept |

### Checkpoint

- [ ] Understand Privacy Stages framework
- [ ] Set up Fhenix development environment
- [ ] Deployed contract to Fhenix testnet
- [ ] Compared Fhenix vs ZAMA approach

---

## Phase 4 Completion Checklist

### MPC
- [ ] Implemented Shamir secret sharing
- [ ] Understand threshold signatures
- [ ] Studied MPC wallet architecture
- [ ] Know collusion risks

### FHE
- [ ] Understand homomorphic operations
- [ ] Know noise and bootstrapping concepts
- [ ] Aware of performance limitations

### fhEVM
- [ ] Set up development environment
- [ ] Built encrypted smart contracts
- [ ] Understand access control model

### Fhenix
- [ ] Deployed to testnet
- [ ] Understand Privacy Stages
- [ ] Compared different FHE approaches

### Decision Making
- [ ] Can recommend MPC vs FHE vs ZK vs TEE for use cases

---

## Technology Selection Guide

| Use Case | Best Tech | Why |
|----------|-----------|-----|
| Key management | MPC | Threshold security, no single point |
| Private balances | FHE | Encrypted state on-chain |
| Prove membership | ZK | Minimal data revealed |
| Fast block building | TEE | Performance critical |
| Private auctions | MPC or FHE | Depends on trust model |
| Confidential voting | FHE | Encrypted tallying |
| MEV protection | TEE | Speed required |

---

## Next: Phase 5 - Building

[Continue to Phase 5: Building Privacy Applications](./zk-phase5-building.md)
