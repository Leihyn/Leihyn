# Phase 2: ZK Deep Dive - Circuits & Proof Systems

From theory to building real ZK circuits.

---

## Overview

| Topic | Weeks | Outcome |
|-------|-------|---------|
| ZK Theory | 9-10 | Understand R1CS, QAP, Fiat-Shamir |
| Proof Systems | 11-12 | Know Groth16, Plonk, SNARKs vs STARKs |
| Circom | 13-16 | Build and deploy ZK circuits |
| Noir | 17-18 | Modern ZK development, browser apps |
| Halo2 | 19-20 | Production-grade Rust circuits |

---

## Week 9-10: ZK Theory

### Core Concepts

**1. What is a ZK Proof?**
- Prover convinces Verifier they know something without revealing it
- Three properties: Completeness, Soundness, Zero-Knowledge
- Interactive → Non-interactive (Fiat-Shamir transform)

**2. Arithmetic Circuits**
- Computation represented as circuit of additions and multiplications
- Gates have wires (signals)
- Circuit takes inputs, produces outputs

**3. R1CS (Rank-1 Constraint System)**
```
Every constraint is: A · B = C
Where A, B, C are linear combinations of variables

Example: Prove you know x such that x³ = 27
Variables: [1, x, x², x³]
Constraints:
  x * x = x²    →  [0,1,0,0] · [0,1,0,0] = [0,0,1,0]
  x * x² = x³   →  [0,1,0,0] · [0,0,1,0] = [0,0,0,1]
  x³ = 27       →  [0,0,0,1] = [27,0,0,0]
```

**4. QAP (Quadratic Arithmetic Program)**
- Transform R1CS into polynomial form
- If polynomials match at random point, high confidence they're equal
- This is what Vitalik's "QAP from Zero to Hero" explains

**5. Witness**
- The private inputs (what you're proving knowledge of)
- Prover generates witness, uses it to create proof
- Witness never revealed to verifier

### Resources

| Resource | Type | Notes |
|----------|------|-------|
| [zk-learning.org MOOC](https://zk-learning.org/) | Video | First 3 lectures essential |
| [Vitalik: QAP from Zero to Hero](https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649) | Article | Must read |
| [RareSkills: R1CS Chapter](https://www.rareskills.io/zk-book) | Book | Code-focused |

### Checkpoint

You should be able to:
- [ ] Explain what R1CS constraints look like
- [ ] Convert a simple computation to R1CS (on paper)
- [ ] Explain why Fiat-Shamir makes proofs non-interactive
- [ ] Define: witness, circuit, constraint, signal

---

## Week 11-12: Proof Systems

### The Zoo of Proof Systems

| System | Setup | Proof Size | Verify Time | Notes |
|--------|-------|------------|-------------|-------|
| **Groth16** | Trusted (circuit-specific) | ~200 bytes | Fast | Most used, Zcash |
| **Plonk** | Trusted (universal) | ~400 bytes | Fast | Reusable setup |
| **Halo2** | No trusted setup | Larger | Medium | Recursive proofs |
| **STARKs** | Transparent | Large (~100KB) | Slower | Quantum-resistant |

### Trusted Setup Deep Dive

**What is it?**
- Generate "toxic waste" parameters
- If anyone keeps the toxic waste, they can create fake proofs
- Destroyed through multi-party ceremony (powers of tau)

**Phases:**
1. **Powers of Tau** - Universal, circuit-independent
2. **Phase 2** - Circuit-specific parameters

**Why SNARKs need it:**
- The pairing-based math requires secret parameters
- e(g^a, g^b) = e(g, g)^ab needs structured reference string

### SNARKs vs STARKs

| Aspect | SNARKs | STARKs |
|--------|--------|--------|
| Setup | Trusted | Transparent |
| Proof Size | Small (~200B) | Large (~100KB) |
| Verify Time | O(1) | O(log n) |
| Quantum | Vulnerable | Resistant |
| Math | Pairings | Hash functions |

**When to use what:**
- On-chain verification where gas matters → SNARKs
- Large computations, quantum concerns → STARKs
- Need recursion → Halo2, Nova

### Key Proof Systems in Practice

**Groth16**
- Powers Zcash, Tornado Cash
- Smallest proofs, fastest verification
- Downside: new trusted setup per circuit

**Plonk**
- Universal trusted setup (reuse across circuits)
- Powers zkSync, Aztec (older versions)
- Good balance of features

**Halo2**
- No trusted setup (recursive proofs eliminate it)
- Powers Scroll, Axiom
- Written in Rust, production-grade

### Resources

| Resource | Focus |
|----------|-------|
| [zk-learning.org](https://zk-learning.org/) Lecture 4-6 | Groth16, Plonk theory |
| [Vitalik: zk-SNARKs Under the Hood](https://medium.com/@VitalikButerin/zk-snarks-under-the-hood-b33151a013f6) | SNARK intuition |
| [Vitalik: STARKs series](https://vitalik.eth.limo/general/2017/11/09/starks_part_1.html) | STARK deep dive |
| [Scroll: Why we chose Halo2](https://scroll.io/blog/proofGeneration) | Practical comparison |

### Checkpoint

- [ ] Explain trusted setup and why it's needed
- [ ] Compare Groth16 vs Plonk vs STARKs (3 key differences each)
- [ ] Know which protocols use which proof systems
- [ ] Explain recursive proofs at high level

---

## Week 13-14: Circom Basics

### Setup

```bash
# Install Rust (if not already)
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh

# Install Circom
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom

# Install snarkjs
npm install -g snarkjs

# Verify
circom --version
snarkjs --version
```

### Your First Circuit

Create `multiplier2.circom`:
```circom
pragma circom 2.0.0;

// Proves: I know a, b such that a * b = c
template Multiplier2() {
    // Private inputs (witness)
    signal input a;
    signal input b;

    // Public output
    signal output c;

    // Constraint: c must equal a * b
    c <== a * b;
}

component main = Multiplier2();
```

### Compile & Prove

```bash
# 1. Compile circuit
circom multiplier2.circom --r1cs --wasm --sym

# 2. Start powers of tau ceremony (for testing)
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

# 3. Generate circuit-specific keys
snarkjs groth16 setup multiplier2.r1cs pot12_final.ptau multiplier2_0000.zkey
snarkjs zkey contribute multiplier2_0000.zkey multiplier2_final.zkey --name="1st Contributor" -v
snarkjs zkey export verificationkey multiplier2_final.zkey verification_key.json

# 4. Create input file (input.json)
echo '{"a": 3, "b": 11}' > input.json

# 5. Calculate witness
node multiplier2_js/generate_witness.js multiplier2_js/multiplier2.wasm input.json witness.wtns

# 6. Generate proof
snarkjs groth16 prove multiplier2_final.zkey witness.wtns proof.json public.json

# 7. Verify proof
snarkjs groth16 verify verification_key.json public.json proof.json
```

### Circom Syntax Deep Dive

**Signals:**
```circom
signal input x;      // Private input
signal output y;     // Public output
signal z;            // Intermediate signal
```

**Constraints vs Assignments:**
```circom
// <== is constraint + assignment
c <== a * b;  // Constrains c = a*b AND assigns value

// === is constraint only
c === a * b;  // Only constrains, c must be assigned elsewhere

// <-- is assignment only (DANGEROUS if not constrained!)
c <-- a * b;  // Only assigns, no constraint (can be exploited!)
```

**Templates:**
```circom
template IsZero() {
    signal input in;
    signal output out;

    signal inv;
    inv <-- in != 0 ? 1/in : 0;

    out <== -in * inv + 1;
    in * out === 0;
}
```

### Common Patterns

**Range Check (0 to 2^n - 1):**
```circom
template Num2Bits(n) {
    signal input in;
    signal output out[n];

    var lc = 0;
    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;  // Each bit is 0 or 1
        lc += out[i] * (1 << i);
    }
    lc === in;  // Bits reconstruct the input
}
```

**Merkle Tree Membership:**
```circom
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/mux1.circom";

template MerkleProof(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    signal hashes[levels + 1];
    hashes[0] <== leaf;

    component hashers[levels];
    component mux[levels];

    for (var i = 0; i < levels; i++) {
        mux[i] = Mux1();
        mux[i].c[0] <== hashes[i];
        mux[i].c[1] <== pathElements[i];
        mux[i].s <== pathIndices[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== mux[i].out[0];
        hashers[i].inputs[1] <== mux[i].out[1];

        hashes[i + 1] <== hashers[i].out;
    }

    root <== hashes[levels];
}
```

### Tools

| Tool | Purpose |
|------|---------|
| [zkrepl.dev](https://zkrepl.dev/) | Online Circom IDE |
| [Circomspect](https://github.com/trailofbits/circomspect) | Static analyzer for vulnerabilities |
| [Circomkit](https://github.com/erhant/circomkit) | Testing framework |
| [CircomLib](https://github.com/iden3/circomlib) | Standard library |

### Resources

| Resource | Type |
|----------|------|
| [Circom Docs](https://docs.circom.io/) | Official |
| [RareSkills Circom Intro](https://rareskills.io/post/circom-intro) | Tutorial |
| [iden3 First ZK Proof](https://blog.iden3.io/first-zk-proof.html) | Tutorial |
| [Vishwas1/zk-circuit](https://github.com/Vishwas1/zk-circuit) | Examples |

### Checkpoint

- [ ] Compiled and ran multiplier2 circuit
- [ ] Understand signals, constraints, templates
- [ ] Know difference between `<==`, `===`, `<--`
- [ ] Used CircomLib for a hash function

---

## Week 15-16: Circom Advanced

### Build: Merkle Membership Proof

Complete project structure:
```
merkle-proof/
├── circuits/
│   └── merkle.circom
├── scripts/
│   ├── compile.sh
│   └── prove.sh
├── test/
│   └── merkle.test.js
└── package.json
```

**Goal:** Prove you know a leaf in a Merkle tree without revealing which one.

### Security: Common Vulnerabilities

**1. Under-constrained Circuits**
```circom
// BAD: No constraint on out!
template Bad() {
    signal input in;
    signal output out;
    out <-- in * 2;  // Assignment but no constraint
}

// GOOD: Properly constrained
template Good() {
    signal input in;
    signal output out;
    out <== in * 2;  // Constrained
}
```

**2. Arithmetic Overflow**
- Circom uses finite field arithmetic (mod p)
- Be careful with comparisons and ranges

**3. Trusted Setup Attacks**
- Never reuse trusted setup between circuits
- Use reputable ceremony parameters

### On-Chain Verification

```bash
# Generate Solidity verifier
snarkjs zkey export solidityverifier multiplier2_final.zkey verifier.sol
```

```solidity
// Deploy verifier and call verify()
contract MyContract {
    Groth16Verifier public verifier;

    constructor(address _verifier) {
        verifier = Groth16Verifier(_verifier);
    }

    function doSomething(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[1] memory input  // public inputs
    ) public {
        require(verifier.verifyProof(a, b, c, input), "Invalid proof");
        // Do something now that proof is verified
    }
}
```

### Checkpoint

- [ ] Built Merkle membership circuit
- [ ] Deployed verifier contract to testnet
- [ ] Understand common vulnerabilities
- [ ] Used Circomspect to analyze circuit

---

## Week 17-18: Noir

### Why Noir?

- Modern, Rust-like syntax
- Backend agnostic (can use different proof systems)
- Better developer experience than Circom
- Powers Aztec's private smart contracts

### Setup

```bash
# Install Noir
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup

# Or specific version
noirup -v 1.0.0-beta.15

# Create project
nargo new my_circuit
cd my_circuit
```

### First Noir Program

`src/main.nr`:
```rust
fn main(x: Field, y: pub Field) {
    assert(x * x == y);
}
```

`Prover.toml`:
```toml
x = "3"
y = "9"
```

```bash
# Compile
nargo compile

# Execute (check constraints)
nargo execute

# Generate proof
nargo prove

# Verify
nargo verify
```

### Noir Syntax

**Types:**
```rust
// Field element (native)
let a: Field = 5;

// Unsigned integers
let b: u32 = 100;
let c: u64 = 1000;

// Boolean
let d: bool = true;

// Arrays
let arr: [Field; 3] = [1, 2, 3];

// Structs
struct Point {
    x: Field,
    y: Field,
}
```

**Control Flow:**
```rust
fn max(a: Field, b: Field) -> Field {
    if a > b { a } else { b }
}

fn sum(arr: [Field; 5]) -> Field {
    let mut total = 0;
    for i in 0..5 {
        total += arr[i];
    }
    total
}
```

**Assertions (Constraints):**
```rust
fn main(x: Field, y: pub Field) {
    // These create constraints
    assert(x != 0);
    assert_eq(x * x, y);
}
```

### Noir Standard Library

```rust
use std::hash::pedersen_hash;
use std::merkle::compute_merkle_root;
use std::ecdsa_secp256k1::verify_signature;

fn main(
    message_hash: pub [u8; 32],
    pub_key_x: [u8; 32],
    pub_key_y: [u8; 32],
    signature: [u8; 64]
) {
    let valid = verify_signature(pub_key_x, pub_key_y, signature, message_hash);
    assert(valid);
}
```

### Browser App with NoirJS

```bash
npm install @noir-lang/noir_js @aztec/bb.js
```

```typescript
import { Noir } from '@noir-lang/noir_js';
import { BarretenbergBackend } from '@aztec/bb.js';

// Load circuit
const circuit = await fetch('circuit.json').then(r => r.json());
const backend = new BarretenbergBackend(circuit);
const noir = new Noir(circuit, backend);

// Generate proof
const input = { x: 3, y: 9 };
const proof = await noir.generateProof(input);

// Verify
const verified = await noir.verifyProof(proof);
console.log('Verified:', verified);
```

### Resources

| Resource | Type |
|----------|------|
| [Noir Docs](https://noir-lang.org/docs/) | Official |
| [ZKCamp Noir Course](https://github.com/ZKCamp/aztec-noir-course) | Course |
| [awesome-noir](https://github.com/noir-lang/awesome-noir) | Curated list |
| [OpenZeppelin Noir Guide](https://www.openzeppelin.com/news/developer-guide-to-building-safe-noir-circuits) | Security |

### Checkpoint

- [ ] Installed Noir and created project
- [ ] Built and proved simple circuit
- [ ] Understand Noir syntax (types, assertions)
- [ ] Built browser app with NoirJS

---

## Week 19-20: Halo2

### Why Halo2?

- No trusted setup (recursive proofs)
- Production-grade (powers Scroll, Axiom)
- Rust-native, high performance
- More control, steeper learning curve

### Setup

```bash
# In a new Rust project
cargo new halo2-example
cd halo2-example
```

`Cargo.toml`:
```toml
[dependencies]
halo2_proofs = { git = "https://github.com/privacy-scaling-explorations/halo2", tag = "v0.3.0" }
```

### Halo2 Architecture

**Key Concepts:**
- **Config**: Define columns (advice, fixed, selector)
- **Chip**: Reusable circuit component
- **Region**: Area where you assign values
- **Layouter**: Organizes regions

```rust
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

#[derive(Clone)]
struct MyConfig {
    advice: Column<Advice>,
    selector: Selector,
}

impl MyConfig {
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let advice = meta.advice_column();
        let selector = meta.selector();

        meta.create_gate("square", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(advice, Rotation::cur());
            let b = meta.query_advice(advice, Rotation::next());

            // Constraint: when selector is on, b = a * a
            vec![s * (b - a.clone() * a)]
        });

        Self { advice, selector }
    }
}
```

### Starter Repos

| Repo | Purpose |
|------|---------|
| [halo2-starter](https://github.com/teddav/halo2-starter) | Basic setup, Tornado Cash example |
| [halo2-scaffold](https://github.com/axiom-crypto/halo2-scaffold) | Axiom's scaffolding |
| [zk-mooc-halo2](https://github.com/scroll-tech/zk-mooc-halo2) | Hash function circuits |

### Resources

| Resource | Type |
|----------|------|
| [Halo2 Book](https://zcash.github.io/halo2/) | Official docs |
| [halo2.zksecurity.xyz](https://halo2.zksecurity.xyz/) | Course |
| [Halo2 Tutorial](https://erroldrummond.gitbook.io/halo2-tutorial/) | Tutorial |
| [Trail of Bits: Axiom Halo2](https://blog.trailofbits.com/2025/05/30/a-deep-dive-into-axioms-halo2-circuits/) | Deep dive |

### Checkpoint

- [ ] Set up Halo2 Rust project
- [ ] Understand Config, Chip, Region, Layouter
- [ ] Ran example from halo2-scaffold
- [ ] Know when to use Halo2 vs Circom/Noir

---

## Phase 2 Completion Checklist

### Theory
- [ ] Can explain R1CS and QAP
- [ ] Understand trusted setup and alternatives
- [ ] Know trade-offs: Groth16 vs Plonk vs STARKs

### Circom
- [ ] Built multiple circuits
- [ ] Generated and verified proofs
- [ ] Deployed on-chain verifier

### Noir
- [ ] Comfortable with Noir syntax
- [ ] Built browser ZK app

### Halo2
- [ ] Understand architecture
- [ ] Ran basic examples

### Projects Completed
- [ ] Merkle membership proof (Circom)
- [ ] Simple web app (Noir)
- [ ] At least one Halo2 example

---

## Next: Phase 3 - TEEs

[Continue to Phase 3: Trusted Execution Environments](./zk-phase3-tee.md)
