# ZK/Privacy/TEE Study Tracker

Track your progress through the complete learning path.

---

## Quick Stats

| Phase | Status | Progress |
|-------|--------|----------|
| Phase 1: Foundations | Not Started | 0/8 weeks |
| Phase 2: ZK Deep Dive | Not Started | 0/12 weeks |
| Phase 3: TEEs | Not Started | 0/6 weeks |
| Phase 4: MPC/FHE | Not Started | 0/10 weeks |
| Phase 5: Building | Not Started | 0/ongoing |

**Start Date**: ___________
**Target Completion**: ___________

---

## Phase 1: Mathematical Foundations (8 weeks)

### Week 1: Groups Basics
- [ ] Read RareSkills ZK Book Chapter 1
- [ ] Understand group definition (set + operation + identity + inverses)
- [ ] Learn what cyclic groups are
- [ ] Implement modular addition in Python
- [ ] **Checkpoint**: Can explain what makes a group "cyclic"

**Notes**:
```
(your notes here)
```

### Week 2: Finite Fields
- [ ] Read RareSkills ZK Book Chapter 2-3
- [ ] Read Cyfrin "Rings and Fields for ZK" article
- [ ] Understand Z_p (integers mod prime p)
- [ ] Implement modular multiplication
- [ ] Implement modular inverse (Fermat's little theorem)
- [ ] **Checkpoint**: Can explain why we use prime numbers for modulus

**Code checkpoint**:
```python
# Verify you can implement this from scratch
def mod_inv(a, p):
    return pow(a, p - 2, p)

assert (5 * mod_inv(5, 17)) % 17 == 1
```

**Notes**:
```
(your notes here)
```

### Week 3: EC Fundamentals
- [ ] Read EC chapter in RareSkills or Rosing book
- [ ] Understand curve equation y² = x³ + ax + b
- [ ] Learn point addition geometry
- [ ] Learn point doubling
- [ ] **Checkpoint**: Can explain point addition visually

**Notes**:
```
(your notes here)
```

### Week 4: EC over Finite Fields
- [ ] Install py_ecc: `pip install py_ecc`
- [ ] Implement scalar multiplication with py_ecc
- [ ] Understand discrete log problem on curves
- [ ] Learn about secp256k1 and BN254 curves
- [ ] **Checkpoint**: Can explain why scalar mult is easy but discrete log is hard

**Code checkpoint**:
```python
from py_ecc.bn128 import G1, multiply, add

# Verify this works
P = multiply(G1, 5)
Q = multiply(G1, 7)
R = add(P, Q)
assert R == multiply(G1, 12)
```

**Notes**:
```
(your notes here)
```

### Week 5: Polynomials
- [ ] Read RareSkills polynomials chapter
- [ ] Understand polynomial representation
- [ ] Learn Lagrange interpolation
- [ ] Implement Lagrange interpolation in Python
- [ ] Read about Schwartz-Zippel lemma
- [ ] **Checkpoint**: Can interpolate a polynomial through 3 points

**Code checkpoint**:
```python
# Implement Lagrange interpolation
def lagrange_interpolate(points, x):
    # Your implementation
    pass

# Should pass:
points = [(1, 2), (2, 4), (3, 8)]
# lagrange_interpolate(points, 4) should work
```

**Notes**:
```
(your notes here)
```

### Week 6: KZG Commitments
- [ ] Read Dankrad Feist's KZG post
- [ ] Read "KZG with Code Walkthrough" Medium article
- [ ] Understand commitment, opening, verification
- [ ] Study trusted setup concept
- [ ] **Checkpoint**: Can explain KZG at high level (commit, open, verify)

**Notes**:
```
(your notes here)
```

### Week 7: Hash & Signatures
- [ ] Review hash function properties (collision, preimage resistance)
- [ ] Learn about ZK-friendly hashes (Poseidon, Pedersen)
- [ ] Understand ECDSA vs Schnorr vs BLS
- [ ] **Checkpoint**: Can explain why Poseidon is "SNARK-friendly"

**Notes**:
```
(your notes here)
```

### Week 8: Pairings
- [ ] Read Vitalik's "Exploring Elliptic Curve Pairings"
- [ ] Understand bilinear property: e(aG, bH) = e(G,H)^ab
- [ ] Learn why pairings enable KZG verification
- [ ] **Checkpoint**: Can explain what pairings unlock for ZK

**Notes**:
```
(your notes here)
```

### Phase 1 Completion
- [ ] All weekly checkpoints passed
- [ ] Can implement finite field arithmetic from scratch
- [ ] Can explain EC point addition
- [ ] Can implement Lagrange interpolation
- [ ] Understand KZG at conceptual level
- [ ] Know what pairings are and why they matter

**Phase 1 Completed**: ___________

---

## Phase 2: ZK Deep Dive (12 weeks)

### Week 9-10: ZK Theory
- [ ] Watch first 3 lectures of zk-learning.org MOOC
- [ ] Read Vitalik's "Quadratic Arithmetic Programs" post
- [ ] Understand Interactive → Non-interactive (Fiat-Shamir)
- [ ] Learn R1CS constraint format
- [ ] Learn about QAP transformation
- [ ] **Checkpoint**: Can explain what R1CS is

**Notes**:
```
(your notes here)
```

### Week 11-12: Proof Systems Theory
- [ ] Watch zk-learning.org lectures on Groth16
- [ ] Understand trusted setup (powers of tau, circuit-specific)
- [ ] Learn about Plonk (universal trusted setup)
- [ ] Compare SNARKs vs STARKs
- [ ] **Checkpoint**: Can explain trusted setup and why SNARKs need it

**Notes**:
```
(your notes here)
```

### Week 13-14: Circom Basics
- [ ] Install Circom: follow docs.circom.io
- [ ] Install snarkjs: `npm install -g snarkjs`
- [ ] Complete iden3 "First ZK Proof" tutorial
- [ ] Read RareSkills Circom Intro
- [ ] Build multiplier2 example circuit
- [ ] Generate and verify your first proof
- [ ] **Checkpoint**: Successfully proved knowledge of factors of 33

**Code checkpoint**:
```circom
// Your first circuit
template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}
component main = Multiplier2();
```

**Notes**:
```
(your notes here)
```

### Week 15-16: Circom Advanced
- [ ] Study CircomLib examples
- [ ] Build a Merkle tree membership circuit
- [ ] Understand signal constraints vs assignments
- [ ] Learn about constraint optimization
- [ ] Use Circomspect for static analysis
- [ ] **Checkpoint**: Built and tested Merkle membership proof

**Notes**:
```
(your notes here)
```

### Week 17-18: Noir Language
- [ ] Install Noir: `noirup -v 1.0.0-beta.15`
- [ ] Read Noir official docs (noir-lang.org)
- [ ] Complete ZKCamp Aztec Noir Course (Lecture 1-3)
- [ ] Port a simple circuit from Circom to Noir
- [ ] Build a web app with NoirJS + Barretenberg
- [ ] **Checkpoint**: Deployed ZK app to browser

**Notes**:
```
(your notes here)
```

### Week 19-20: Halo2 Introduction
- [ ] Read halo2.zksecurity.xyz course (first 3 chapters)
- [ ] Read Errol Drummond's Halo2 Tutorial
- [ ] Clone axiom-crypto/halo2-scaffold
- [ ] Understand Configure vs Synthesize
- [ ] Build OR gate example
- [ ] **Checkpoint**: Compiled and ran first Halo2 circuit

**Notes**:
```
(your notes here)
```

### Phase 2 Completion
- [ ] Can explain R1CS, QAP, trusted setup
- [ ] Built and tested Circom circuits
- [ ] Built and tested Noir circuits
- [ ] Ran first Halo2 circuit
- [ ] Understand tradeoffs between proof systems

**Phase 2 Completed**: ___________

---

## Phase 3: TEEs (6 weeks)

### Week 21-22: TEE Concepts
- [ ] Read a16z TEE Primer
- [ ] Read Metaschool TEE Guide
- [ ] Understand enclave architecture
- [ ] Learn about attestation
- [ ] Study side-channel attack vectors
- [ ] **Checkpoint**: Can explain enclave isolation model

**Notes**:
```
(your notes here)
```

### Week 23-24: Intel SGX
- [ ] Read SGX 101 (sgx101.gitbook.io)
- [ ] Understand ECALLs and OCALLs
- [ ] Study EDL (Enclave Definition Language)
- [ ] Review digawp/hello-enclave example
- [ ] (Optional) Set up SGX dev environment if hardware available
- [ ] **Checkpoint**: Understand SGX application architecture

**Notes**:
```
(your notes here)
```

### Week 25-26: TEE Blockchain Applications
- [ ] Study Secret Network architecture
- [ ] Read Oasis Network documentation
- [ ] Study Unichain's TEE-based block building
- [ ] Review Flashbots SUAVE design
- [ ] **Checkpoint**: Can explain how Secret Network uses SGX

**Notes**:
```
(your notes here)
```

### Phase 3 Completion
- [ ] Understand TEE isolation model
- [ ] Know SGX architecture (trusted/untrusted parts)
- [ ] Studied 2+ TEE blockchain protocols
- [ ] Understand attestation flow

**Phase 3 Completed**: ___________

---

## Phase 4: MPC/FHE (10 weeks)

### Week 27-28: MPC Fundamentals
- [ ] Read Alchemy MPC Wallet Guide
- [ ] Understand Shamir's Secret Sharing
- [ ] Learn about threshold signatures
- [ ] Study 2-party computation concepts
- [ ] **Checkpoint**: Can explain Shamir secret sharing

**Notes**:
```
(your notes here)
```

### Week 29-30: MPC Practice
- [ ] Study Partisia Blockchain architecture
- [ ] Review MPC wallet implementations
- [ ] Understand MPC tradeoffs (communication, rounds)
- [ ] **Checkpoint**: Understand when to use MPC vs other approaches

**Notes**:
```
(your notes here)
```

### Week 31-32: FHE Theory
- [ ] Read ZAMA fhEVM documentation overview
- [ ] Understand homomorphic operations (+, *, comparison)
- [ ] Learn about noise growth and bootstrapping
- [ ] Study TFHE, BGV, CKKS schemes (high level)
- [ ] **Checkpoint**: Can explain what FHE enables

**Notes**:
```
(your notes here)
```

### Week 33-34: fhEVM Practice
- [ ] Clone zama-ai/fhevm-quickstart
- [ ] Complete ZAMA Quick Start Tutorial (30 min)
- [ ] Build encrypted counter contract
- [ ] Convert regular ERC20 to confidential ERC20
- [ ] **Checkpoint**: Deployed confidential smart contract

**Code checkpoint**:
```solidity
// Verify you can use FHEVM
import "fhevm/lib/TFHE.sol";

contract EncryptedCounter {
    euint32 private counter;

    function increment(einput encryptedAmount, bytes calldata inputProof) public {
        euint32 amount = TFHE.asEuint32(encryptedAmount, inputProof);
        counter = TFHE.add(counter, amount);
    }
}
```

**Notes**:
```
(your notes here)
```

### Week 35-36: Fhenix
- [ ] Read Fhenix documentation
- [ ] Understand CoFHE (Confidential FHE)
- [ ] Study Privacy Stages framework
- [ ] Deploy test contract on Fhenix testnet
- [ ] **Checkpoint**: Deployed to Fhenix testnet

**Notes**:
```
(your notes here)
```

### Phase 4 Completion
- [ ] Understand MPC (secret sharing, thresholds)
- [ ] Understand FHE (homomorphic ops, noise)
- [ ] Built and deployed fhEVM contract
- [ ] Experimented with Fhenix
- [ ] Know when to use MPC vs FHE vs ZK vs TEE

**Phase 4 Completed**: ___________

---

## Phase 5: Building (Ongoing)

### Project 1: ZK Membership Proof
- [ ] Design: Prove membership in group without revealing identity
- [ ] Build Merkle tree circuit in Circom
- [ ] Create proof generation script
- [ ] Deploy verifier contract
- [ ] Build simple frontend
- [ ] **Status**: ___________

**Notes**:
```
(your notes here)
```

### Project 2: Private Voting (Semaphore)
- [ ] Study Semaphore protocol docs
- [ ] Clone semaphore-protocol/semaphore
- [ ] Build anonymous voting dApp
- [ ] Implement double-voting prevention
- [ ] Deploy to testnet
- [ ] **Status**: ___________

**Notes**:
```
(your notes here)
```

### Project 3: Confidential DeFi
- [ ] Choose: dark pool / sealed-bid auction / private lending
- [ ] Design with appropriate privacy tech (ZK/FHE/TEE)
- [ ] Implement core contracts
- [ ] Write comprehensive tests
- [ ] Document architecture
- [ ] **Status**: ___________

**Notes**:
```
(your notes here)
```

### Project 4: Contribute to Protocol
- [ ] Choose protocol (Semaphore, ZAMA, Noir, Halo2, etc.)
- [ ] Study codebase
- [ ] Find good first issue
- [ ] Submit PR
- [ ] **Status**: ___________

**Notes**:
```
(your notes here)
```

---

## Resource Quick Links

### Phase 1
- [RareSkills ZK Book](https://www.rareskills.io/zk-book)
- [Cyfrin: Rings and Fields](https://www.cyfrin.io/blog/zk-math-101-rings-and-fields)
- [Dankrad: KZG Commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html)
- [Vitalik: Pairings](https://medium.com/@VitalikButerin/exploring-elliptic-curve-pairings-c73c1864e627)

### Phase 2
- [zk-learning.org MOOC](https://zk-learning.org/)
- [Circom Docs](https://docs.circom.io/)
- [RareSkills Circom Intro](https://rareskills.io/post/circom-intro)
- [Noir Docs](https://noir-lang.org/docs/)
- [ZKCamp Noir Course](https://github.com/ZKCamp/aztec-noir-course)
- [Halo2 Course](https://halo2.zksecurity.xyz/)

### Phase 3
- [a16z TEE Primer](https://a16zcrypto.com/posts/article/trusted-execution-environments-tees-primer/)
- [SGX 101](https://sgx101.gitbook.io/sgx101/)
- [awesome-tee-blockchain](https://github.com/dineshpinto/awesome-tee-blockchain)

### Phase 4
- [ZAMA fhEVM Docs](https://docs.zama.org/protocol/)
- [fhEVM GitHub](https://github.com/zama-ai/fhevm)
- [Fhenix Docs](https://docs.fhenix.io/)
- [Alchemy MPC Guide](https://www.alchemy.com/overviews/what-is-a-multi-party-computation-mpc-wallet)

### Phase 5
- [Semaphore Protocol](https://semaphore.pse.dev/)
- [MACI (Voting)](https://github.com/privacy-scaling-explorations/maci)

---

## Weekly Log

Use this to track your actual progress week by week.

| Week | Dates | Focus | Hours | Notes |
|------|-------|-------|-------|-------|
| 1 | | Groups | | |
| 2 | | Fields | | |
| 3 | | EC Basics | | |
| 4 | | EC/Finite | | |
| 5 | | Polynomials | | |
| 6 | | KZG | | |
| 7 | | Hash/Sig | | |
| 8 | | Pairings | | |
| 9 | | ZK Theory | | |
| 10 | | ZK Theory | | |
| 11 | | Proof Sys | | |
| 12 | | Proof Sys | | |
| 13 | | Circom | | |
| 14 | | Circom | | |
| 15 | | Circom Adv | | |
| 16 | | Circom Adv | | |
| 17 | | Noir | | |
| 18 | | Noir | | |
| 19 | | Halo2 | | |
| 20 | | Halo2 | | |
| 21 | | TEE Concepts | | |
| 22 | | TEE Concepts | | |
| 23 | | SGX | | |
| 24 | | SGX | | |
| 25 | | TEE Chains | | |
| 26 | | TEE Chains | | |
| 27 | | MPC | | |
| 28 | | MPC | | |
| 29 | | MPC Practice | | |
| 30 | | MPC Practice | | |
| 31 | | FHE Theory | | |
| 32 | | FHE Theory | | |
| 33 | | fhEVM | | |
| 34 | | fhEVM | | |
| 35 | | Fhenix | | |
| 36 | | Fhenix | | |

---

*Last updated: January 10, 2026*
