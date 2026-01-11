# ZK, Privacy & TEE Learning Roadmap

A structured path from DeFi engineer to privacy/ZK specialist.

## Why This Matters

Privacy is the next unlock for DeFi:
- **ZK Rollups** are winning the L2 scaling race (zkSync, Scroll, Linea, Polygon zkEVM)
- **Private DeFi** solves MEV, front-running, and information leakage
- **Confidential compute** enables new primitives (dark pools, sealed-bid auctions, private lending)
- **$1B+** invested in Decentralized Confidential Computing (DeCC) projects

Your existing DeFi skills + privacy tech = rare, high-demand profile.

---

## The Three Pillars

| Technology | What It Does | Trade-offs |
|------------|--------------|------------|
| **ZK Proofs** | Prove computation without revealing inputs | Complex circuits, proving time |
| **TEEs** | Hardware-isolated secure enclaves | Trust hardware vendor, side-channel attacks |
| **MPC/FHE** | Compute on encrypted data | Slow, communication overhead |

Modern systems combine these (hybrid architectures) for defense-in-depth.

---

## Learning Path (Ordered)

### Phase 1: Foundations (4-8 weeks)

**Goal**: Understand the math and core concepts before touching code.

1. **Abstract Algebra Basics**
   - Groups, Rings, Fields
   - Finite/Galois fields (critical for ZK)
   - Elliptic curve basics

2. **Cryptographic Primitives**
   - Hash functions, commitment schemes
   - Digital signatures (ECDSA, Schnorr, BLS)
   - Polynomial commitments

**Resources**:
- [RareSkills ZK Book](https://www.rareskills.io/zk-book) - From algebra to building a SNARK
- [MoonMath Manual](https://leastauthority.com/community-matters/moonmath-manual/) - Deep reference for zk-SNARK math
- Khan Academy - Abstract algebra refresher

### Phase 2: ZK Deep Dive (8-12 weeks)

**Goal**: Understand SNARKs, STARKs, and write circuits.

1. **Theory**
   - Interactive proofs → Non-interactive (Fiat-Shamir)
   - R1CS and QAP (how circuits become proofs)
   - Trusted setup vs transparent (SNARKs vs STARKs)
   - Plonk, Groth16, Halo2 proof systems

2. **Hands-On Circuit Development**
   - Start with **Circom** (easiest, most resources)
   - Graduate to **Noir** (Aztec's modern ZK DSL)
   - Advanced: **Halo2** (Rust, production-grade)

**Resources**:
- [Zero Knowledge Proofs MOOC](https://zk-learning.org/) - Full course with exercises
- [MIT IAP Modern ZK Cryptography](https://zkiap.com/) - Lectures + problem sets
- [RareSkills ZK Bootcamp](https://rareskills.io/zk-bootcamp) - Paid, comprehensive
- [0xPARC Halo2 Learning Group](https://learn.0xparc.org/halo2) - Advanced circuits
- [Noir Documentation](https://noir-lang.org/docs) - Modern ZK language

**Vitalik's Blog Posts** (essential reading):
- "Quadratic Arithmetic Programs: From Zero to Hero"
- "zk-SNARKs: Under the Hood"
- "STARKs" series

### Phase 3: TEEs (4-6 weeks)

**Goal**: Understand hardware enclaves and their blockchain applications.

1. **Core Concepts**
   - Enclave architecture (code + data isolation)
   - Attestation (proving code runs in TEE)
   - Side-channel attack vectors

2. **Hardware Platforms**
   - Intel SGX - Most widely used in crypto
   - Intel TDX - Next-gen
   - AMD SEV-SNP - Alternative vendor
   - ARM TrustZone - Mobile
   - Keystone (RISC-V) - Open source

**Resources**:
- [a16z TEE Primer](https://a16zcrypto.com/posts/article/trusted-execution-environments-tees-primer/)
- [awesome-tee-blockchain](https://github.com/dineshpinto/awesome-tee-blockchain) - Curated papers & code
- [Metaschool TEE Guide](https://metaschool.so/articles/trusted-execution-environments-tees)
- Intel SGX Developer Reference

**Study These Protocols**:
- **Secret Network** - First TEE-based private smart contracts (Cosmos + SGX)
- **Oasis Network** - Confidential compute layer
- **Unichain** - TEE-based MEV protection in block building
- **Flashbots SUAVE** - TEE for MEV auction privacy

### Phase 4: MPC & FHE (6-10 weeks)

**Goal**: Understand multi-party computation and homomorphic encryption.

1. **MPC Fundamentals**
   - Secret sharing (Shamir's)
   - Secure two-party computation
   - Threshold signatures
   - MPC wallets (practical application)

2. **FHE Basics**
   - Homomorphic operations on ciphertexts
   - Noise growth and bootstrapping
   - TFHE, BGV, CKKS schemes

**Resources**:
- [Alchemy MPC Wallet Guide](https://www.alchemy.com/overviews/what-is-a-multi-party-computation-mpc-wallet)
- [ZAMA fhEVM Documentation](https://docs.zama.ai/fhevm) - FHE smart contracts
- [OpenFHE](https://www.openfhe.org/) - C++ FHE library
- [Fhenix Documentation](https://docs.fhenix.io/) - FHE L2

**Study These Protocols**:
- **Partisia Blockchain** - MPC + FHE Layer 1
- **ZAMA/fhEVM** - FHE for EVM (unicorn, $1B+ valuation)
- **Fhenix** - FHE-powered L2

### Phase 5: Integration & Building (Ongoing)

**Goal**: Build privacy-preserving DeFi applications.

1. **ZK Applications**
   - Private voting (Semaphore, MACI)
   - Identity (zk-passport, WorldID)
   - Private transfers (Tornado Cash architecture study)
   - ZK bridges

2. **Confidential DeFi**
   - Dark pools
   - Sealed-bid auctions
   - Private lending/credit scoring
   - MEV-resistant order flow

---

## Books (Physical/Digital)

| Book | Focus | Level |
|------|-------|-------|
| **Proofs, Arguments, and Zero-Knowledge** (Thaler) | ZK theory | Advanced |
| **A Graduate Course in Applied Cryptography** (Boneh-Shoup) | Crypto foundations | Intermediate |
| **MoonMath Manual** (Least Authority) | zk-SNARK math | Intermediate |
| **RareSkills ZK Book** | Practical ZK | Beginner-Intermediate |
| **Programming Bitcoin** (Song) | Crypto primitives | Beginner |

---

## Podcasts & Community

- [Zero Knowledge Podcast](https://zeroknowledge.fm/) - Long-form interviews with researchers
- [ZK Hack](https://zkhack.dev/) - Hackathons, workshops, puzzles
- [PSE (Privacy Stewards of Ethereum)](https://pse.dev/) - Ethereum privacy research

---

## Suggested Project Progression

1. **Beginner**: Build a ZK proof of membership (Merkle tree + Circom)
2. **Intermediate**: Create a private voting system with Semaphore
3. **Intermediate**: Integrate Secret Network for confidential DeFi logic
4. **Advanced**: Build a ZK rollup component or contribute to existing one
5. **Advanced**: Implement FHE-based sealed-bid auction on Fhenix

---

## Key GitHub Repos to Study

```
matter-labs/awesome-zero-knowledge-proofs  # Curated ZK resources
iden3/circom                               # ZK circuit compiler
noir-lang/noir                             # Modern ZK DSL
privacy-scaling-explorations/maci          # Private voting
semaphore-protocol/semaphore               # Anonymous signaling
zama-ai/fhevm                              # FHE smart contracts
dineshpinto/awesome-tee-blockchain         # TEE resources
```

---

## Timeline Suggestion

This is a deep field. Realistic expectations:

- **3-6 months**: Solid conceptual understanding, basic circuits
- **6-12 months**: Build meaningful ZK applications
- **12-18 months**: Contribute to protocol-level code
- **18+ months**: Design novel privacy systems

The math is front-loaded. Push through Phase 1-2 foundations even when it's hard - everything else builds on it.

---

## Next Actions

1. Start RareSkills ZK Book (free, online)
2. Watch first 3 lectures of zk-learning.org MOOC
3. Set up Circom development environment
4. Read Vitalik's "Quadratic Arithmetic Programs" post
5. Join ZK Hack Discord for community

---

*Sources compiled January 2026*
