# Phase 1: Mathematical Foundations for ZK

The math that makes zero-knowledge proofs work. This is the foundation - don't skip it.

---

## Overview

| Topic | Why It Matters |
|-------|----------------|
| Groups | Basic algebraic structure, cyclic groups enable discrete log |
| Rings & Fields | Polynomial math lives here |
| Finite Fields | All ZK math happens in finite fields (mod p) |
| Elliptic Curves | Where commitments and pairings happen |
| Polynomials | Encode computations as polynomials |
| Commitments | Hide data while proving properties about it |

---

## Week 1-2: Groups & Finite Fields

### What to Learn

1. **Groups**
   - Definition: set + operation + identity + inverses + associativity
   - Cyclic groups and generators
   - Group order
   - Subgroups

2. **Rings**
   - Groups with two operations (addition + multiplication)
   - Polynomial rings

3. **Fields**
   - Rings where every non-zero element has multiplicative inverse
   - Prime fields (Z_p)
   - Why we use prime modulus

4. **Finite/Galois Fields**
   - F_p (integers mod prime p)
   - Field arithmetic: addition, multiplication, inversion
   - Fermat's Little Theorem (for finding inverses)

### Resources (Pick One Path)

**Path A: ZK-Focused (Recommended)**
- [RareSkills ZK Book - Chapter 1-3](https://www.rareskills.io/zk-book) - Start here, code-focused
- [Cyfrin: Rings and Fields for ZK](https://www.cyfrin.io/blog/zk-math-101-rings-and-fields) - Concise explainer

**Path B: Traditional + Deep**
- [Abstract Algebra: Theory and Applications](https://open.umn.edu/opentextbooks/textbooks/217) (Judson) - Free textbook, Chapters 1-5
- Has Sage code examples

**Path C: Quick Reference**
- [Medium: Abstract Algebra for Cryptography](https://medium.com/@olusojiobah/abstract-algebra-for-cryptography-517916943266) - Overview article

### Checkpoint Exercises

After Week 2, you should be able to:

```python
# 1. Implement modular arithmetic from scratch
def mod_add(a, b, p):
    return (a + b) % p

def mod_mul(a, b, p):
    return (a * b) % p

def mod_inv(a, p):
    # Fermat's little theorem: a^(-1) = a^(p-2) mod p
    return pow(a, p - 2, p)

# 2. Verify group properties
p = 17  # prime
# Check: Z_p* is cyclic group of order p-1
# Find a generator

# 3. Understand why this works:
assert mod_mul(5, mod_inv(5, 17), 17) == 1
```

**Checkpoint questions:**
- [ ] What makes a group "cyclic"?
- [ ] Why do we use prime numbers for the modulus?
- [ ] What is the order of Z_p*?
- [ ] How do you find the multiplicative inverse in a finite field?

---

## Week 3-4: Elliptic Curves

### What to Learn

1. **EC Basics**
   - Curve equation: y² = x³ + ax + b
   - Points on the curve
   - Point at infinity (identity element)

2. **EC Group Operations**
   - Point addition (geometric intuition)
   - Point doubling
   - Scalar multiplication (n * P)

3. **EC over Finite Fields**
   - Same operations, but mod p
   - Discrete log problem on curves
   - Why EC is secure

4. **Common Curves**
   - secp256k1 (Bitcoin, Ethereum)
   - BN254/alt_bn128 (Ethereum precompiles, ZK)
   - BLS12-381 (Ethereum 2.0, newer ZK)

### Resources

**Primary (Pick One)**
- [Elliptic Curve Cryptography for Developers](https://www.manning.com/books/elliptic-curve-cryptography-for-developers) (Rosing) - Best for devs, has ZK chapter
- [RareSkills ZK Book - Elliptic Curves Chapter](https://www.rareskills.io/zk-book)
- [Metaschool: ECC Comprehensive Guide](https://metaschool.so/articles/elliptic-curve-cryptography) - Free intro

**Visual Understanding**
- [An Intuitive Explanation of Elliptic Curve Cryptography](https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/) - Cloudflare blog

### Code Exercise

```python
# Using Python's py_ecc library
from py_ecc.bn128 import G1, multiply, add, curve_order

# G1 is the generator point
print(f"Generator: {G1}")

# Scalar multiplication: compute 5 * G
P = multiply(G1, 5)
print(f"5 * G = {P}")

# Point addition
Q = multiply(G1, 7)
R = add(P, Q)  # Should equal 12 * G
assert R == multiply(G1, 12)

# The discrete log problem:
# Given R, find n such that R = n * G
# This is computationally infeasible for large n
```

**Checkpoint questions:**
- [ ] Why is point addition on EC a group operation?
- [ ] What is the discrete logarithm problem on elliptic curves?
- [ ] Why is scalar multiplication easy but reverse (discrete log) hard?
- [ ] What curve does Ethereum use for ZK precompiles?

---

## Week 5-6: Polynomials & Commitments

### What to Learn

1. **Polynomial Basics**
   - Polynomial representation
   - Evaluation at a point
   - Lagrange interpolation (crucial!)
   - Schwartz-Zippel lemma

2. **Why Polynomials for ZK**
   - Encode constraints as polynomials
   - If P(x) = Q(x) at random point, probably equal everywhere
   - Polynomials can encode arbitrary computations

3. **Commitment Schemes**
   - Commit: lock in a value without revealing it
   - Open: prove what you committed to
   - Hiding + Binding properties

4. **KZG Polynomial Commitments**
   - Commit to polynomial with single group element
   - Open at any point efficiently
   - Trusted setup requirement

### Resources

**Polynomials**
- [RareSkills: Polynomials Chapter](https://www.rareskills.io/zk-book)
- [Vitalik: Quadratic Arithmetic Programs](https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649)

**KZG Commitments**
- [Dankrad Feist: KZG Polynomial Commitments](https://dankradfeist.de/ethereum/2020/06/16/kate-polynomial-commitments.html) - Best intro
- [KZG with Code Walkthrough](https://kaijuneer.medium.com/explaining-kzg-commitment-with-code-walkthrough-216638a620c9) - Implementation guide
- [Mastering KZG by Hands](https://thogiti.github.io/2024/03/22/Mastering-KZG-by-hands.html) - Step by step
- [Scroll: KZG in Practice](https://scroll.io/blog/kzg) - Production context
- [GitHub: kzg-commitments-study](https://github.com/arnaucube/kzg-commitments-study) - Code to study

### Code Exercise

```python
import numpy as np

# Lagrange interpolation
# Given points, find the unique polynomial passing through them
def lagrange_interpolate(points, x):
    """
    points: list of (x_i, y_i) tuples
    x: point to evaluate at
    """
    n = len(points)
    result = 0

    for i in range(n):
        xi, yi = points[i]
        term = yi
        for j in range(n):
            if i != j:
                xj, _ = points[j]
                term *= (x - xj) / (xi - xj)
        result += term

    return result

# Example: polynomial passing through (1,2), (2,4), (3,8)
points = [(1, 2), (2, 4), (3, 8)]
# This encodes some polynomial P(x)

# Evaluate at x=4
print(lagrange_interpolate(points, 4))  # What's P(4)?

# Key insight: n points determine a degree-(n-1) polynomial uniquely
```

**Checkpoint questions:**
- [ ] How does Lagrange interpolation work?
- [ ] What does the Schwartz-Zippel lemma tell us?
- [ ] What is a polynomial commitment? Why is it useful for ZK?
- [ ] What is the trusted setup in KZG and why is it needed?

---

## Week 7-8: Cryptographic Primitives

### What to Learn

1. **Hash Functions**
   - Collision resistance, preimage resistance
   - Pedersen hashes (EC-based, ZK-friendly)
   - Poseidon hash (SNARK-optimized)

2. **Digital Signatures**
   - ECDSA (used in Ethereum txs)
   - Schnorr signatures (simpler, aggregatable)
   - BLS signatures (pairing-based, aggregatable)

3. **Pairings (Bilinear Maps)**
   - e(aG, bH) = e(G, H)^(ab)
   - Why this enables KZG and SNARKs
   - BN254 and BLS12-381 pairing curves

### Resources

- [RareSkills: Pairings Chapter](https://www.rareskills.io/zk-book)
- [Vitalik: Exploring Elliptic Curve Pairings](https://medium.com/@VitalikButerin/exploring-elliptic-curve-pairings-c73c1864e627)
- [BLS Signatures Explainer](https://eth2book.info/capella/part2/building_blocks/signatures/)

### Pairing Intuition

```
# Pairings let you "multiply" encrypted values

# Without pairings:
# Given: g^a, g^b
# Cannot compute: g^(ab)

# With pairings:
# Given: g1^a, g2^b
# Can compute: e(g1^a, g2^b) = e(g1, g2)^(ab)

# This enables:
# - Verifying polynomial evaluations (KZG)
# - Checking that prover knows secret without revealing it
```

**Checkpoint questions:**
- [ ] What makes a hash function "ZK-friendly"?
- [ ] How do Schnorr signatures differ from ECDSA?
- [ ] What is a bilinear pairing and why does it matter for ZK?
- [ ] Why can't we do SNARKs without pairings (or alternative like FRI)?

---

## Phase 1 Completion Checklist

You're ready for Phase 2 (ZK Deep Dive) when you can:

- [ ] Implement finite field arithmetic (add, mul, inv) from scratch
- [ ] Explain why Z_p* forms a cyclic group
- [ ] Perform EC point addition by hand (on paper)
- [ ] Implement Lagrange interpolation
- [ ] Explain KZG commitments at a high level
- [ ] Understand why pairings enable polynomial verification
- [ ] Know the difference between SNARK-friendly and STARK-friendly constructions

---

## Recommended Study Schedule

| Week | Focus | Primary Resource |
|------|-------|------------------|
| 1 | Groups basics | RareSkills ZK Book Ch 1-2 |
| 2 | Finite fields | RareSkills + Cyfrin article |
| 3 | EC fundamentals | Rosing book or RareSkills |
| 4 | EC over finite fields | Code exercises with py_ecc |
| 5 | Polynomials | RareSkills + Vitalik QAP post |
| 6 | KZG commitments | Dankrad's post + code walkthrough |
| 7 | Hash + signatures | RareSkills |
| 8 | Pairings | Vitalik's pairings post |

---

## Setup Your Environment

```bash
# Python (for quick prototyping)
pip install py_ecc numpy

# Rust (for production-grade code later)
# Install rustup, then:
cargo install --git https://github.com/arkworks-rs/algebra

# Sage (optional, great for algebra)
# https://www.sagemath.org/
```

---

## Next Step

After Phase 1, move to [Phase 2: ZK Deep Dive](./zk-phase2-circuits.md) where you'll:
- Learn SNARK/STARK theory
- Write your first Circom circuits
- Understand R1CS and proof systems

---

*Sources: RareSkills, Cyfrin, Manning Publications, Dankrad Feist, Vitalik Buterin, Scroll Documentation*
