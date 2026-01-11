"""
Week 5-6: Polynomials & Lagrange Interpolation
===============================================

Run with: python week5_polynomials.py

Key concept: n points uniquely determine a degree-(n-1) polynomial
This is the foundation of polynomial commitments (KZG).
"""

from typing import List, Tuple

print("=" * 50)
print("Week 5-6: Polynomials & Lagrange Interpolation")
print("=" * 50)

# ============================================
# Part 1: Polynomial Representation
# ============================================

print("\n1. Polynomial Representation")
print("-" * 30)

# P(x) = 3x^2 + 2x + 1 is represented as [1, 2, 3]
# coefficients[i] = coefficient of x^i

def eval_poly(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial at x"""
    result = 0
    for i, c in enumerate(coeffs):
        result += c * (x ** i)
    return result

# Example: P(x) = x^2 + 2x + 3
coeffs = [3, 2, 1]  # 3 + 2x + x^2
print(f"P(x) = {coeffs[2]}x^2 + {coeffs[1]}x + {coeffs[0]}")
print(f"P(0) = {eval_poly(coeffs, 0)}")
print(f"P(1) = {eval_poly(coeffs, 1)}")
print(f"P(2) = {eval_poly(coeffs, 2)}")

# ============================================
# Part 2: Lagrange Interpolation
# ============================================

print("\n2. Lagrange Interpolation")
print("-" * 30)

def lagrange_interpolate(points: List[Tuple[int, int]], x: int) -> float:
    """
    Given n points, find the unique polynomial P of degree n-1
    that passes through all points, and evaluate P(x).

    Key insight: We construct P as sum of basis polynomials L_i
    where L_i(x_i) = 1 and L_i(x_j) = 0 for j != i
    """
    n = len(points)
    result = 0.0

    for i in range(n):
        xi, yi = points[i]

        # Build Lagrange basis polynomial L_i
        # L_i(x) = product of (x - x_j) / (x_i - x_j) for j != i
        basis = 1.0
        for j in range(n):
            if i != j:
                xj, _ = points[j]
                basis *= (x - xj) / (xi - xj)

        result += yi * basis

    return result

# Example: Find polynomial through (1, 2), (2, 5), (3, 10)
# This is P(x) = x^2 + 1
points = [(1, 2), (2, 5), (3, 10)]
print(f"Points: {points}")
print(f"Finding polynomial through these points...")
print()

for x in range(0, 6):
    y = lagrange_interpolate(points, x)
    print(f"P({x}) = {y:.1f}")

print()
print("Note: This matches P(x) = x^2 + 1")

# ============================================
# Part 3: Exercise - Implement Yourself
# ============================================

print("\n3. Exercise: Secret Sharing with Polynomials")
print("-" * 30)

def share_secret(secret: int, k: int, n: int) -> List[Tuple[int, int]]:
    """
    Split secret into n shares where any k can reconstruct.

    Method:
    1. Create random polynomial P of degree k-1 with P(0) = secret
    2. Shares are (i, P(i)) for i = 1 to n
    """
    import random

    # P(x) = secret + a1*x + a2*x^2 + ... + a_{k-1}*x^{k-1}
    coeffs = [secret] + [random.randint(1, 100) for _ in range(k - 1)]

    shares = []
    for i in range(1, n + 1):
        shares.append((i, eval_poly(coeffs, i)))

    return shares

def reconstruct_secret(shares: List[Tuple[int, int]]) -> int:
    """Reconstruct secret from k shares using Lagrange interpolation"""
    # Secret is P(0)
    return round(lagrange_interpolate(shares, 0))

# Demo: 2-of-3 secret sharing
secret = 42
shares = share_secret(secret, k=2, n=3)
print(f"Secret: {secret}")
print(f"Shares (2-of-3): {shares}")
print()

# Reconstruct from different pairs
print("Reconstruction:")
print(f"  From shares 1,2: {reconstruct_secret(shares[:2])}")
print(f"  From shares 2,3: {reconstruct_secret(shares[1:])}")
print(f"  From shares 1,3: {reconstruct_secret([shares[0], shares[2]])}")

# ============================================
# Part 4: Why This Matters for ZK
# ============================================

print("\n4. Connection to Zero-Knowledge Proofs")
print("-" * 30)

print("""
Key Insight (Schwartz-Zippel Lemma):
------------------------------------
If two polynomials P(x) and Q(x) of degree d are different,
they can agree on at most d points.

So if P(r) = Q(r) for a random r, with high probability P = Q.

This is used in ZK proofs:
1. Prover encodes computation as polynomial P
2. Verifier picks random point r
3. Prover shows P(r) = expected value
4. If true for random r, computation was probably correct!

Polynomial Commitments (KZG):
----------------------------
1. Commit to polynomial P without revealing it
2. Later prove P(r) = v for any r
3. Commitment is a single elliptic curve point!
4. This enables succinct proofs (small, fast to verify)
""")

# ============================================
# Part 5: Finite Field Version (for real ZK)
# ============================================

print("\n5. Finite Field Lagrange (Production Version)")
print("-" * 30)

def lagrange_interpolate_field(points: List[Tuple[int, int]], x: int, p: int) -> int:
    """Lagrange interpolation in finite field Z_p"""
    n = len(points)
    result = 0

    for i in range(n):
        xi, yi = points[i]

        # Compute Lagrange basis
        num = 1
        den = 1
        for j in range(n):
            if i != j:
                xj, _ = points[j]
                num = (num * (x - xj)) % p
                den = (den * (xi - xj)) % p

        # Modular inverse of denominator
        den_inv = pow(den, p - 2, p)

        basis = (num * den_inv) % p
        result = (result + yi * basis) % p

    return result

# In a prime field
p = 101  # Small prime for demo
points_field = [(1, 10), (2, 25), (3, 50)]
print(f"Field: Z_{p}")
print(f"Points: {points_field}")
print(f"P(0) mod {p} = {lagrange_interpolate_field(points_field, 0, p)}")
print(f"P(5) mod {p} = {lagrange_interpolate_field(points_field, 5, p)}")

# ============================================
# Checkpoint
# ============================================

print("\n" + "=" * 50)
print("Checkpoint questions:")
print("=" * 50)
print("[ ] Why do n points determine a degree-(n-1) polynomial?")
print("[ ] What is the Schwartz-Zippel lemma?")
print("[ ] How does polynomial interpolation enable secret sharing?")
print("[ ] Why use finite fields instead of real numbers?")
