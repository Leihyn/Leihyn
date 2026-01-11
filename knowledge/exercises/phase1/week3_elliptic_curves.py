"""
Week 3-4: Elliptic Curves
=========================

Run with: python week3_elliptic_curves.py

Uses py_ecc library for BN128 curve (same as Ethereum)
"""

from py_ecc.bn128 import G1, G2, multiply, add, neg, curve_order, field_modulus

print("=" * 50)
print("Week 3-4: Elliptic Curves with py_ecc")
print("=" * 50)

# ============================================
# Part 1: Understanding the Generator Point
# ============================================

print("\n1. Generator Point G1")
print("-" * 30)
print(f"G1 = {G1}")
print(f"G1 is a point on the BN128 curve")
print(f"Curve order (number of points) = {curve_order}")

# ============================================
# Part 2: Scalar Multiplication
# ============================================

print("\n2. Scalar Multiplication")
print("-" * 30)

# n * G means: add G to itself n times
# This is EASY to compute (fast)

P = multiply(G1, 5)  # 5 * G1
print(f"5 * G1 = {P}")

Q = multiply(G1, 7)  # 7 * G1
print(f"7 * G1 = {Q}")

# ============================================
# Part 3: Point Addition
# ============================================

print("\n3. Point Addition")
print("-" * 30)

# P + Q should equal 12 * G1
R = add(P, Q)
R_expected = multiply(G1, 12)

print(f"(5*G1) + (7*G1) = {R}")
print(f"12 * G1 = {R_expected}")
print(f"Equal? {R == R_expected}")

# ============================================
# Part 4: The Discrete Log Problem
# ============================================

print("\n4. Discrete Logarithm Problem")
print("-" * 30)

secret = 12345
public_point = multiply(G1, secret)

print(f"Secret scalar: {secret}")
print(f"Public point P = secret * G1")
print(f"P = {public_point}")
print()
print("THE HARD PROBLEM:")
print("Given P, find 'secret' such that P = secret * G1")
print("This is computationally infeasible for large secrets!")
print("Security of elliptic curve crypto depends on this.")

# ============================================
# Part 5: Exercise - Verify Properties
# ============================================

print("\n5. Exercise: Verify EC Group Properties")
print("-" * 30)

# Identity: P + O = P (O is point at infinity, represented as None)
# In py_ecc, we can't directly represent O, but add handles it

# Inverse: P + (-P) = O
P = multiply(G1, 42)
neg_P = neg(P)
# result = add(P, neg_P)  # This would give point at infinity

print("Verifying: 42*G + (-42*G) = O (point at infinity)")
print(f"42 * G1 = {P}")
print(f"-(42 * G1) = {neg_P}")
print("Note: y-coordinate is negated (mod field_modulus)")

# Associativity: (P + Q) + R = P + (Q + R)
A = multiply(G1, 3)
B = multiply(G1, 5)
C = multiply(G1, 7)

left = add(add(A, B), C)   # (A + B) + C
right = add(A, add(B, C))  # A + (B + C)

print(f"\nAssociativity: (3G + 5G) + 7G = 3G + (5G + 7G)?")
print(f"Equal? {left == right}")

# ============================================
# Part 6: Real-world application preview
# ============================================

print("\n6. Preview: Public Key Cryptography")
print("-" * 30)

# Alice generates keypair
alice_private = 0xDEADBEEF  # Secret!
alice_public = multiply(G1, alice_private)

print("Alice's private key: 0xDEADBEEF (secret)")
print(f"Alice's public key: {alice_public}")
print()
print("Anyone can verify Alice's signatures using her public key,")
print("but only Alice (with private key) can create valid signatures.")

# ============================================
# Checkpoint
# ============================================

print("\n" + "=" * 50)
print("Checkpoint questions:")
print("=" * 50)
print("[ ] Why is scalar multiplication easy but discrete log hard?")
print("[ ] What makes a point valid on the curve?")
print("[ ] What is the curve order and why does it matter?")
print("[ ] How is this used in Ethereum addresses?")
