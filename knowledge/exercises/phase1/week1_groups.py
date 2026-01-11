"""
Week 1: Groups & Modular Arithmetic
====================================

Run with: python week1_groups.py

Exercises:
1. Implement modular arithmetic from scratch
2. Verify group properties
3. Find a generator of Z_p*
"""

# Exercise 1: Implement modular arithmetic
# ----------------------------------------

def mod_add(a: int, b: int, p: int) -> int:
    """Add two numbers modulo p"""
    # TODO: Implement this
    pass

def mod_mul(a: int, b: int, p: int) -> int:
    """Multiply two numbers modulo p"""
    # TODO: Implement this
    pass

def mod_inv(a: int, p: int) -> int:
    """
    Find multiplicative inverse of a modulo p.
    Uses Fermat's little theorem: a^(-1) = a^(p-2) mod p
    """
    # TODO: Implement this
    pass


# Exercise 2: Verify group properties
# -----------------------------------

def verify_group_properties(p: int):
    """
    Verify that Z_p* (non-zero integers mod p) forms a group.

    Group properties:
    1. Closure: a * b is in the group
    2. Associativity: (a * b) * c = a * (b * c)
    3. Identity: 1 * a = a
    4. Inverse: a * a^(-1) = 1
    """
    print(f"Verifying group properties for Z_{p}*")

    # TODO: Test closure
    # TODO: Test associativity
    # TODO: Test identity
    # TODO: Test inverses

    print("All group properties verified!")


# Exercise 3: Find a generator
# ----------------------------

def find_generator(p: int) -> int:
    """
    Find a generator of Z_p*.

    A generator g satisfies: {g^1, g^2, ..., g^(p-1)} = Z_p*
    The order of the group is p-1.
    """
    # TODO: Find a number g such that g^(p-1) = 1 mod p
    # and g^k != 1 for any k < p-1
    pass


def is_generator(g: int, p: int) -> bool:
    """Check if g is a generator of Z_p*"""
    # TODO: Implement this
    pass


# ============================================
# SOLUTIONS (uncomment to check your answers)
# ============================================

def mod_add_solution(a: int, b: int, p: int) -> int:
    return (a + b) % p

def mod_mul_solution(a: int, b: int, p: int) -> int:
    return (a * b) % p

def mod_inv_solution(a: int, p: int) -> int:
    return pow(a, p - 2, p)

def is_generator_solution(g: int, p: int) -> bool:
    """Check if g generates all of Z_p*"""
    seen = set()
    val = 1
    for _ in range(p - 1):
        val = (val * g) % p
        seen.add(val)
    return len(seen) == p - 1

def find_generator_solution(p: int) -> int:
    for g in range(2, p):
        if is_generator_solution(g, p):
            return g
    return -1


# ============================================
# TESTS
# ============================================

if __name__ == "__main__":
    p = 17  # Small prime for testing

    print("=" * 50)
    print("Week 1: Groups & Modular Arithmetic")
    print("=" * 50)

    # Test modular arithmetic
    print("\n1. Testing modular arithmetic...")

    # Using solutions for demo - replace with your implementations
    a, b = 5, 7

    print(f"   {a} + {b} mod {p} = {mod_add_solution(a, b, p)}")
    print(f"   {a} * {b} mod {p} = {mod_mul_solution(a, b, p)}")
    print(f"   {a}^(-1) mod {p} = {mod_inv_solution(a, p)}")

    # Verify inverse
    inv_a = mod_inv_solution(a, p)
    assert mod_mul_solution(a, inv_a, p) == 1, "Inverse check failed!"
    print(f"   Verified: {a} * {inv_a} mod {p} = 1 ✓")

    # Find generator
    print(f"\n2. Finding generator of Z_{p}*...")
    g = find_generator_solution(p)
    print(f"   Generator found: {g}")

    # Show powers of generator
    print(f"\n3. Powers of generator {g}:")
    powers = []
    val = 1
    for i in range(1, p):
        val = (val * g) % p
        powers.append(val)
    print(f"   {g}^1 to {g}^{p-1} = {powers}")
    print(f"   Generates all of Z_{p}* = {set(powers) == set(range(1, p))}")

    print("\n" + "=" * 50)
    print("Checkpoint questions:")
    print("=" * 50)
    print("[ ] What makes Z_p* a group?")
    print("[ ] Why do we use prime p?")
    print("[ ] What is the order of Z_p*?")
    print("[ ] How does Fermat's little theorem give us inverses?")
