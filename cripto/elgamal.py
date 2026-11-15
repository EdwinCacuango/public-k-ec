"""ElGamal sobre Z_p^* con p primo seguro."""
import secrets

from .nt import inverse, random_safe_prime


def find_generator(p, q):
    for g in range(2, p):
        if pow(g, 2, p) != 1 and pow(g, q, p) != 1:
            return g


def keygen(bits):
    p, q = random_safe_prime(bits)
    g = find_generator(p, q)
    x = secrets.randbelow(p - 3) + 2
    return {"p": p, "q": q, "g": g, "x": x, "h": pow(g, x, p)}


def encrypt(m, p, g, h):
    k = secrets.randbelow(p - 3) + 2
    return k, pow(g, k, p), m * pow(h, k, p) % p


def decrypt(c1, c2, x, p):
    return c2 * inverse(pow(c1, x, p), p) % p
