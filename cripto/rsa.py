"""RSA de libro de texto (sin padding), como en clase."""
from .nt import inverse, random_prime, load, save
from math import gcd

E = 65537


def keygen(bits):
    while True:
        p = random_prime(bits // 2)
        q = random_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(E, phi) == 1:
            break
    n = p * q
    d = inverse(E, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": E, "d": d}


def get_or_create(name, bits):
    k = load(name)
    if k is None:
        k = save(name, keygen(bits))
    return k


def encrypt(m, e, n):
    assert 0 <= m < n, "el mensaje debe ser menor que n"
    return pow(m, e, n)


def decrypt(c, d, n):
    return pow(c, d, n)
