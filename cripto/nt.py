"""Teoría de números básica (sin librerías externas)."""
import json
import math
import os
import secrets
import time

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def is_probable_prime(n, rounds=40):
    """Test de Miller-Rabin."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(c):
            return c


def random_safe_prime(bits):
    """p = 2q + 1 con q primo (útil para ElGamal: generador fácil de comprobar)."""
    while True:
        q = random_prime(bits - 1)
        p = 2 * q + 1
        if is_probable_prime(p):
            return p, q


def inverse(a, m):
    """Inverso modular con el algoritmo extendido de Euclides."""
    old_r, r = a, m
    old_s, s = 1, 0
    while r:
        k = old_r // r
        old_r, r = r, old_r - k * r
        old_s, s = s, old_s - k * s
    if old_r != 1:
        raise ValueError(f"{a} no es invertible módulo {m}")
    return old_s % m


def pollard_rho(n, timeout=20.0):
    """Busca un factor no trivial de n. Devuelve None si se agota el tiempo."""
    if n % 2 == 0:
        return 2
    t0 = time.time()
    while time.time() - t0 < timeout:
        x = y = secrets.randbelow(n - 2) + 2
        c = secrets.randbelow(n - 1) + 1
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            if time.time() - t0 > timeout:
                return None
        if d != n:
            return d
    return None


def bsgs(g, h, p, max_m=1 << 24):
    """Logaritmo discreto x tal que g^x = h (mod p) por paso de bebé / paso de gigante."""
    m = math.isqrt(p - 1) + 1
    if m > max_m:
        return None  # inviable en memoria/tiempo
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % p
    factor = pow(g, -m, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return i * m + table[gamma]
        gamma = gamma * factor % p
    return None


# ---------- persistencia sencilla (para que las claves no cambien entre ejecuciones)
def load(name):
    path = os.path.join(DATA, name + ".json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return None


def save(name, obj):
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, name + ".json"), "w") as f:
        json.dump(obj, f, indent=2)
    return obj


def header(t):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


def factorize(n):
    """Factorización completa: división de prueba + Pollard rho. Devuelve {primo: exponente}."""
    out = {}
    for s in range(2, 1000):
        while n % s == 0:
            out[s] = out.get(s, 0) + 1
            n //= s
    stack = [n] if n > 1 else []
    while stack:
        m = stack.pop()
        if is_probable_prime(m):
            out[m] = out.get(m, 0) + 1
        else:
            f = pollard_rho(m, timeout=60)
            stack += [f, m // f]
    return out


def pohlig_hellman(g, h, p):
    """Logaritmo discreto en Z_p^* cuando p-1 solo tiene factores primos pequeños.
    Resuelve x mod q^e en cada subgrupo (con BSGS) y une los resultados con el TCR."""
    n = p - 1
    fac = factorize(n)
    residues = []
    for q, e in fac.items():
        qe = q ** e
        g_q, h_q = pow(g, n // qe, p), pow(h, n // qe, p)
        gamma = pow(g_q, qe // q, p)  # elemento de orden q
        x = 0
        for k in range(e):
            hk = pow(h_q * pow(g_q, -x, p) % p, qe // q ** (k + 1), p)
            dk = bsgs_order(gamma, hk, p, q)
            x += dk * q ** k
        residues.append((x, qe))
    x, mod = 0, 1  # Teorema chino del resto
    for r, m in residues:
        t = (r - x) * pow(mod, -1, m) % m
        x, mod = x + mod * t, mod * m
    return x % n, fac, residues


def bsgs_order(g, h, p, order):
    """BSGS en un subgrupo de orden conocido."""
    m = math.isqrt(order) + 1
    table = {}
    e = 1
    for j in range(m):
        table.setdefault(e, j)
        e = e * g % p
    factor = pow(g, -m, p)
    gamma = h
    for i in range(m):
        if gamma in table:
            return (i * m + table[gamma]) % order
        gamma = gamma * factor % p
    raise ValueError("sin solución")