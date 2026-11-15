"""Compañero ficticio: no hay compañero anterior, así que se crea uno con
sus propias claves. Su par RSA se reutiliza en las secciones 1 y 4; ElGamal
y Diffie-Hellman son esquemas distintos y necesitan claves propias."""
import secrets

from . import elgamal, rsa
from .nt import load, save

NOMBRE = "Compañero Ficticio"
DH_P, DH_G = 7883, 2


def get():
    f = load("ficticio")
    if f is None:
        b = secrets.randbelow(DH_P - 3) + 2
        f = save("ficticio", {
            "nombre": NOMBRE,
            "rsa": rsa.keygen(32),          # ~10 dígitos, como las de clase
            "elgamal": elgamal.keygen(32),
            "dh": {"b": b, "B": pow(DH_G, b, DH_P)},
        })
    return f
