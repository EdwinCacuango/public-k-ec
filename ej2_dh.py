"""Sección 2: Diffie-Hellman con p = 7883, g = 2.

Uso:  python ej2_dh.py --teacher-B 7765
"""
import argparse
import secrets

from cripto.nt import bsgs, header, load, save

P, G = 7883, 2
ap = argparse.ArgumentParser()
ap.add_argument("--teacher-B", type=int, required=True, help="g^b publicado por la profesora")
args = ap.parse_args()

header("2.1  Mi valor secreto y mi valor público")
st = load("dh_state") or save("dh_state", {"a": secrets.randbelow(P - 3) + 2})
a = st["a"]
A = pow(G, a, P)
print(f"a (secreto) = {a}")
print(f"A = g^a mod p = 2^{a} mod {P} = {A}")


header("2.2  Clave compartida con la profesora")
B = args.teacher_B
K = pow(B, a, P)
print(f"Valor público de la profesora: B = {B}")
print(f"K = B^a mod p = {B}^{a} mod {P} = {K}")
