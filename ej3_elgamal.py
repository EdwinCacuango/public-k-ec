"""Sección 3: ElGamal.
Envío al compañero REAL anterior (cripto/destinatario.py); recibo del compañero ficticio.

Uso:  python ej3_elgamal.py [--msg 1234]
"""
import argparse
import secrets
import time

from cripto import elgamal, ficticio
from cripto.destinatario import DESTINATARIO_ELGAMAL
from cripto.nt import header, load, pohlig_hellman, save

ap = argparse.ArgumentParser()
ap.add_argument("--bits", type=int, default=32)
ap.add_argument("--msg", type=int)
args = ap.parse_args()
fic = ficticio.get()
NOM = fic["nombre"]                                       # quien ME envía
peer, DEST = DESTINATARIO_ELGAMAL, DESTINATARIO_ELGAMAL["nombre"]  # a quien YO envío

header("3.1  Generación de MI par de claves ElGamal")
me = load("elgamal_mine") or save("elgamal_mine", elgamal.keygen(args.bits))
print(f"p = {me['p']}  (primo seguro: p = 2q+1, q = {me['q']})")
print(f"g = {me['g']}  (generador: g^2 != 1 y g^q != 1 mod p)")
print(f"x (privada) = {me['x']}")
print(f"h = g^x mod p = {me['h']}")


header(f"3.2  Cifrado para {DEST}")
print(f"Clave pública de {DEST}: g = {peer['g']}, p = {peer['p']}, g^a mod p = {peer['h']}")
st = load("elgamal_state") or {}
m = args.msg if args.msg is not None else st.get("m") or secrets.randbelow(peer["p"] - 2) + 2
assert 0 < m < peer["p"], "el mensaje debe ser menor que p_B"
st["m"] = m
if "k" not in st:
    st["k"] = secrets.randbelow(peer["p"] - 3) + 2
save("elgamal_state", st)
k = st["k"]
c1 = pow(peer["g"], k, peer["p"])
c2 = m * pow(peer["h"], k, peer["p"]) % peer["p"]
print(f"m = {m},  k (efímero, aleatorio) = {k}")
print(f"C1 = g^k mod p = {c1}")
print(f"C2 = m * (g^a)^k mod p = {c2}")

header(f"3.3  ¿Se puede obtener la clave privada de {DEST}?")
bits = peer["p"].bit_length()
print(f"p_B tiene {bits} bits. Hay que resolver g^a = h (mod p) usando solo datos públicos.")
print(f"BSGS directo necesitaría ~sqrt(p) = {int(peer['p'] ** 0.5):,} pasos: costoso.")
t0 = time.time()
a_b, fac, res = pohlig_hellman(peer["g"], peer["h"], peer["p"])
print(f"Pero p-1 = {' * '.join(f'{q}^{e}' if e > 1 else str(q) for q, e in fac.items())}"
      " solo tiene factores primos pequeños.")
print("Pohlig-Hellman: se resuelve a mod q^e en cada subgrupo y se combinan con el TCR:")
for r, mod in res:
    print(f"  a ≡ {r} (mod {mod})")
print(f"Tiempo: {time.time() - t0:.3f} s  ->  a_B = {a_b}")
print(f"Comprobación g^a mod p = {pow(peer['g'], a_b, peer['p'])}  (h = {peer['h']})")
print(f"Con a_B descifro mi propio mensaje: {elgamal.decrypt(c1, c2, a_b, peer['p'])}  (m = {m})")
print("=> SÍ: p es pequeño y p-1 es 'suave' (factores pequeños), así que el logaritmo discreto")
print("   se resuelve en segundos. Con p de 2048 bits y p-1 = 2q (q primo) sería inviable.")

header(f"3.4  {NOM} me envía un mensaje cifrado con MI clave pública")
st = load("elgamal_state")
if "m_in" not in st:
    st["m_in"] = secrets.randbelow(me["p"] - 2) + 2
    save("elgamal_state", st)
_, c1_in, c2_in = elgamal.encrypt(st["m_in"], me["p"], me["g"], me["h"])
print(f"{NOM} elige m = {st['m_in']}")
print(f"c1 = {c1_in}\nc2 = {c2_in}")
s = pow(c1_in, me["x"], me["p"])
m_in = elgamal.decrypt(c1_in, c2_in, me["x"], me["p"])
print(f"s = c1^x mod p = {s}")
print(f"m = c2 * s^-1 mod p = {m_in}  -> {'correcto' if m_in == st['m_in'] else 'ERROR'}")