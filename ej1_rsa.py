"""Sección 1: RSA + AES-256.
Envío a un compañero REAL (cripto/destinatario.py); recibo del compañero ficticio.

Uso:
  python ej1_rsa.py
  python ej1_rsa.py --msg 1234     # elegir el número que se envía
"""
import argparse
import hashlib
import secrets
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from cripto import ficticio, rsa
from cripto.destinatario import DESTINATARIO
from cripto.nt import header, inverse, load, pollard_rho, save

ap = argparse.ArgumentParser()
ap.add_argument("--bits", type=int, default=32, help="tamaño de MI módulo n (32 bits ~ 10 dígitos)")
ap.add_argument("--msg", type=int, help="mensaje numérico a enviar")
ap.add_argument("--aes-text", default="Mensaje secreto del portfolio II de criptografia")
args = ap.parse_args()

fic = ficticio.get()
NOM = fic["nombre"]                       # quien ME envía (ficticio)
peer = DESTINATARIO                       # a quien YO envío (real)
DEST = peer["nombre"]

# ---------------------------------------------------------------- 1.1
header("1.1  Generación de MI par de claves RSA")
me = rsa.get_or_create("rsa_mine", args.bits)
print(f"p   = {me['p']}")
print(f"q   = {me['q']}")
print(f"n   = p*q = {me['n']}")
print(f"phi = (p-1)(q-1) = {me['phi']}")
print(f"e   = {me['e']}   (mcd(e, phi) = 1)")
print(f"d   = e^-1 mod phi = {me['d']}")
print(f"Comprobación e*d mod phi = {me['e'] * me['d'] % me['phi']}")

# ---------------------------------------------------------------- 1.2
header(f"1.2  Cifrado con la clave pública de {DEST}")
print(f"Clave pública de {DEST} (RSA Public Key Directory): n_B = {peer['n']}, e_B = {peer['e']}")
st = load("rsa_state") or {}
m = args.msg if args.msg is not None else st.get("m") or secrets.randbelow(peer["n"] - 2) + 2
assert m < peer["n"], "el mensaje debe ser menor que n_B"
st["m"] = m
save("rsa_state", st)
c = rsa.encrypt(m, peer["e"], peer["n"])
print(f"m = {m}")
print(f"c = m^e_B mod n_B = {m}^{peer['e']} mod {peer['n']} = {c}")

# ---------------------------------------------------------------- 1.3
header("1.3  ¿Se puede obtener la clave privada de esa clave pública?")
bits = peer["n"].bit_length()
print(f"n_B tiene {bits} bits ({len(str(peer['n']))} dígitos). Solo conozco (n_B, e_B).")
t0 = time.time()
f = pollard_rho(peer["n"], timeout=20) if bits <= 160 else None
if f:
    p_, q_ = f, peer["n"] // f
    phi_ = (p_ - 1) * (q_ - 1)
    d_ = inverse(peer["e"], phi_)
    print(f"Factorización (Pollard rho, {time.time() - t0:.3f} s): n_B = {p_} * {q_}")
    print(f"phi_B = {phi_}\nd_B obtenida = e_B^-1 mod phi_B = {d_}")
    print(f"Comprobación e_B * d_B mod phi_B = {peer['e'] * d_ % phi_}")
    print(f"Descifro mi propio criptograma con la d obtenida: {pow(c, d_, peer['n'])}  (m = {m})")
    print("=> SÍ: n es tan pequeño que se factoriza en milisegundos, y con p y q se calcula d.")
else:
    print("=> NO en la práctica: obtener d exige factorizar n.")

# ---------------------------------------------------------------- 1.4
header(f"1.4  {NOM} me envía un mensaje cifrado con MI clave pública")
st = load("rsa_state")
if "m_in" not in st:
    st["m_in"] = secrets.randbelow(me["n"] - 2) + 2
    save("rsa_state", st)
c_in = rsa.encrypt(st["m_in"], me["e"], me["n"])
print(f"{NOM} elige m = {st['m_in']} y calcula c = m^e mod n con (n, e) míos.")
print(f"c recibido = {c_in}")
m_in = rsa.decrypt(c_in, me["d"], me["n"])
print(f"Descifro con MI privada: m = c^d mod n = {m_in}  -> {'correcto' if m_in == st['m_in'] else 'ERROR'}")

# ---------------------------------------------------------------- 1.5
header("1.5  SHA-256 del mensaje descifrado (clave para AES)")
key_text = str(m_in)
key = hashlib.sha256(key_text.encode()).digest()
print(f"Texto hasheado: '{key_text}'")
print(f"SHA-256 = {key.hex()}")

# ---------------------------------------------------------------- 1.6
header("1.6  Cifrado AES-256 en modo CBC")
st = load("rsa_state")
if "iv" not in st:
    st["iv"] = secrets.token_hex(16)
    save("rsa_state", st)
iv = bytes.fromhex(st["iv"])
ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(args.aes_text.encode(), 16))
print(f"Texto claro : {args.aes_text}")
print(f"Clave (hex) : {key.hex()}")
print(f"IV (hex)    : {iv.hex()}")
print(f"Cifrado(hex): {ct.hex()}")
key_fic = hashlib.sha256(str(st["m_in"]).encode()).digest()  # él conoce el número que me envió
dec = unpad(AES.new(key_fic, AES.MODE_CBC, iv).decrypt(ct), 16).decode()
print(f"\nComprobación: {NOM} deriva la misma clave de SU número y descifra: '{dec}'")

