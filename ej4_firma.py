"""Sección 4: cifrado + firma RSA del resumen h(m) = m mod 1000003.
Envío al mismo compañero REAL de la 1.2; recibo del compañero ficticio.

Uso:  python ej4_firma.py [--msg 1234]
"""
import argparse
import secrets

from cripto import ficticio, rsa
from cripto.destinatario import DESTINATARIO
from cripto.nt import header, inverse, load, pollard_rho, save

H_MOD = 1000003  # 10^6 + 3


def digest(m):
    return m % H_MOD


ap = argparse.ArgumentParser()
ap.add_argument("--msg", type=int)
args = ap.parse_args()

me = rsa.get_or_create("rsa_mine", 32)
fic = ficticio.get()
peer, NOM = fic["rsa"], fic["nombre"]    # quien ME envía (ficticio)
dest, DEST = DESTINATARIO, DESTINATARIO["nombre"]  # a quien YO envío (real)

header(f"4.1  Cifrado para {DEST} + firma del resumen con MI privada")
print(f"Clave pública de {DEST} (la misma de 1.2): n_B = {dest['n']}, e_B = {dest['e']}")
st = load("firma_state") or {}
m = args.msg if args.msg is not None else st.get("m") or secrets.randbelow(dest["n"] - 2) + 2
assert m < dest["n"], "el mensaje debe ser menor que n_B"
st["m"] = m
save("firma_state", st)
c = rsa.encrypt(m, dest["e"], dest["n"])
h = digest(m)
s = pow(h, me["d"], me["n"])
print(f"m = {m}")
print(f"Cifrado:  c = m^e_B mod n_B = {c}")
print(f"Resumen:  h = m mod {H_MOD} = {h}")
print(f"Firma:    s = h^d_A mod n_A = {s}")
print(f"\nComprobación de lo que hará {DEST} (su d se obtiene factorizando n_B, como en 1.3):")
f = pollard_rho(dest["n"])
d_b = inverse(dest["e"], (f - 1) * (dest["n"] // f - 1))
m_b = rsa.decrypt(c, d_b, dest["n"])
print(f"  descifra: m = c^d_B mod n_B = {m_b}")
print(f"  h(m) = {digest(m_b)};  s^e_A mod n_A (con MI pública) = {pow(s, me['e'], me['n'])}")
print(f"  => firma {'CORRECTA' if digest(m_b) == pow(s, me['e'], me['n']) else 'INCORRECTA'}")


header(f"4.2  {NOM} me envía un mensaje cifrado y firmado")
st = load("firma_state")
if "m_in" not in st:
    st["m_in"] = secrets.randbelow(me["n"] - 2) + 2
    save("firma_state", st)
c_in = rsa.encrypt(st["m_in"], me["e"], me["n"])
s_in = pow(digest(st["m_in"]), peer["d"], peer["n"])
print(f"{NOM} cifra con MI pública y firma el resumen con SU privada d_B.")
print(f"c recibido = {c_in}\ns recibida = {s_in}")
m_in = rsa.decrypt(c_in, me["d"], me["n"])
h_calc = digest(m_in)
h_sig = pow(s_in, peer["e"], peer["n"])
print(f"1) Descifro con MI privada: m = c^d_A mod n_A = {m_in}")
print(f"2) Calculo el resumen:      h(m) = m mod {H_MOD} = {h_calc}")
print(f"3) Verifico con SU pública: s^e_B mod n_B = {h_sig}")
print(f"=> Firma {'CORRECTA' if h_calc == h_sig else 'INCORRECTA'}; mensaje original = {m_in}")
