"""Paso 0: creación del compañero ficticio (pública y privada)."""
from cripto import ficticio
from cripto.nt import header

f = ficticio.get()
r, e, d = f["rsa"], f["elgamal"], f["dh"]
header(f"0. {f['nombre']}: claves generadas")
print("RSA (se usa en las secciones 1 y 4):")
print(f"  p = {r['p']}, q = {r['q']}")
print(f"  PÚBLICA  n = {r['n']}, e = {r['e']}")
print(f"  PRIVADA  d = {r['d']}")
print("ElGamal (sección 3):")
print(f"  PÚBLICA  p = {e['p']}, g = {e['g']}, h = {e['h']}")
print(f"  PRIVADA  x = {e['x']}")
print("Diffie-Hellman (sección 2, p = 7883, g = 2):")
print(f"  PÚBLICO  B = {d['B']}")
print(f"  SECRETO  b = {d['b']}")
