## Requisitos e instalación

Requiere Python 3.10 o superior.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

La aritmética modular usa los enteros de precisión arbitraria de Python. AES-256 y SHA-256 se calculan con `pycryptodome` y `hashlib`.

## Ejecución

Todos los scripts se ejecutan desde la raíz del proyecto:

```bash
python ej0_ficticio.py               # claves del compañero ficticio
python ej1_rsa.py                    # 1. RSA + AES-256
python ej2_dh.py --teacher-B 7765    # 2. Diffie-Hellman (7765 = g^b publicado por la profesora)
python ej3_elgamal.py                # 3. ElGamal
python ej4_firma.py                  # 4. Firmas digitales
```

Cada script imprime los pasos de su sección con los valores intermedios y las comprobaciones de que cada operación es correcta.

## Estructura

```
├── cripto/
│   ├── nt.py            # teoría de números
│   ├── rsa.py           # RSA de libro de texto
│   ├── elgamal.py       # ElGamal
│   ├── destinatario.py  # claves públicas reales tomadas de los directorios
│   └── ficticio.py      # compañero ficticio
├── ej0_ficticio.py
├── ej1_rsa.py
├── ej2_dh.py
├── ej3_elgamal.py
├── ej4_firma.py
├── data/                # claves y valores generados (se crea en la primera ejecución)
└── requirements.txt
```

**`cripto/nt.py`** implementa las funciones de teoría de números que usan todos los ejercicios:

- test de primalidad de Miller-Rabin, generación de primos y de primos seguros (p = 2q + 1);
- inverso modular por el algoritmo extendido de Euclides;
- factorización con el método rho de Pollard;
- logaritmo discreto con baby-step giant-step y Pohlig-Hellman (con el teorema chino del resto).

**`cripto/rsa.py`** y **`cripto/elgamal.py`** contienen la generación de claves, el cifrado y el descifrado de cada esquema.

## Contenido de cada sección

| Script | Contenido |
|---|---|
| `ej1_rsa.py` | 1.1 generación de claves RSA · 1.2 cifrado para el compañero anterior · 1.3 obtención de su clave privada por factorización (rho de Pollard) · 1.4 descifrado de un mensaje recibido · 1.5 SHA-256 del mensaje · 1.6 cifrado AES-256 en modo CBC |
| `ej2_dh.py` | 2.1 valor secreto y valor público · 2.2 clave compartida con la profesora 
| `ej3_elgamal.py` | 3.1 generación de claves sobre un primo seguro · 3.2 cifrado para el compañero anterior · 3.3 obtención de su clave privada con Pohlig-Hellman · 3.4 descifrado de un mensaje recibido |
| `ej4_firma.py` | 4.1 cifrado y firma RSA del resumen h(m) = m mod 1000003 · 4.2 descifrado y verificación de un mensaje firmado |

## Interlocutores

- **Destinatario real (`cripto/destinatario.py`).** Los mensajes RSA (1.2, 4.1) y ElGamal (3.2) se cifran para el compañero en la posición anterior de los directorios. Solo se conocen sus claves públicas.
- **Compañero ficticio (`cripto/ficticio.py`).** Cuando realicé la práctica no había en los canales mensajes dirigidos a mí, así que un compañero ficticio, con claves generadas con las mismas funciones, hace de remitente de los mensajes que descifro (1.4, 3.4, 4.2).

## Reproducibilidad

La carpeta `data/` no se incluye en el repositorio: se crea en la primera ejecución, con las claves y valores aleatorios que genere esa ejecución. Por eso los números no coincidirán con los del informe, aunque todas las comprobaciones deben dar resultado correcto. Las ejecuciones posteriores reutilizan esos valores y reproducen los mismos resultados. Si se borra `data/`, se generan claves nuevas.

## Equivalencias con Maxima

| Maxima | Python |
|---|---|
| `power_mod(a, b, n)` | `pow(a, b, n)` |
| `inv_mod(a, n)` | `inverse(a, n)` |
| `primep(n)` | `is_probable_prime(n)` |
| `ifactors(n)` | `pollard_rho(n)` / `factorize(n)` |
| `zn_log(h, g, p)` | `bsgs(g, h, p)` / `pohlig_hellman(g, h, p)` |