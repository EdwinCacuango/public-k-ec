"""Destinatarios REALES de mis mensajes: el compañero anterior en los directorios
de Moodle. Solo conozco sus claves públicas."""
DESTINATARIO = {  # RSA Public Key Directory (secciones 1.2 y 4.1)
    "nombre": "SA-ultimo compañero en foro",
    "n": 3250549272254309,
    "e": 5,
}

DESTINATARIO_ELGAMAL = {  # ElGamal Public Key Directory (sección 3.2)
    "nombre": "SA-ultimo compañero en foro",
    "g": 13,
    "p": 2693121009009169,
    "h": 1860151212429259,  # g^a mod p
}