"""
Crea la base de datos del laboratorio (lab.db) con usuarios de ejemplo.
Ejecutar una vez antes de levantar la app:  python init_db.py

Las contrasenas se guardan SOLO como hash (pbkdf2-sha256), nunca en texto plano.
"""
import os
import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab.db")

# Usuarios de ejemplo: (email, contrasena_en_claro_SOLO_para_el_taller, rol)
USUARIOS = [
    ("admin@comparaya.cl", "Admin.Taller.2025", "admin"),
    ("ana@comparaya.cl",   "clave-de-ana",       "usuario"),
]


def init():
    # Reinicia la BD en cada ejecucion para que el laboratorio sea reproducible.
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE usuarios (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            rol           TEXT NOT NULL DEFAULT 'usuario'
        )
        """
    )

    for email, password, rol in USUARIOS:
        # SEGURO (hashing): se almacena generate_password_hash(...) -> scrypt con salt (hash por defecto de Werkzeug).
        # Nunca se guarda ni se compara la contrasena en claro.
        conn.execute(
            "INSERT INTO usuarios (email, password_hash, rol) VALUES (?, ?, ?)",
            (email, generate_password_hash(password), rol),
        )

    conn.commit()
    conn.close()

    print("Base de datos creada en:", DB_PATH)
    print("Credenciales del taller:")
    for email, password, rol in USUARIOS:
        print(f"  - {email} / {password}   (rol: {rol})")


if __name__ == "__main__":
    init()
