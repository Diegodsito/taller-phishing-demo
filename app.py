"""
Laboratorio didactico de seguridad web (taller academico, SOLO entorno local).

Contiene DOS vulnerabilidades INTENCIONALES, de familias OWASP distintas e
independientes entre si, marcadas con "# VULN":
  - VULN 1: SSTI  (Server-Side Template Injection)  -> OWASP A03:2021 Injection / CWE-94
  - VULN 2: Open Redirect                            -> OWASP A01:2021 Broken Access Control / CWE-601

TODO lo demas esta endurecido segun OWASP, marcado con "# SEGURO".

Levantar:
    python init_db.py
    python app.py
    -> http://127.0.0.1:5000
"""
import os
import sqlite3

from flask import (
    Flask, request, redirect, render_template,
    render_template_string, session, abort,
)
from werkzeug.security import check_password_hash

app = Flask(__name__)

# SEGURO: la clave de firma de sesion es fija SOLO porque es un laboratorio local y reproducible.
# En produccion vendria de una variable de entorno / gestor de secretos, nunca en el codigo.
app.secret_key = os.environ.get("LAB_SECRET", "clave-solo-para-laboratorio-local-no-produccion")

# SEGURO (cookies): endurecemos la cookie de sesion.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JavaScript NO puede leer la cookie -> mitiga robo de sesion via XSS.
    SESSION_COOKIE_SAMESITE="Lax",  # No se envia en peticiones cross-site de terceros -> mitiga CSRF.
    SESSION_COOKIE_SECURE=False,    # Lab en http://127.0.0.1. En produccion (HTTPS) iria True.
)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Rutas publicas / autenticacion
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def home():
    return render_template(
        "login.html",
        error=None,
        usuario=session.get("usuario"),
        rol=session.get("rol"),
    )


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email", "")
    password = request.form.get("password", "")

    conn = get_db()
    # SEGURO (A03 Injection - SQL): consulta PARAMETRIZADA con "?".
    # El valor del usuario viaja como DATO, nunca como codigo SQL. Por eso payloads
    # clasicos de bypass como  ' OR '1'='1' --  se buscan literalmente y no inician sesion.
    row = conn.execute(
        "SELECT id, email, password_hash, rol FROM usuarios WHERE email = ?",
        (email,),
    ).fetchone()
    conn.close()

    # SEGURO (hashing): se compara la contrasena contra el hash (scrypt) con check_password_hash.
    # Nunca se guarda ni se compara texto plano.
    if row and check_password_hash(row["password_hash"], password):
        session.clear()
        session["usuario"] = row["email"]
        session["rol"] = row["rol"]
        return redirect("/panel")

    # SEGURO: mensaje generico. No revela si el correo existe o si fallo la clave.
    return render_template("login.html", error="Credenciales invalidas.", usuario=None, rol=None), 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/panel")
def panel():
    # SEGURO (A01 Broken Access Control): el control de acceso se hace EN EL SERVIDOR,
    # verificando que exista sesion y que el rol sea 'admin'. Sin eso -> 403.
    if session.get("rol") != "admin":
        abort(403)

    conn = get_db()
    usuarios = conn.execute("SELECT id, email, rol FROM usuarios ORDER BY id").fetchall()
    conn.close()
    return render_template("panel.html", usuario=session.get("usuario"), usuarios=usuarios)


# ---------------------------------------------------------------------------
# VULN 1 - SSTI (Server-Side Template Injection)
# OWASP A03:2021 Injection / CWE-94
# ---------------------------------------------------------------------------
@app.route("/saludo")
def saludo():
    nombre = request.args.get("nombre", "invitado")

    # VULN 1 (SSTI): la entrada del usuario se CONCATENA dentro de una plantilla y el
    # servidor la EVALUA con Jinja2 mediante render_template_string. Como Jinja2 interpreta
    # {{ ... }}, la entrada ?nombre={{7*7}} se evalua en el servidor y devuelve "49".
    # A partir de ahi se puede escalar a ejecucion de comandos (ver README).
    #
    # La forma correcta seria pasar 'nombre' como VARIABLE del contexto y que la plantilla
    # sea fija:   render_template_string("<h2>Hola, {{ nombre }}!</h2>", nombre=nombre)
    # (ver defensa comentada en el README).
    plantilla = """
    <!doctype html><html lang="es"><head><meta charset="utf-8">
    <title>Saludo COMPARAYA</title>
    <style>body{font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 16px}
    a{color:#ee6a17}</style></head><body>
    <h2>Hola, """ + nombre + """!</h2>
    <p>Bienvenido a COMPARAYA. (Endpoint de saludo del laboratorio.)</p>
    <p><a href="/">&larr; Volver al inicio</a></p>
    </body></html>
    """
    return render_template_string(plantilla)


# ---------------------------------------------------------------------------
# VULN 2 - Open Redirect
# OWASP A01:2021 Broken Access Control / CWE-601
# ---------------------------------------------------------------------------
@app.route("/go")
def go():
    destino = request.args.get("url", "/")

    # VULN 2 (Open Redirect): se redirige a CUALQUIER valor recibido en ?url= sin validar
    # que el destino sea interno o este en una lista blanca. Explotable en local apuntando
    # a una URL de prueba propia:  /go?url=http://127.0.0.1:9999/test
    #
    # La defensa (comentada en el README) es permitir SOLO rutas relativas internas o una
    # lista blanca de destinos, rechazando URLs absolutas/externas.
    return redirect(destino)


# ---------------------------------------------------------------------------
# Endurecimiento global
# ---------------------------------------------------------------------------
@app.after_request
def set_security_headers(resp):
    # SEGURO (cabeceras de seguridad):
    # CSP restringe el origen de scripts/estilos/fuentes -> reduce el impacto de inyecciones en cliente.
    # (Se permite 'unsafe-inline' para estilos/scripts porque la plantilla del taller los usa en linea.)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"  # el navegador no "adivina" el tipo MIME.
    resp.headers["X-Frame-Options"] = "DENY"            # no se puede incrustar en un iframe -> anti clickjacking.
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# SEGURO (manejo de errores): respuestas genericas, SIN trazas ni detalles internos.
@app.errorhandler(403)
def err_403(e):
    return render_template("error.html", code=403,
                           msg="Acceso denegado: se requiere sesion de administrador."), 403


@app.errorhandler(404)
def err_404(e):
    return render_template("error.html", code=404, msg="Pagina no encontrada."), 404


@app.errorhandler(500)
def err_500(e):
    # Nunca se filtra el stack trace al usuario (debug esta desactivado).
    return render_template("error.html", code=500, msg="Error interno del servidor."), 500


if __name__ == "__main__":
    # SEGURO: ligado a 127.0.0.1 (no accesible desde la red) y debug DESACTIVADO.
    # debug=True expondria el depurador interactivo de Werkzeug (RCE) y trazas completas.
    app.run(host="127.0.0.1", port=5000, debug=False)
