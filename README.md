# Laboratorio de seguridad web — Taller académico (COMPARAYA)

Aplicación **deliberadamente vulnerable** para un taller de ciberseguridad.
Se monta y ataca **solo en entorno local** (`127.0.0.1`), sin exponerse a terceros.
Objetivo pedagógico: **detectar, explotar y remediar** dos vulnerabilidades OWASP
sobre una app ficticia (`COMPARAYA`, marca inventada), con todo lo demás endurecido.

- **2 vulnerabilidades intencionales**, independientes y de familias OWASP distintas,
  marcadas en el código con `# VULN`.
- Todo lo demás **endurecido** (SQL parametrizado, hashing, control por rol, cabeceras,
  cookies, manejo de errores), marcado con `# SEGURO`.
- App ligada a `127.0.0.1`, **sin modo debug**.

> ⚠️ Uso exclusivamente educativo y en local. La marca es ficticia; **no** imita a
> ninguna empresa real. El *open redirect* se incluye como **objeto de estudio** para
> detectarlo y corregirlo, **no** como señuelo de phishing.

---

## 1. Cómo levantar la app

Requisitos: Python 3.10+ (probado con 3.14).

```bash
cd taller-phishing-demo

# 1) entorno virtual (recomendado)
python -m venv .venv
.venv\Scripts\activate          # Windows (PowerShell/CMD)
# source .venv/bin/activate     # Linux/macOS

# 2) dependencias
pip install -r requirements.txt

# 3) crear la base de datos (usuarios con contraseña hasheada)
python init_db.py

# 4) arrancar (queda en http://127.0.0.1:5000)
python app.py
```

Credenciales de ejemplo que crea `init_db.py`:

| Correo | Contraseña | Rol |
|---|---|---|
| `admin@comparaya.cl` | `Admin.Taller.2025` | admin |
| `ana@comparaya.cl` | `clave-de-ana` | usuario |

Estructura:

```
taller-phishing-demo/
├─ app.py            # servidor Flask (rutas, vulns y defensas)
├─ init_db.py        # crea lab.db con contraseñas hasheadas
├─ requirements.txt  # Flask, Werkzeug
├─ templates/
│  ├─ login.html     # login funcional (diseño COMPARAYA) + índice de endpoints
│  ├─ panel.html     # panel admin (protegido por rol)
│  └─ error.html     # errores genéricos, sin trazas
├─ index.html        # demo estática original de concientización (independiente, opcional)
└─ README.md
```

---

## 2. Las dos vulnerabilidades

### 🔴 VULN 1 — SSTI (Server-Side Template Injection)

**OWASP A03:2021 Injection · CWE-94**

- **Dónde está:** [app.py](app.py) → ruta `/saludo` (función `saludo`, comentario `# VULN 1`).
  La entrada `nombre` se **concatena** en una plantilla que el servidor **evalúa** con
  Jinja2 vía `render_template_string(...)`. Al interpretar `{{ ... }}`, cualquier
  expresión del usuario se ejecuta en el servidor.

- **Cómo detectarla:**
  1. Inyecta una operación matemática y observa si el servidor la **calcula**:
     ```
     http://127.0.0.1:5000/saludo?nombre={{7*7}}
     ```
     Si la página responde `Hola, 49!` (y no `Hola, {{7*7}}!`), hay evaluación de plantilla
     del lado servidor → **SSTI confirmada**.
  2. Confirma el motor con un sondeo típico de Jinja2: `{{7*'7'}}` → `7777777`.

- **Cómo explotarla (payload exacto):**
  - Prueba básica (devuelve `49`):
    ```
    /saludo?nombre={{7*7}}
    ```
  - Escalada a **ejecución de comandos (RCE)**. Jinja2 corre sobre Python; se parte de un
    objeto accesible en la plantilla y se llega a `os.popen`:
    ```
    /saludo?nombre={{ cycler.__init__.__globals__.os.popen('whoami').read() }}
    ```
    En consola/navegador verás el nombre de usuario del sistema devuelto por `whoami`,
    demostrando que el payload se ejecutó en el servidor (sustituyendo `whoami` por otro
    comando se ejecutaría igual). *Verificado en este laboratorio.*
  - Con `curl` (URL-encoding del payload):
    ```bash
    curl -s "http://127.0.0.1:5000/saludo" --get \
         --data-urlencode "nombre={{ cycler.__init__.__globals__.os.popen('whoami').read() }}"
    ```

- **Cómo corregirla:** nunca construyas la plantilla concatenando entrada del usuario.
  Pásala como **variable de contexto** a una plantilla fija (así el dato se escapa y no se
  evalúa), o usa `render_template` con archivos `.html`:
  ```python
  # CORRECTO: 'nombre' es un dato, no parte de la plantilla -> {{7*7}} se muestra literal.
  return render_template_string("<h2>Hola, {{ nombre }}!</h2>", nombre=nombre)
  ```
  Además, valida/limita la entrada (longitud, caracteres) y **nunca** uses
  `render_template_string` con cadenas que incluyan datos no confiables.

---

### 🔴 VULN 2 — Open Redirect

**OWASP A01:2021 Broken Access Control · CWE-601**

- **Dónde está:** [app.py](app.py) → ruta `/go` (función `go`, comentario `# VULN 2`).
  Hace `redirect(request.args.get('url'))` devolviendo el valor recibido **sin validar**
  que el destino sea interno o esté en una lista blanca.

- **Cómo detectarla:** busca endpoints de redirección que tomen una URL/ruta de destino
  desde la query (`?url=`, `?next=`, `?return=`). Prueba un destino **absoluto** distinto
  al propio dominio y observa si el servidor responde `302` con un `Location` hacia ese
  destino externo.

- **Cómo explotarla (payload exacto, solo local):**
  ```
  http://127.0.0.1:5000/go?url=http://127.0.0.1:9999/test
  ```
  El servidor responde `302 Found` con `Location: http://127.0.0.1:9999/test`, enviando al
  usuario a un destino **ajeno a la app**. *Verificado:* con un servidor de prueba propio
  escuchando en `127.0.0.1:9999`, la redirección aterriza en él.
  ```bash
  curl -s -i "http://127.0.0.1:5000/go?url=http://127.0.0.1:9999/test" | grep -i location
  # Location: http://127.0.0.1:9999/test
  ```

- **Por qué es peligroso:** un enlace que empieza con un dominio **de confianza**
  (`https://sitio-legitimo/go?url=...`) termina llevando a un destino controlado por el
  atacante. La víctima ve el dominio conocido y confía. En **campañas de phishing** esto se
  abusa para que el enlace *herede la reputación* del dominio legítimo (pasa filtros, se ve
  creíble) antes de saltar a una página fraudulenta. También sirve para robar tokens que
  viajan en la URL o para cadenas de redirección. *(En este laboratorio solo apuntamos a una
  URL de prueba local; no se encadena hacia sitios externos ni se usa como señuelo.)*

- **Cómo corregirla:** nunca redirijas a un valor arbitrario. Opciones:
  1. **Solo rutas relativas internas:** rechaza URLs absolutas; acepta solo destinos que
     empiecen por `/` y no por `//` (que el navegador interpreta como host externo).
     ```python
     from urllib.parse import urlparse
     def destino_seguro(url):
         # SEGURO: solo ruta interna; sin esquema, sin host, sin "//".
         p = urlparse(url)
         return (not p.scheme) and (not p.netloc) and url.startswith('/') and not url.startswith('//')
     destino = request.args.get('url', '/')
     return redirect(destino if destino_seguro(destino) else '/')
     ```
  2. **Lista blanca** de destinos permitidos (mapa `clave -> ruta fija`) y recibir solo la
     clave, nunca la URL completa.

---

## 3. Defensas activas (lo que quedó cerrado)

Cada una marcada con `# SEGURO` en [app.py](app.py) / [init_db.py](init_db.py):

- **SQL parametrizado** (`A03`): el login usa consultas con `?`; la entrada viaja como dato.
  `' OR '1'='1' --` **no** inicia sesión.
- **Hashing de contraseñas:** se guarda solo el hash **scrypt** (Werkzeug), nunca texto plano.
- **Control de acceso por rol** (`A01`): `/panel` verifica `rol == 'admin'` en el servidor;
  sin sesión válida responde **403**.
- **Cabeceras de seguridad:** `Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy`.
- **Manejo de errores:** handlers 404/500 genéricos, **sin** trazas; `debug=False`.
- **Cookies:** sesión con `HttpOnly` y `SameSite=Lax` (firmada por Flask).
- **Bind local:** `host="127.0.0.1"` (no accesible desde la red).

---

## 4. Tabla resumen — clasificación OWASP

| # | Vulnerabilidad | Tipo | OWASP Top 10 (2021) | CWE | Endpoint | Payload de prueba |
|---|---|---|---|---|---|---|
| 1 | SSTI | Intencional (`# VULN`) | **A03:2021 – Injection** | CWE-94 | `/saludo?nombre=` | `{{7*7}}` → `49` |
| 2 | Open Redirect | Intencional (`# VULN`) | **A01:2021 – Broken Access Control** | CWE-601 | `/go?url=` | `http://127.0.0.1:9999/test` |
| — | Inyección SQL | Mitigada (`# SEGURO`) | A03:2021 – Injection | CWE-89 | `/login` | consultas parametrizadas |
| — | Credenciales en texto plano | Mitigada (`# SEGURO`) | A02:2021 – Cryptographic Failures | CWE-256 | `init_db.py` | hashing scrypt |
| — | Acceso sin autorización | Mitigada (`# SEGURO`) | A01:2021 – Broken Access Control | CWE-862 | `/panel` | rol admin → 403 |
| — | Falta de cabeceras | Mitigada (`# SEGURO`) | A05:2021 – Security Misconfiguration | CWE-693 | global | CSP, XFO, nosniff |
| — | Fuga por errores/debug | Mitigada (`# SEGURO`) | A05:2021 – Security Misconfiguration | CWE-209 | global | `debug=False`, 404/500 genéricos |

---

## 5. Evidencia de la prueba end-to-end

Probado con el servidor en `127.0.0.1:5000` y un destino de prueba en `127.0.0.1:9999`.

**Vulnerabilidades (funcionan):**

```
VULN 1 · SSTI   /saludo?nombre={{7*7}}                 → <h2>Hola, 49!</h2>
VULN 1 · RCE    /saludo?nombre={{...os.popen('whoami')...}} → <h2>Hola, <usuario-del-sistema>
VULN 2 · Redir  /go?url=http://127.0.0.1:9999/test     → HTTP/1.1 302 FOUND
                                                          Location: http://127.0.0.1:9999/test
```

**Defensas (cerradas):**

```
Login admin correcto                 → 302 /panel  · Set-Cookie: session=...; HttpOnly; SameSite=Lax
Bypass SQL  ' OR '1'='1' --          → HTTP 401  (no inicia sesión)
Contraseña incorrecta                → HTTP 401
/panel sin sesión                    → HTTP 403
/panel con sesión admin              → HTTP 200
/panel con sesión rol 'usuario'      → HTTP 403
Cabeceras en /                       → Content-Security-Policy / X-Content-Type-Options: nosniff
                                       X-Frame-Options: DENY / Referrer-Policy: no-referrer
/ruta-inexistente                    → HTTP 404 (página genérica, sin traza)
BD: hash de admin                    → scrypt:32768:8:1$...  (no hay texto plano)
```

> El archivo `index.html` es la **demo estática original** de concientización de phishing
> (independiente del backend). Puede abrirse aparte en el navegador; no forma parte de la
> app Flask del laboratorio.
