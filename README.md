# Taller de Phishing — Demo de concientización

Página **ficticia** con fines educativos para un taller de ciberseguridad.
Imita la *estructura* de un comparador de precios (barra de búsqueda, menú,
login con correo/contraseña y botones sociales), pero:

- Usa una **marca inventada** (`COMPARAYA`), **no** una empresa real.
- **No captura, guarda ni envía datos** a ningún servidor. Todo ocurre en el navegador.
- Al "iniciar sesión" muestra una pantalla de **revelado** que explica el engaño.
- Incluye un botón **"Revelar las señales de phishing"** que marca las 5 pistas sobre la página.

> Objetivo didáctico: mostrar lo convincente que puede verse un sitio falso y
> enseñar a reconocer las señales de alerta. No debe usarse para engañar a
> personas reales ni para capturar credenciales ajenas.

## Cómo abrirlo

1. Abre la carpeta `taller-phishing-demo` en VS Code.
2. Haz doble clic en `index.html` para abrirlo en tu navegador, **o**
3. En VS Code instala la extensión **"Live Server"** (Ritwick Dey), haz clic
   derecho sobre `index.html` → **"Open with Live Server"**.

No necesita instalar nada más: es HTML/CSS/JS puro (las fuentes se cargan por internet).

## Cómo presentarlo en el taller

1. **Muestra la página tal cual.** Pregunta a la audiencia: *¿se ve confiable?*
2. **Haz que "caigan":** escribe un correo y una clave de ejemplo y pulsa
   *INICIAR SESIÓN*. Aparece el mensaje "Acabas de caer en la simulación".
3. **Revela las pistas:** baja al panel y pulsa
   *"Revelar las señales de phishing"* para resaltar las 5 señales numeradas.
4. **Explica cada señal** usando las tarjetas del panel.

## Las 5 señales incluidas

| # | Señal | Qué enseñar |
|---|-------|-------------|
| 1 | URL engañosa | El dominio real está al final: `cl-acceso-cuenta.net`, no `comparaya`. |
| 2 | Sin HTTPS | Dice "No seguro" y usa `http://`. |
| 3 | Urgencia / amenaza | "Tu cuenta será suspendida en 24 horas". |
| 4 | Pide credenciales tras un enlace | Llegaste por correo y ya te piden clave. |
| 5 | Botones sociales falsos | Imitan Google/Facebook para robar más accesos. |

## Personalizar

- **Marca / colores:** edita los tokens `--accent`, `--bg`, etc. al inicio del `<style>`.
- **URL falsa de ejemplo:** busca `cl-acceso-cuenta.net` en el HTML.
- **Textos de la lección:** están en las secciones `.learn-card` y `#reveal`.
