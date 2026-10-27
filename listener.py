"""
"Servidor del atacante" para la DEMO de phishing del taller (SOLO local, 127.0.0.1).

Escucha en el puerto 9999 y cumple dos funciones didacticas:
  1) POST /captura  -> imprime EN CONSOLA las credenciales que el sitio falso exfiltra.
  2) GET  /test     -> pagina de aterrizaje para la demo de Open Redirect (/go?url=...).

Uso:
    python listener.py
Detener con Ctrl+C.

Recurso exclusivamente educativo y local: sirve para VISUALIZAR como un sitio de
phishing roba lo que tecleas. No usar contra personas reales ni fuera del laboratorio.
"""
import datetime
import http.server
import socketserver
import sys
from urllib.parse import parse_qs

PORT = 9999

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


class Handler(http.server.BaseHTTPRequestHandler):
    def _headers(self, code=200, ctype="text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_OPTIONS(self):
        self._headers(204)

    def do_GET(self):
        # Aterrizaje para la demo de Open Redirect (/go?url=http://127.0.0.1:9999/test).
        self._headers(200, "text/html; charset=utf-8")
        self.wfile.write(
            b"<!doctype html><meta charset='utf-8'>"
            b"<h1>DESTINO DE PRUEBA &mdash; 127.0.0.1:9999</h1>"
            b"<p>Si llegaste aqui desde <code>/go?url=...</code>, el Open Redirect funciona: "
            b"la app de confianza te solto en un servidor distinto.</p>"
        )

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        datos = parse_qs(body)
        correo = (datos.get("correo") or ["(vacio)"])[0]
        clave = (datos.get("clave") or ["(vacio)"])[0]
        ts = datetime.datetime.now().strftime("%H:%M:%S")

        print("\n" + "=" * 56)
        print(f"[{ts}]  >>> CREDENCIALES CAPTURADAS POR EL SITIO FALSO <<<")
        print(f"       correo : {correo}")
        print(f"       clave  : {clave}")
        print(f"       desde  : {self.client_address[0]}")
        print("=" * 56)

        self._headers(204)

    def log_message(self, *args):
        pass  # Silenciar el log HTTP por defecto: en pantalla solo se ven las capturas.


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(line_buffering=True)  # cada captura se ve al instante en consola
    except Exception:
        pass
    socketserver.TCPServer.allow_reuse_address = True
    print(f"[*] Listener del atacante (DEMO) escuchando en http://127.0.0.1:{PORT}")
    print("[*] POST /captura -> imprime credenciales   |   GET /test -> aterrizaje open redirect")
    print("[*] Ctrl+C para detener.\n")
    with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Listener detenido.")
