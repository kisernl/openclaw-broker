"""
ngrok daemon — opens a TCP tunnel to the local mitmproxy port and writes
the public URL to run/proxy_url.txt so the sandbox launcher can read it.

This runs as a background process (started by start.py). It stays alive
for the duration of the session. When it exits, the tunnel closes and
the E2B sandbox loses its proxy route (requests fail closed).

Not used when PROXY_URL is set in the environment.
"""

import os
import signal
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
RUN_DIR = os.path.join(ROOT, "run")
PROXY_URL_FILE = os.path.join(RUN_DIR, "proxy_url.txt")

PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
NGROK_AUTHTOKEN = os.environ.get("NGROK_AUTHTOKEN", "")


def _write_proxy_url(url: str) -> None:
    os.makedirs(RUN_DIR, exist_ok=True)
    with open(PROXY_URL_FILE, "w") as f:
        f.write(url)
    print(f"[ngrok] Proxy URL written: {url}")


def _clear_proxy_url() -> None:
    if os.path.exists(PROXY_URL_FILE):
        os.remove(PROXY_URL_FILE)


def main() -> None:
    from pyngrok import ngrok, conf

    if NGROK_AUTHTOKEN:
        conf.get_default().auth_token = NGROK_AUTHTOKEN

    print(f"[ngrok] Opening TCP tunnel to localhost:{PROXY_PORT}...")
    # TCP tunnel is required — mitmproxy speaks the HTTP CONNECT proxy protocol,
    # not plain HTTP. Using "http" here would break the proxy handshake.
    tunnel = ngrok.connect(PROXY_PORT, "tcp")
    proxy_url = tunnel.public_url

    # ngrok TCP URLs look like tcp://0.tcp.ngrok.io:PORT
    # Convert to http:// so it can be used as HTTP_PROXY / HTTPS_PROXY
    if proxy_url.startswith("tcp://"):
        proxy_url = "http://" + proxy_url[len("tcp://"):]

    _write_proxy_url(proxy_url)

    def _shutdown(signum, frame):
        print("[ngrok] Shutting down tunnel...")
        ngrok.kill()
        _clear_proxy_url()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print("[ngrok] Tunnel active. Waiting...")
    while True:
        time.sleep(60)


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv(os.path.join(ROOT, ".env"))
    main()
