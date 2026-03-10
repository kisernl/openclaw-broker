#!/usr/bin/env python3
"""
OpenClaw credential broker — startup script.

Sequence:
  1. Validate environment
  2. Create run/ and certs/ directories
  3. Start mitmproxy daemon (generates CA cert on first run)
  4. Wait for mitmproxy to be healthy and cert to be generated
  5. Start Flask approval UI daemon
  6. Wait for Flask to be healthy
  7. Start ngrok daemon (unless PROXY_URL is already set)
  8. Wait for proxy URL to be available
  9. Launch the E2B sandbox with OpenClaw
 10. Print the gateway URL

Daemons run as background processes detached from this terminal.
Close this terminal — they keep running. Use stop.py to shut them down.
"""

import os
import socket
import subprocess
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
RUN_DIR = os.path.join(ROOT, "run")
LOG_DIR = os.path.join(ROOT, "logs")
CERTS_DIR = os.path.join(ROOT, "certs")
PROXY_URL_FILE = os.path.join(RUN_DIR, "proxy_url.txt")

PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
UI_PORT = int(os.environ.get("UI_PORT", "5000"))


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _ensure_dirs():
    for d in [RUN_DIR, LOG_DIR, CERTS_DIR]:
        os.makedirs(d, exist_ok=True)


def _pid_file(name: str) -> str:
    return os.path.join(RUN_DIR, f"{name}.pid")


def _log_file(name: str) -> str:
    return os.path.join(LOG_DIR, f"{name}.log")


def _write_pid(name: str, pid: int):
    with open(_pid_file(name), "w") as f:
        f.write(str(pid))


def _is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _wait_for_port(port: int, name: str, timeout: int = 30) -> None:
    print(f"  Waiting for {name} on port {port}...", end="", flush=True)
    for _ in range(timeout):
        if _is_port_open(port):
            print(" ready.")
            return
        time.sleep(1)
        print(".", end="", flush=True)
    print()
    raise TimeoutError(f"{name} did not start within {timeout}s. Check {_log_file(name)}.")


def _wait_for_file(path: str, name: str, timeout: int = 30) -> None:
    print(f"  Waiting for {name}...", end="", flush=True)
    for _ in range(timeout):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            print(" ready.")
            return
        time.sleep(1)
        print(".", end="", flush=True)
    print()
    raise TimeoutError(f"{name} file not found within {timeout}s.")


def _wait_for_cert(timeout: int = 30) -> None:
    cert_path = os.path.join(CERTS_DIR, "mitmproxy-ca-cert.pem")
    _wait_for_file(cert_path, "mitmproxy CA cert", timeout)


def _start_daemon(name: str, cmd: list[str], env: dict | None = None) -> int:
    """Launch a process detached from the terminal. Returns its PID."""
    log = open(_log_file(name), "a")
    proc_env = {**os.environ, **(env or {})}
    proc = subprocess.Popen(
        cmd,
        stdout=log,
        stderr=log,
        env=proc_env,
        start_new_session=True,  # detach from terminal — survives terminal close
        cwd=ROOT,
    )
    _write_pid(name, proc.pid)
    print(f"  {name} started (PID {proc.pid}) — logs: {_log_file(name)}")
    return proc.pid


def _already_running(name: str) -> bool:
    pid_path = _pid_file(name)
    if not os.path.exists(pid_path):
        return False
    try:
        with open(pid_path) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)  # check if process exists
        return True
    except (ProcessLookupError, ValueError):
        os.remove(pid_path)
        return False


def _check_env(*keys: str) -> None:
    missing = [k for k in keys if not os.environ.get(k)]
    if missing:
        print(f"[start] ERROR: Missing required environment variables: {', '.join(missing)}")
        print("  Copy .env.example to .env and fill in the values.")
        sys.exit(1)


# ------------------------------------------------------------------ #
# Main startup sequence
# ------------------------------------------------------------------ #


def main():
    # Load .env if present
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(ROOT, ".env"))
    except ImportError:
        pass

    print("\n=== OpenClaw Credential Broker — Starting ===\n")

    _check_env("E2B_API_KEY")

    use_ngrok = not os.environ.get("PROXY_URL", "").strip()
    if use_ngrok:
        _check_env("NGROK_AUTHTOKEN")

    _ensure_dirs()

    # ---- Step 1: mitmproxy ----
    print("[1/5] mitmproxy proxy daemon")
    if _already_running("mitmproxy"):
        print("  Already running — skipping.")
    else:
        _start_daemon(
            "mitmproxy",
            [
                sys.executable, "-m", "mitmproxy.tools.main",
                "mitmdump",
                "-s", os.path.join(ROOT, "proxy", "addon.py"),
                "--listen-port", str(PROXY_PORT),
                "--listen-host", "0.0.0.0",
                "--set", f"confdir={CERTS_DIR}",
                "--set", "ssl_insecure=false",
            ],
        )
        # Wait for port AND cert file (cert is written before port is open, but be safe)
        _wait_for_port(PROXY_PORT, "mitmproxy")
        _wait_for_cert()

    # ---- Step 2: Flask approval UI ----
    print("\n[2/5] Flask approval UI")
    if _already_running("flask"):
        print("  Already running — skipping.")
    else:
        _start_daemon(
            "flask",
            [sys.executable, "-m", "flask", "--app", "approval_ui/app.py", "run",
             "--host", "0.0.0.0", "--port", str(UI_PORT)],
            env={"FLASK_ENV": "production", "UI_PORT": str(UI_PORT)},
        )
        _wait_for_port(UI_PORT, "Flask UI")

    # ---- Step 3: ngrok tunnel (local only) ----
    print("\n[3/5] Proxy tunnel")
    if not use_ngrok:
        proxy_url = os.environ["PROXY_URL"]
        print(f"  Using fixed PROXY_URL: {proxy_url}")
        with open(PROXY_URL_FILE, "w") as f:
            f.write(proxy_url)
    elif _already_running("ngrok") and os.path.exists(PROXY_URL_FILE):
        with open(PROXY_URL_FILE) as f:
            proxy_url = f.read().strip()
        print(f"  ngrok already running — proxy URL: {proxy_url}")
    else:
        _start_daemon(
            "ngrok",
            [sys.executable, os.path.join(ROOT, "scripts", "ngrok_daemon.py")],
        )
        _wait_for_file(PROXY_URL_FILE, "ngrok proxy URL", timeout=30)
        with open(PROXY_URL_FILE) as f:
            proxy_url = f.read().strip()
        print(f"  Tunnel active: {proxy_url}")

    # ---- Step 4: E2B sandbox ----
    print("\n[4/5] Launching E2B sandbox")
    sys.path.insert(0, ROOT)
    from sandbox.launcher import launch_sandbox
    result = launch_sandbox()

    # ---- Step 5: Save state and print summary ----
    print("\n[5/5] Saving session state")
    with open(os.path.join(RUN_DIR, "session.txt"), "w") as f:
        f.write(f"sandbox_id={result['sandbox_id']}\n")
        f.write(f"gateway_url={result['gateway_url']}\n")
        f.write(f"proxy_url={proxy_url}\n")

    print("\n" + "=" * 50)
    print("OpenClaw is running and isolated.")
    print(f"\n  Gateway URL:  {result['gateway_url']}")
    print(f"  Approval UI:  http://localhost:{UI_PORT}")
    print(f"  Audit log:    http://localhost:{UI_PORT}/audit-log")
    print(f"  Proxy:        {proxy_url}")
    print()
    print("Any request from OpenClaw requiring credentials will pause")
    print("and appear at the Approval UI for your input.")
    print("OpenClaw never receives your credentials directly.")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
