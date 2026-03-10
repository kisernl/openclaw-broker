"""
E2B sandbox launcher for OpenClaw.

Creates an E2B sandbox using the 'openclaw' template, installs the
mitmproxy CA certificate so HTTPS inspection works, configures all
outbound traffic to route through the local mitmproxy (via ngrok tunnel
or a fixed PROXY_URL), then starts the OpenClaw gateway.

OpenClaw never receives credentials — it has no secrets in its
environment. All credentialed requests will be intercepted by the proxy.
"""

import os
import time

from e2b import Sandbox

GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "18789"))
OPENCLAW_APP_TOKEN = os.environ.get("OPENCLAW_APP_TOKEN", "my-gateway-token")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")


def _read_proxy_url() -> str:
    """
    Read the proxy URL from the environment or from the state file
    written by the ngrok daemon. Raises if neither is available.
    """
    proxy_url = os.environ.get("PROXY_URL", "").strip()
    if proxy_url:
        return proxy_url

    state_file = os.path.join(os.path.dirname(__file__), "..", "run", "proxy_url.txt")
    state_file = os.path.normpath(state_file)
    if os.path.exists(state_file):
        with open(state_file) as f:
            url = f.read().strip()
        if url:
            return url

    raise RuntimeError(
        "No proxy URL available. Set PROXY_URL env var or ensure the ngrok daemon "
        "has written run/proxy_url.txt before calling launch_sandbox()."
    )


def _read_cert() -> str:
    """Read the mitmproxy CA cert from the certs/ directory."""
    cert_path = os.path.join(os.path.dirname(__file__), "..", "certs", "mitmproxy-ca-cert.pem")
    cert_path = os.path.normpath(cert_path)
    if not os.path.exists(cert_path):
        raise FileNotFoundError(
            f"mitmproxy CA cert not found at {cert_path}. "
            "Ensure mitmproxy has started and generated its certs before launching the sandbox."
        )
    with open(cert_path) as f:
        return f.read()


def _install_cert(sandbox: Sandbox, cert_pem: str) -> None:
    """Upload the mitmproxy CA cert into the sandbox and trust it."""
    print("[launcher] Installing mitmproxy CA cert in sandbox...")
    sandbox.files.write("/tmp/mitmproxy-ca-cert.pem", cert_pem)
    result = sandbox.commands.run(
        "cp /tmp/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt "
        "&& update-ca-certificates"
    )
    if result.exit_code != 0:
        raise RuntimeError(
            f"Failed to install CA cert in sandbox:\n{result.stderr}"
        )
    print("[launcher] CA cert installed.")


def _wait_for_gateway(sandbox: Sandbox, port: int, timeout: int = 45) -> None:
    """Poll until the OpenClaw gateway is listening on the given port."""
    print(f"[launcher] Waiting for gateway on port {port}...")
    for _ in range(timeout):
        probe = sandbox.commands.run(
            f"bash -lc 'ss -ltn | grep -q \":{port} \" && echo ready || echo waiting'"
        )
        if probe.stdout.strip() == "ready":
            return
        time.sleep(1)
    raise TimeoutError(f"OpenClaw gateway did not start within {timeout}s")


def launch_sandbox() -> dict:
    """
    Start an OpenClaw E2B sandbox with the proxy configured.

    Returns a dict with:
      - sandbox_id: the E2B sandbox ID (save this to reconnect)
      - gateway_url: the URL to open in a browser
    """
    proxy_url = _read_proxy_url()
    cert_pem = _read_cert()

    print(f"[launcher] Using proxy: {proxy_url}")
    print("[launcher] Creating E2B sandbox (openclaw template)...")

    # OpenClaw has no secrets — credentials are never passed here.
    # The only env var is OPENAI_API_KEY for the model backend;
    # all API calls will still route through the proxy and require approval.
    sandbox = Sandbox.create(
        "openclaw",
        envs={
            "OPENAI_API_KEY": OPENAI_API_KEY,
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "NO_PROXY": "localhost,127.0.0.1",
        },
        timeout_ms=3_600_000,
    )

    print(f"[launcher] Sandbox created: {sandbox.sandbox_id}")

    # Install the mitmproxy CA cert so HTTPS inspection works
    _install_cert(sandbox, cert_pem)

    # Configure OpenClaw settings
    print("[launcher] Configuring OpenClaw...")
    sandbox.commands.run(
        "bash -lc '"
        "openclaw config set agents.defaults.model.primary openai/gpt-4o && "
        "openclaw config set gateway.controlUi.allowInsecureAuth true && "
        "openclaw config set gateway.controlUi.dangerouslyDisableDeviceAuth true"
        "'"
    )

    # Start the gateway in the background
    print("[launcher] Starting OpenClaw gateway...")
    sandbox.commands.run(
        f"openclaw gateway "
        f"--allow-unconfigured "
        f"--bind lan "
        f"--auth token "
        f"--token {OPENCLAW_APP_TOKEN} "
        f"--port {GATEWAY_PORT}",
        background=True,
    )

    _wait_for_gateway(sandbox, GATEWAY_PORT)

    gateway_url = f"https://{sandbox.get_host(GATEWAY_PORT)}/?token={OPENCLAW_APP_TOKEN}"
    print(f"[launcher] Gateway ready: {gateway_url}")

    return {
        "sandbox_id": sandbox.sandbox_id,
        "gateway_url": gateway_url,
    }


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    result = launch_sandbox()
    print(f"\nGateway URL: {result['gateway_url']}")
    print(f"Sandbox ID:  {result['sandbox_id']}")
