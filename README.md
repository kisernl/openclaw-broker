# OpenClaw Credential Broker

An intercepting proxy that sits between OpenClaw and the internet, requiring manual human credential input for any authenticated request. OpenClaw never sees or handles your credentials — they are injected at the proxy layer only after you explicitly approve each request.

## How it works

```
E2B Sandbox (OpenClaw)
        │
        │  All HTTP/HTTPS traffic routed via HTTP_PROXY
        ▼
  ngrok TCP tunnel → mitmproxy (localhost:8080)
        │
        │  Auth signal detected — request paused
        ▼
  Flask Approval UI (localhost:5000)
        │
        │  You open the UI, select credential type, paste value, click Approve
        ▼
  mitmproxy injects credential into request → Upstream API
```

Every credentialed request requires your explicit approval. If the approval UI is unreachable, the request is blocked (fail closed).

## Project structure

```
openclaw-broker/
├── proxy/
│   └── addon.py              # mitmproxy addon — detects auth, pauses flows, injects credentials
├── approval_ui/
│   ├── app.py                # Flask server — approve/deny UI + audit log
│   └── templates/
│       ├── approve.html      # Pending requests UI (auto-refreshes every 3s)
│       └── audit_log.html    # History of all approved/denied decisions
├── sandbox/
│   └── launcher.py           # Creates E2B sandbox, installs cert, starts OpenClaw gateway
├── scripts/
│   ├── start.py              # Main entry point — starts all daemons + sandbox
│   ├── stop.py               # Shuts down all broker daemons
│   └── ngrok_daemon.py       # Opens TCP tunnel, writes public URL to run/proxy_url.txt
├── certs/                    # mitmproxy CA cert lives here (gitignored, generated on first run)
├── .env.example
└── requirements.txt
```

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Fill in your `.env`:

| Variable | Required | Description |
|---|---|---|
| `E2B_API_KEY` | Yes | From [e2b.dev/dashboard](https://e2b.dev/dashboard) |
| `OPENAI_API_KEY` | Yes | Passed to the OpenClaw sandbox for model calls |
| `OPENCLAW_APP_TOKEN` | Yes | Token for the OpenClaw gateway UI |
| `NGROK_AUTHTOKEN` | Local only | From [dashboard.ngrok.com](https://dashboard.ngrok.com/get-started/your-authtoken) — not needed when `PROXY_URL` is set |
| `PROXY_URL` | Railway only | Skip ngrok and use a fixed proxy URL (e.g. Railway service URL) |

### 3. Start

```bash
python scripts/start.py
```

This will:
1. Start mitmproxy on port 8080 (generates CA cert on first run)
2. Start the Flask approval UI on port 5000
3. Open an ngrok TCP tunnel and write the public URL to `run/proxy_url.txt`
4. Create an E2B sandbox, install the mitmproxy CA cert, and start the OpenClaw gateway
5. Print the gateway URL

You can close the terminal — all three daemons survive it.

### 4. Use OpenClaw

Open the printed **Gateway URL** in your browser to use the OpenClaw interface as normal.

When OpenClaw makes a request that requires credentials, it will pause. Open `http://localhost:5000` to see pending requests:

1. Review the intercepted request (method, URL, auth signal)
2. Select the credential type (Bearer Token, API Key, Basic Auth, etc.)
3. Paste the credential value into the password field
4. Click **Approve & Inject**

The credential is injected directly into the request. It is never stored, logged, or visible to OpenClaw.

To deny a request outright, click **Deny Request** — the flow is killed and OpenClaw receives an error.

### 5. Stop

```bash
python scripts/stop.py
```

## Audit log

Every approve/deny decision is recorded at `http://localhost:5000/audit-log`. The log captures the URL, action, and credential type — never the credential value itself.

## Railway deployment

The approval UI (Flask) deploys on Railway as a standard HTTP service. The proxy (mitmproxy) requires Railway's **TCP Proxy** feature because the E2B sandbox communicates with mitmproxy using the HTTP CONNECT method, which Railway's standard HTTP load balancer does not forward.

### Service 1: Approval UI

1. In Railway, create a new project and add a service from this repo, setting the **root directory** to `approval_ui/`
2. Railway will detect the `Dockerfile` automatically
3. Set these environment variables on the service:

   | Variable | Value |
   |---|---|
   | `APPROVAL_UI_URL` | *(auto — this is the UI itself, not needed here)* |

4. Note the public URL Railway assigns (e.g. `https://approval-ui-production.up.railway.app`) — you'll need it for the proxy service

### Service 2: Proxy (mitmproxy)

1. Add a second service from this repo, setting the **root directory** to `proxy/`
2. Railway will detect the `Dockerfile`
3. In the service settings, go to **Networking → TCP Proxy** and enable it on port `8080`. Railway will assign a public `hostname:port` (e.g. `containers-us-west-123.railway.app:12345`)
4. Set these environment variables on the service:

   | Variable | Value |
   |---|---|
   | `APPROVAL_UI_URL` | The URL from Service 1 (e.g. `https://approval-ui-production.up.railway.app`) |

5. On first deploy, mitmproxy generates its CA cert inside the container. To get it:
   ```bash
   railway run --service proxy -- cat /data/certs/mitmproxy-ca-cert.pem > certs/mitmproxy-ca-cert.pem
   ```
   This cert is what `sandbox/launcher.py` installs into the E2B sandbox.

### Local `.env` after Railway deployment

Update your local `.env` so `start.py` skips ngrok and uses the Railway proxy:

```
# Railway TCP proxy endpoint (from Service 2 networking settings)
PROXY_URL=http://containers-us-west-123.railway.app:12345

# Railway approval UI URL (from Service 1)
APPROVAL_UI_URL=https://approval-ui-production.up.railway.app
```

With `PROXY_URL` set, `start.py` skips the ngrok daemon entirely and goes straight to launching the E2B sandbox.

## Security properties

| Threat | Mitigation |
|---|---|
| OpenClaw reads secrets from environment | No secrets in sandbox environment |
| OpenClaw bypasses proxy and calls APIs directly | All outbound traffic routed via `HTTP_PROXY` + mitmproxy |
| Proxy logs your credentials | Credentials redacted before logging; never stored |
| Prompt injection tricks OpenClaw into exfiltrating secrets | OpenClaw never has secrets to exfiltrate |
| Rogue request made without your knowledge | Every credentialed request requires manual approval |
| Approval UI unreachable | Fail closed — request is blocked |

### What this does not protect against

- **Response data**: if an API returns sensitive data in its response, OpenClaw sees it. This project controls credential *input*, not data *output*.
- **Approved request scope**: once approved, the request executes fully. Use read-only tokens where possible as a complementary layer.
- **Host compromise**: the Flask UI and proxy run on your machine. If your host is compromised, all bets are off.
