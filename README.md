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

### Tool policy

- `web_fetch` is disabled at the gateway level — it bypasses the proxy and cannot be credentialed
- The agent is instructed to use `curl` or Python `requests` for all HTTP calls
- Placeholder credential env vars (`GITHUB_TOKEN=broker-pending`, etc.) are pre-set so the agent proceeds with requests rather than asking you for tokens inline; the proxy replaces them with real credentials you inject at approval time

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
│   └── launcher.py           # Creates E2B sandbox, installs cert, configures tool policy, starts gateway
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
python -m venv venv && source venv/bin/activate
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
| `OPENROUTER_API_KEY` | Yes | From [openrouter.ai/keys](https://openrouter.ai/keys) — used for the OpenClaw model backend |
| `OPENCLAW_APP_TOKEN` | Yes | Token for the OpenClaw gateway UI (any string you choose) |
| `NGROK_AUTHTOKEN` | Yes (local) | From [dashboard.ngrok.com](https://dashboard.ngrok.com/get-started/your-authtoken) — TCP tunnels require a verified card on file (free, not charged) |
| `PROXY_URL` | Optional | Skip ngrok and use a pre-existing proxy URL (e.g. a fixed server) |

### 3. Start

```bash
python scripts/start.py
```

This will:
1. Start mitmproxy on port 8080 (generates CA cert on first run)
2. Start the Flask approval UI on port 5000
3. Open an ngrok TCP tunnel and write the public URL to `run/proxy_url.txt`
4. Create an E2B sandbox, install the mitmproxy CA cert, apply tool policy, and start the OpenClaw gateway
5. Print the gateway URL

You can close the terminal — all daemons survive it.

### 4. Use OpenClaw

Open the printed **Gateway URL** in your browser to use the OpenClaw interface.

When OpenClaw makes a request to a known API host (GitHub, Linear, Notion, Slack, etc.), it will be intercepted and paused. Open `http://localhost:5000` to see pending requests:

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

## Model configuration

The default model is set in `sandbox/launcher.py`:

```python
"openclaw config set agents.defaults.model.primary openrouter/moonshotai/kimi-k2"
```

Change this to any model available on OpenRouter using the `openrouter/<provider>/<model>` format. The model API key is the `OPENROUTER_API_KEY` — it bypasses the proxy entirely and is never intercepted.

## Security properties

| Threat | Mitigation |
|---|---|
| OpenClaw reads secrets from environment | No real secrets in sandbox environment; only broker placeholders |
| OpenClaw bypasses proxy and calls APIs directly | All outbound traffic routed via `HTTP_PROXY` + mitmproxy |
| OpenClaw uses web_fetch to bypass the proxy | `web_fetch` denied at the gateway level via tool policy |
| Proxy logs your credentials | Credentials redacted before logging; never stored |
| Prompt injection tricks OpenClaw into exfiltrating secrets | OpenClaw never has real secrets to exfiltrate |
| Rogue request made without your knowledge | Every credentialed request requires manual approval |
| Approval UI unreachable | Fail closed — request is blocked |

### What this does not protect against

- **Response data**: if an API returns sensitive data in its response, OpenClaw sees it. This project controls credential *input*, not data *output*.
- **Approved request scope**: once approved, the request executes fully. Use read-only tokens where possible as a complementary layer.
- **Host compromise**: the Flask UI and proxy run on your machine. If your host is compromised, all bets are off.
- **Unlisted services**: placeholder tokens are only pre-set for known API hosts. Requests to unlisted services are still intercepted if they carry an auth header or hit a known auth path, but the model may ask for credentials inline for unknown services.
