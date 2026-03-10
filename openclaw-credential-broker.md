# OpenClaw Credential Broker — Project Outline & Build Guide

## Overview

This project builds a security layer around OpenClaw that prevents it from ever seeing or transmitting your credentials directly. Instead, all outbound HTTP/HTTPS traffic from OpenClaw is routed through an intercepting proxy. When the proxy detects an authentication attempt, it pauses the request, prompts you to manually input the credential, injects it, and forwards the request — without OpenClaw ever handling the secret.

---

## Architecture

```
┌─────────────────────────────────┐
│        Docker Container         │
│                                 │
│   OpenClaw ──► mitmproxy        │
│                    │            │
│         (TLS cert installed)    │
└────────────────────┼────────────┘
         Docker network policy:
           DENY all outbound
           ALLOW via proxy only
                    │
          ┌─────────▼──────────┐
          │   Approval UI      │  ◄── You type credential here
          │  (runs on host)    │
          └─────────┬──────────┘
                    │
             ┌──────▼──────┐
             │  Internet   │
             │  (Stripe,   │
             │   GitHub,   │
             │   etc.)     │
             └─────────────┘
```

### Key Properties

- **OpenClaw has no secrets.** No API keys, no tokens, no credentials in environment variables or config files.
- **Generic interception.** The proxy detects auth patterns (headers, body fields, query params) without needing per-service configuration.
- **Network-enforced.** Docker network rules make it physically impossible for OpenClaw to bypass the proxy and call services directly.
- **Human-in-the-loop.** Every credentialed request requires your explicit approval and input before it proceeds.

---

## Components

| Component | Technology | Purpose |
|---|---|---|
| OpenClaw container | Docker | Runs the agent in isolation |
| Intercepting proxy | mitmproxy + Python addon | Inspects all outbound traffic |
| Approval UI | Python (Flask) or terminal prompt | Surfaces credential requests to you |
| Network policy | Docker `--network` + iptables | Enforces proxy-only outbound access |
| TLS certificate | mitmproxy built-in CA | Allows HTTPS inspection inside container |

---

## Project Structure

```
openclaw-broker/
├── docker-compose.yml          # Orchestrates container + proxy
├── Dockerfile.openclaw         # OpenClaw container with cert installed
├── proxy/
│   ├── Dockerfile              # mitmproxy container
│   ├── addon.py                # Auth detection + approval logic
│   └── requirements.txt
├── approval-ui/
│   ├── app.py                  # Flask UI for credential input
│   ├── templates/
│   │   └── approve.html        # Approval prompt page
│   └── requirements.txt
├── certs/                      # Generated mitmproxy CA cert (gitignored)
└── .env.example                # Documents expected env vars (no secrets)
```

---

## Build Steps

### Phase 1 — Project Scaffold and Docker Setup

**Prompt 1 — Initialize the project**
```
Create a new project directory called `openclaw-broker`. 
Inside it, create the folder structure as follows:
- /proxy (empty for now)
- /approval-ui (empty for now)
- /certs (empty, add to .gitignore)
- A root .gitignore that ignores /certs, .env, __pycache__, and *.pyc
- A root README.md with a one-paragraph description of what this project does:
  an intercepting proxy that sits between OpenClaw and the internet, 
  requiring manual human credential input for any authenticated request.
```

---

**Prompt 2 — Create the OpenClaw Dockerfile**
```
Create a file at Dockerfile.openclaw.

It should:
1. Start FROM the official openclaw Docker image (use openclaw/openclaw:latest as placeholder)
2. Copy a CA certificate file from ./certs/mitmproxy-ca-cert.pem into the container 
   at /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
3. Run `update-ca-certificates` to install it as a trusted cert
4. Set the environment variables HTTP_PROXY and HTTPS_PROXY both pointing to http://proxy:8080
5. Set NO_PROXY to localhost,127.0.0.1

Add a comment at the top explaining why the cert is installed: so that mitmproxy 
can intercept TLS traffic without OpenClaw rejecting the connection.
```

---

**Prompt 3 — Create the mitmproxy Dockerfile**
```
Create a file at proxy/Dockerfile.

It should:
1. Use python:3.11-slim as base
2. Install mitmproxy via pip
3. Copy addon.py into /app/addon.py
4. Expose port 8080
5. Set the entrypoint to run mitmproxy in proxy mode (mitmdump) 
   with the addon loaded: mitmdump -s /app/addon.py --listen-port 8080
6. Also expose port 8081 for the mitmproxy web UI (useful for debugging)
```

---

**Prompt 4 — Create docker-compose.yml**
```
Create docker-compose.yml at the project root.

Define three services:

1. `openclaw` service:
   - Build from Dockerfile.openclaw
   - Depends on `proxy` and `approval-ui`
   - Set environment variable APPROVAL_UI_URL=http://approval-ui:5000
   - Do NOT give it any secret environment variables
   - Attach it only to an internal Docker network called `internal`
   - Do not expose any ports to the host

2. `proxy` service:
   - Build from proxy/Dockerfile
   - Mount ./certs as a volume at /home/mitmproxy/.mitmproxy so the 
     generated CA cert persists across restarts
   - Attach to both `internal` network and `external` network
   - Expose port 8080 internally only

3. `approval-ui` service:
   - Build from approval-ui/ directory
   - Expose port 5000 to the host (so you can access it in your browser)
   - Attach to the `internal` network only

Define two networks:
- `internal`: internal: true (no outbound internet access)
- `external`: normal bridge network with internet access

Add a comment explaining that the openclaw service is on `internal` only, 
meaning its only route to the internet is via the proxy, which bridges both networks.
```

---

### Phase 2 — The Intercepting Proxy Addon

**Prompt 5 — Auth pattern detection**
```
Create proxy/addon.py.

Write a mitmproxy addon class called `CredentialBroker`.

Implement a `request(self, flow)` method that detects whether an outbound 
request contains or requires authentication by checking all of the following:

1. Authorization header present (any value)
2. Headers named: X-API-Key, X-Auth-Token, X-Secret-Key, Api-Key
3. Query parameters named: api_key, key, secret, token, access_token, client_secret
4. JSON body fields named: api_key, secret, token, client_secret, password, access_token
   (parse body safely — catch all exceptions, don't crash on non-JSON)
5. URL path segments containing: /oauth/token, /auth/token, /login, /signin, /authenticate

If any of these are detected, set a flag on the flow: flow.metadata["requires_auth"] = True
and also store which signal triggered it in flow.metadata["auth_signal"].

Write a separate method `_parse_json_body(self, flow)` that safely attempts 
to parse the request body as JSON and returns a dict or None.

At the bottom, register the addon: addons = [CredentialBroker()]
```

---

**Prompt 6 — Request interception and approval**
```
Extend proxy/addon.py.

In the `request` method, after auth detection:

If flow.metadata.get("requires_auth") is True:
1. Build a dict called `request_summary` containing:
   - method: the HTTP method
   - url: the full URL (redact any detected secrets from the display)
   - auth_signal: what triggered the detection
   - headers_present: list of header names (not values)
   - timestamp: current UTC time as ISO string

2. Make a POST request to the approval UI at the URL stored in the 
   environment variable APPROVAL_UI_URL (default: http://approval-ui:5000).
   POST to /request-approval with the request_summary as JSON body.
   
3. Poll GET /approval-status/{request_id} every 500ms until the response 
   contains status "approved" or "denied".

4. If denied: call flow.kill() to abort the request entirely.

5. If approved: the approval response will contain a dict called `injected_headers`
   and `injected_params`. Apply these to flow.request before allowing it to continue.

Make sure all network calls to the approval UI are wrapped in try/except. 
If the approval UI is unreachable, default to DENY (call flow.kill()).
Add a comment: "Fail closed — if we can't reach the approval UI, block the request."
```

---

### Phase 3 — The Approval UI

**Prompt 7 — Flask approval server**
```
Create approval-ui/app.py.

Build a Flask application with the following routes:

POST /request-approval
- Accepts JSON body describing a pending request
- Generates a unique request_id (UUID)
- Stores the request in an in-memory dict called `pending_requests`
  with status "pending"
- Returns JSON: { "request_id": "...", "status": "pending" }

GET /approval-status/<request_id>
- Looks up the request in pending_requests
- Returns JSON with current status: "pending", "approved", or "denied"
- If approved, also returns injected_headers and injected_params

GET /
- Renders approve.html template
- Passes all pending requests to the template

POST /approve/<request_id>
- Accepts form data with fields: credential_type, credential_value
- Updates pending_requests[request_id] with:
  - status: "approved"
  - injected_headers: build appropriate header based on credential_type
    (e.g., if type is "bearer", set Authorization: Bearer <value>)
    (if type is "api_key_header", set X-API-Key: <value>)
  - injected_params: empty dict for now
- Returns redirect to /

POST /deny/<request_id>
- Sets pending_requests[request_id]["status"] = "denied"
- Returns redirect to /

Run on host 0.0.0.0 port 5000.
```

---

**Prompt 8 — Approval UI template**
```
Create approval-ui/templates/approve.html.

Build a clean, minimal HTML page that:

1. Has a heading: "Credential Approval Required"

2. If there are no pending requests, shows a message: 
   "No pending requests. OpenClaw is idle."

3. For each pending request, shows a card containing:
   - The HTTP method and URL of the intercepted request
   - The auth signal that triggered interception (e.g., "Authorization header detected")
   - The timestamp
   - A form with:
     - A dropdown to select credential type: 
       "Bearer Token", "API Key (Header)", "API Key (Query Param)", "Basic Auth"
     - A password input field for the credential value
       (type="password" so it doesn't display on screen)
     - An "Approve & Inject" submit button (posts to /approve/<request_id>)
     - A "Deny Request" button (posts to /deny/<request_id>)

4. Add a small note at the bottom: 
   "Credentials entered here are injected directly into the request 
    and are never stored or logged."

Use only inline CSS — no external dependencies. Keep the design simple and functional.
```

---

### Phase 4 — Certificate Generation and Network Hardening

**Prompt 9 — Certificate bootstrap script**
```
Create a shell script at scripts/bootstrap-certs.sh.

The script should:
1. Check if ./certs/mitmproxy-ca-cert.pem already exists. If so, exit early 
   with message "Certs already exist, skipping generation."
2. Run mitmproxy's built-in cert generation by starting mitmdump briefly 
   with --no-server flag to generate the CA in ~/.mitmproxy/
3. Copy mitmproxy-ca-cert.pem from ~/.mitmproxy/ into ./certs/
4. Print: "Certificate generated. You must copy ./certs/mitmproxy-ca-cert.pem 
   into the OpenClaw container before building — see Dockerfile.openclaw."

Make the script executable and add error handling: if cert generation fails, 
print a clear error and exit with code 1.
```

---

**Prompt 10 — iptables network enforcement**
```
Create a script at scripts/enforce-network.sh.

This script should use iptables to add an extra enforcement layer beyond 
Docker's network policy. It should:

1. Identify the Docker network interface for the `internal` network 
   (you can find this with `docker network inspect openclaw-broker_internal`)
   
2. Add an iptables OUTPUT rule that blocks all traffic from the internal 
   network interface EXCEPT:
   - Traffic destined for the proxy container's IP on port 8080
   - Traffic destined for the approval-ui container's IP on port 5000
   - Loopback traffic

3. Log blocked packets to syslog with prefix "OPENCLAW-BLOCKED: "

4. Print a summary of rules added.

Add a companion script scripts/clear-network.sh that removes these rules 
(for when you want to tear down the project cleanly).

Add a prominent comment: "These rules are belt-and-suspenders enforcement. 
Docker network isolation handles the primary restriction. 
These rules add a kernel-level backstop."
```

---

### Phase 5 — Wiring, Testing, and Hardening

**Prompt 11 — Startup script**
```
Create a script at scripts/start.sh that runs the full startup sequence:

1. Check that Docker and docker-compose are installed
2. Run scripts/bootstrap-certs.sh if certs don't exist
3. Run docker-compose build
4. Run docker-compose up -d
5. Wait 3 seconds, then run scripts/enforce-network.sh
6. Print startup summary:
   - "OpenClaw is running and isolated"
   - "Approval UI available at http://localhost:5000"
   - "Any request from OpenClaw requiring credentials will pause and 
      appear at the approval UI for your input"
   - "OpenClaw never receives your credentials directly"
```

---

**Prompt 12 — Write a test for the proxy addon**
```
Create proxy/test_addon.py.

Write unit tests for the CredentialBroker addon covering:

1. test_detects_authorization_header: 
   Mock a flow with an Authorization header, assert requires_auth is True

2. test_detects_api_key_query_param:
   Mock a flow with ?api_key=something in the URL, assert requires_auth is True

3. test_detects_json_body_secret:
   Mock a flow with a JSON body containing {"secret": "abc123"}, 
   assert requires_auth is True

4. test_passes_clean_request:
   Mock a plain GET request with no auth signals, assert requires_auth is False 
   or not set

5. test_kills_flow_on_approval_ui_unreachable:
   Mock the approval UI being unreachable (requests.post raises ConnectionError),
   assert flow.kill() is called

Use pytest and unittest.mock. Add a fixture that creates a minimal mock flow object.
```

---

**Prompt 13 — Redaction of credentials from logs**
```
Update proxy/addon.py to add credential redaction.

Add a method `_redact_for_display(self, flow)` that returns a safe version 
of the request for logging and display:

1. Copy all headers, but replace the VALUE of any sensitive header 
   (Authorization, X-API-Key, X-Auth-Token) with "[REDACTED]"
2. Copy the URL but replace the value of any sensitive query parameter 
   (api_key, secret, token, access_token) with "[REDACTED]"
3. If the body is JSON and contains sensitive fields, replace their values 
   with "[REDACTED]"

Use this redacted version when building request_summary for the approval UI 
and for any console logging.

Add a comment: "We never log raw credentials, even in the proxy process itself."
```

---

**Prompt 14 — Approval UI: request history and audit log**
```
Update approval-ui/app.py to add an audit log.

Every time a request is approved or denied:
1. Append an entry to a list called `audit_log` containing:
   - request_id
   - url (redacted)
   - action: "approved" or "denied"
   - credential_type (if approved, not the value)
   - timestamp

Add a route GET /audit-log that renders a simple HTML page listing 
all audit entries in reverse chronological order.

Add a link to "Audit Log" in the approve.html template.

Add a comment: "The audit log records that a credential was provided, 
but never the credential value itself. This gives you a record of 
what OpenClaw accessed without creating a new secret-exposure risk."
```

---

## Security Properties Summary

When fully built, this system guarantees:

| Threat | Mitigation |
|---|---|
| OpenClaw reads secrets from environment | No secrets in container environment |
| OpenClaw reads secrets from filesystem | Docker volume isolation |
| OpenClaw bypasses proxy and calls API directly | Docker network policy + iptables blocks all direct outbound |
| Proxy logs your credentials | Redaction applied before logging |
| Prompt injection tricks OpenClaw into exfiltrating secrets | OpenClaw never has secrets to exfiltrate |
| Rogue request made without your knowledge | Every credentialed request requires manual approval |

---

## What This Does Not Protect Against

- **Responses containing sensitive data**: if Stripe returns your full account details, OpenClaw sees those. This project controls credential *input*, not data *output*.
- **Approved requests being replayed**: once you approve a request, it executes fully. Scope control (e.g., read-only tokens) is a separate, complementary layer.
- **The approval UI itself being compromised**: the Flask app runs on your host. If your host is compromised, all bets are off.
