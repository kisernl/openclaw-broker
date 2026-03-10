"""
mitmproxy addon — CredentialBroker

Intercepts all outbound HTTP/HTTPS requests from the OpenClaw E2B sandbox.
When a request contains or requires authentication, it pauses the flow,
submits a summary to the Flask approval UI, and waits for a human to either
approve (injecting credentials) or deny (killing the flow).

We never log raw credentials, even in the proxy process itself.
Fail closed — if we can't reach the approval UI, block the request.
"""

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

import httpx
from mitmproxy import http

APPROVAL_UI_URL = os.environ.get("APPROVAL_UI_URL", "http://localhost:5000")
APPROVAL_TIMEOUT_SECONDS = int(os.environ.get("APPROVAL_TIMEOUT_SECONDS", "300"))
POLL_INTERVAL = 0.5

AUTH_HEADERS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-secret-key",
    "api-key",
}

AUTH_QUERY_PARAMS = {
    "api_key",
    "key",
    "secret",
    "token",
    "access_token",
    "client_secret",
}

AUTH_BODY_FIELDS = {
    "api_key",
    "secret",
    "token",
    "client_secret",
    "password",
    "access_token",
}

AUTH_PATH_SEGMENTS = {
    "/oauth/token",
    "/auth/token",
    "/login",
    "/signin",
    "/authenticate",
}

SENSITIVE_HEADERS = {"authorization", "x-api-key", "x-auth-token", "x-secret-key"}
SENSITIVE_PARAMS = {"api_key", "secret", "token", "access_token", "client_secret"}
SENSITIVE_BODY_FIELDS = AUTH_BODY_FIELDS


class CredentialBroker:
    async def request(self, flow: http.HTTPFlow) -> None:
        requires_auth, auth_signal = self._detect_auth(flow)

        if not requires_auth:
            return

        flow.metadata["requires_auth"] = True
        flow.metadata["auth_signal"] = auth_signal

        request_summary = self._build_summary(flow, auth_signal)

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{APPROVAL_UI_URL}/request-approval",
                    json=request_summary,
                )
                resp.raise_for_status()
                request_id = resp.json()["request_id"]
        except Exception as exc:
            # Fail closed — approval UI unreachable
            print(f"[broker] Could not reach approval UI: {exc} — blocking request")
            flow.kill()
            return

        # Poll for approval decision
        deadline = time.monotonic() + APPROVAL_TIMEOUT_SECONDS
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                while time.monotonic() < deadline:
                    await asyncio.sleep(POLL_INTERVAL)
                    try:
                        poll = await client.get(
                            f"{APPROVAL_UI_URL}/approval-status/{request_id}"
                        )
                        data = poll.json()
                    except Exception:
                        # Treat unreachable UI as denied
                        flow.kill()
                        return

                    status = data.get("status")

                    if status == "denied":
                        flow.kill()
                        return

                    if status == "approved":
                        injected_headers = data.get("injected_headers", {})
                        injected_params = data.get("injected_params", {})
                        for k, v in injected_headers.items():
                            flow.request.headers[k] = v
                        if injected_params:
                            flow.request.query.update(injected_params)
                        return

                    # status == "pending" — keep polling

        except Exception as exc:
            print(f"[broker] Polling error: {exc} — blocking request")
            flow.kill()
            return

        # Timeout reached with no decision — fail closed
        print(f"[broker] Approval timeout for {request_id} — blocking request")
        flow.kill()

    # ------------------------------------------------------------------ #
    # Auth detection
    # ------------------------------------------------------------------ #

    def _detect_auth(self, flow: http.HTTPFlow) -> tuple[bool, str]:
        headers = {k.lower(): v for k, v in flow.request.headers.items()}

        for h in AUTH_HEADERS:
            if h in headers:
                return True, f"header:{h}"

        parsed = urlparse(flow.request.pretty_url)
        params = parse_qs(parsed.query)
        for p in AUTH_QUERY_PARAMS:
            if p in params:
                return True, f"query_param:{p}"

        path = parsed.path.lower()
        for segment in AUTH_PATH_SEGMENTS:
            if segment in path:
                return True, f"path:{segment}"

        body = self._parse_json_body(flow)
        if body:
            for field in AUTH_BODY_FIELDS:
                if field in body:
                    return True, f"body_field:{field}"

        return False, ""

    def _parse_json_body(self, flow: http.HTTPFlow) -> dict | None:
        try:
            content_type = flow.request.headers.get("content-type", "")
            if "json" not in content_type.lower():
                return None
            return json.loads(flow.request.content)
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    # Redaction and summary building
    # ------------------------------------------------------------------ #

    def _redact_for_display(self, flow: http.HTTPFlow) -> dict:
        # Redact sensitive headers
        safe_headers = {}
        for k, v in flow.request.headers.items():
            safe_headers[k] = "[REDACTED]" if k.lower() in SENSITIVE_HEADERS else v

        # Redact sensitive query params from URL
        parsed = urlparse(flow.request.pretty_url)
        params = parse_qs(parsed.query)
        safe_params = []
        for k, vals in params.items():
            display_val = "[REDACTED]" if k.lower() in SENSITIVE_PARAMS else vals[0]
            safe_params.append(f"{k}={display_val}")
        safe_url = parsed._replace(query="&".join(safe_params)).geturl()

        # Redact sensitive body fields
        safe_body = None
        body = self._parse_json_body(flow)
        if body:
            safe_body = {
                k: "[REDACTED]" if k.lower() in SENSITIVE_BODY_FIELDS else v
                for k, v in body.items()
            }

        return {
            "safe_headers": safe_headers,
            "safe_url": safe_url,
            "safe_body": safe_body,
        }

    def _build_summary(self, flow: http.HTTPFlow, auth_signal: str) -> dict:
        redacted = self._redact_for_display(flow)
        return {
            "method": flow.request.method,
            "url": redacted["safe_url"],
            "auth_signal": auth_signal,
            "headers_present": list(flow.request.headers.keys()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


addons = [CredentialBroker()]
