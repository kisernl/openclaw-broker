"""
Flask approval UI for the OpenClaw credential broker.

Receives intercepted request summaries from the mitmproxy addon,
surfaces them to the operator via a browser UI, and records
approve/deny decisions. Approved requests have credentials injected
at the proxy layer — credentials never enter the OpenClaw sandbox.

The audit log records that a credential was provided, but never the
credential value itself. This gives you a record of what OpenClaw
accessed without creating a new secret-exposure risk.
"""

import uuid
from datetime import datetime, timezone

from flask import Flask, jsonify, redirect, render_template, request, url_for

app = Flask(__name__)

# In-memory state — sufficient for a single-process daemon.
# Replace with Redis/SQLite if deploying with multiple workers on Railway.
pending_requests: dict[str, dict] = {}
audit_log: list[dict] = []


# ------------------------------------------------------------------ #
# Proxy addon endpoints
# ------------------------------------------------------------------ #


@app.post("/request-approval")
def request_approval():
    data = request.get_json(force=True)
    request_id = str(uuid.uuid4())
    pending_requests[request_id] = {
        "request_id": request_id,
        "status": "pending",
        "method": data.get("method", ""),
        "url": data.get("url", ""),
        "auth_signal": data.get("auth_signal", ""),
        "headers_present": data.get("headers_present", []),
        "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "injected_headers": {},
        "injected_params": {},
    }
    return jsonify({"request_id": request_id, "status": "pending"})


@app.get("/approval-status/<request_id>")
def approval_status(request_id: str):
    entry = pending_requests.get(request_id)
    if not entry:
        return jsonify({"status": "denied", "reason": "not_found"}), 404

    resp: dict = {"status": entry["status"]}
    if entry["status"] == "approved":
        resp["injected_headers"] = entry["injected_headers"]
        resp["injected_params"] = entry["injected_params"]
    return jsonify(resp)


# ------------------------------------------------------------------ #
# Browser UI endpoints
# ------------------------------------------------------------------ #


@app.get("/")
def index():
    pending = {
        rid: entry
        for rid, entry in pending_requests.items()
        if entry["status"] == "pending"
    }
    return render_template("approve.html", pending=pending)


@app.post("/approve/<request_id>")
def approve(request_id: str):
    entry = pending_requests.get(request_id)
    if not entry:
        return redirect(url_for("index"))

    credential_type = request.form.get("credential_type", "")
    credential_value = request.form.get("credential_value", "")

    injected_headers = _build_injected_headers(credential_type, credential_value)

    entry["status"] = "approved"
    entry["injected_headers"] = injected_headers
    entry["injected_params"] = {}

    audit_log.insert(0, {
        "request_id": request_id,
        "url": entry["url"],
        "action": "approved",
        "credential_type": credential_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    return redirect(url_for("index"))


@app.post("/deny/<request_id>")
def deny(request_id: str):
    entry = pending_requests.get(request_id)
    if entry:
        entry["status"] = "denied"
        audit_log.insert(0, {
            "request_id": request_id,
            "url": entry["url"],
            "action": "denied",
            "credential_type": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    return redirect(url_for("index"))


@app.get("/audit-log")
def view_audit_log():
    return render_template("audit_log.html", entries=audit_log)


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _build_injected_headers(credential_type: str, value: str) -> dict:
    mapping = {
        "bearer": {"Authorization": f"Bearer {value}"},
        "api_key_header": {"X-API-Key": value},
        "basic": {"Authorization": f"Basic {value}"},
        "api_key_query": {},  # injected_params handled separately if needed
    }
    return mapping.get(credential_type, {"Authorization": value})


if __name__ == "__main__":
    import os
    # Railway sets $PORT automatically; UI_PORT is the local override
    port = int(os.environ.get("PORT") or os.environ.get("UI_PORT") or 5000)
    app.run(host="0.0.0.0", port=port, threaded=True)
