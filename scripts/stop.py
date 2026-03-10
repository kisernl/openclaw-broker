#!/usr/bin/env python3
"""
OpenClaw credential broker — stop script.

Sends SIGTERM to all broker daemons (mitmproxy, Flask, ngrok)
and cleans up PID files and the proxy URL state file.
"""

import os
import signal
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
RUN_DIR = os.path.join(ROOT, "run")

DAEMONS = ["mitmproxy", "flask", "ngrok"]


def _pid_file(name: str) -> str:
    return os.path.join(RUN_DIR, f"{name}.pid")


def _stop_daemon(name: str) -> None:
    pid_path = _pid_file(name)
    if not os.path.exists(pid_path):
        print(f"  {name}: no PID file — skipping")
        return
    try:
        with open(pid_path) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"  {name}: sent SIGTERM to PID {pid}")
        os.remove(pid_path)
    except ProcessLookupError:
        print(f"  {name}: process {pid} not found — cleaning up PID file")
        os.remove(pid_path)
    except ValueError:
        print(f"  {name}: invalid PID file — removing")
        os.remove(pid_path)
    except Exception as exc:
        print(f"  {name}: error stopping — {exc}")


def main():
    print("\n=== OpenClaw Credential Broker — Stopping ===\n")
    for daemon in DAEMONS:
        _stop_daemon(daemon)

    # Clean up state files
    for fname in ["proxy_url.txt", "session.txt"]:
        path = os.path.join(RUN_DIR, fname)
        if os.path.exists(path):
            os.remove(path)
            print(f"  Removed {fname}")

    print("\nAll broker daemons stopped.\n")


if __name__ == "__main__":
    main()
