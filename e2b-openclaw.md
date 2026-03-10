> ## Documentation Index
> Fetch the complete documentation index at: https://e2b.mintlify.app/llms.txt
> Use this file to discover all available pages before exploring further.

# Deploy OpenClaw

> Start the OpenClaw gateway in an E2B sandbox and connect your browser.

## Quick start

This launches your OpenClaw [gateway](https://docs.openclaw.ai/gateway) site (web UI for chatting with agents).

<CodeGroup>
  ```typescript JavaScript & TypeScript theme={"theme":{"light":"github-light","dark":"github-dark-default"}}
  import { Sandbox } from 'e2b'

  const TOKEN = process.env.OPENCLAW_APP_TOKEN || 'my-gateway-token'
  const PORT = 18789

  // 1. Create sandbox
  const sandbox = await Sandbox.create('openclaw', {
    envs: { OPENAI_API_KEY: process.env.OPENAI_API_KEY },
    timeoutMs: 3600_000,
  })

  // 2. Set the default model
  await sandbox.commands.run('openclaw config set agents.defaults.model.primary openai/gpt-5.2')

  // 3. Set insecure control UI flags and start the gateway with token auth
  await sandbox.commands.run(
    `bash -lc 'openclaw config set gateway.controlUi.allowInsecureAuth true && ` +
      `openclaw config set gateway.controlUi.dangerouslyDisableDeviceAuth true && ` +
      `openclaw gateway --allow-unconfigured --bind lan --auth token --token ${TOKEN} --port ${PORT}'`,
    { background: true }
  )

  // 4. Wait for the gateway to start listening
  for (let i = 0; i < 45; i++) {
    const probe = await sandbox.commands.run(
      `bash -lc 'ss -ltn | grep -q ":${PORT} " && echo ready || echo waiting'`
    )
    if (probe.stdout.trim() === 'ready') break
    await new Promise((r) => setTimeout(r, 1000))
  }

  const url = `https://${sandbox.getHost(PORT)}/?token=${TOKEN}`
  console.log(`Gateway: ${url}`)
  ```

  ```python Python theme={"theme":{"light":"github-light","dark":"github-dark-default"}}
  import os, time
  from e2b import Sandbox

  TOKEN = os.environ.get("OPENCLAW_APP_TOKEN", "my-gateway-token")
  PORT = 18789

  # 1. Create sandbox
  sandbox = Sandbox.create("openclaw", envs={
      "OPENAI_API_KEY": os.environ["OPENAI_API_KEY"],
  }, timeout=3600)

  # 2. Set the default model
  sandbox.commands.run("openclaw config set agents.defaults.model.primary openai/gpt-5.2")

  # 3. Set insecure control UI flags and start the gateway with token auth
  sandbox.commands.run(
      f"bash -lc 'openclaw config set gateway.controlUi.allowInsecureAuth true && "
      f"openclaw config set gateway.controlUi.dangerouslyDisableDeviceAuth true && "
      f"openclaw gateway --allow-unconfigured --bind lan --auth token --token {TOKEN} --port {PORT}'",
      background=True,
  )

  # 4. Wait for the gateway to start listening
  for _ in range(45):
      probe = sandbox.commands.run(
          f'bash -lc \'ss -ltn | grep -q ":{PORT} " && echo ready || echo waiting\''
      )
      if probe.stdout.strip() == "ready":
          break
      time.sleep(1)

  url = f"https://{sandbox.get_host(PORT)}/?token={TOKEN}"
  print(f"Gateway: {url}")
  ```
</CodeGroup>

Visit the printed `Gateway` URL in your browser.

If you run in secure mode (set `gateway.controlUi.dangerouslyDisableDeviceAuth false`), run this after opening the URL to poll pending pairing requests and approve the first one.

<CodeGroup>
  ```typescript JavaScript & TypeScript theme={"theme":{"light":"github-light","dark":"github-dark-default"}}
  // 5. Poll for the browser's pending device request and approve it
  for (let i = 0; i < 30; i++) {
    try {
      const res = await sandbox.commands.run(
        `openclaw devices list --json --url ws://127.0.0.1:${PORT} --token ${TOKEN}`
      )
      const data = JSON.parse(res.stdout)
      if (data.pending?.length) {
        const rid = data.pending[0].requestId
        await sandbox.commands.run(
          `openclaw devices approve ${rid} --token ${TOKEN} --url ws://127.0.0.1:${PORT}`
        )
        console.log(`Device approved: ${rid}`)
        break
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 2000))
  }
  ```

  ```python Python theme={"theme":{"light":"github-light","dark":"github-dark-default"}}
  import json

  # 5. Poll for the browser's pending device request and approve it
  for _ in range(30):
      try:
          res = sandbox.commands.run(
              f"openclaw devices list --json --url ws://127.0.0.1:{PORT} --token {TOKEN}"
          )
          data = json.loads(res.stdout)
          if data.get("pending"):
              rid = data["pending"][0]["requestId"]
              sandbox.commands.run(
                  f"openclaw devices approve {rid} --token {TOKEN} --url ws://127.0.0.1:{PORT}"
              )
              print(f"Device approved: {rid}")
              break
      except Exception:
          pass
      time.sleep(2)
  ```
</CodeGroup>

Once approved, the browser connects and the gateway UI loads.

## How it works

| Step                         | What happens                                                                 |
| ---------------------------- | ---------------------------------------------------------------------------- |
| `--bind lan`                 | Gateway listens on `0.0.0.0` so E2B can proxy it                             |
| `--auth token`               | Requires `?token=` on the URL for HTTP and WebSocket auth                    |
| Browser opens URL            | Gateway serves the UI, browser opens a WebSocket                             |
| `code=1008 pairing required` | Gateway closes the WebSocket until the device is approved (secure mode only) |
| `devices approve`            | Approves the browser's device fingerprint (secure mode only)                 |
| Browser reconnects           | WebSocket connects successfully, UI is live                                  |

## Gateway flags reference

| Flag                   | Purpose                                            |
| ---------------------- | -------------------------------------------------- |
| `--allow-unconfigured` | Start without a full config file                   |
| `--bind lan`           | Bind to `0.0.0.0` (required for E2B port proxying) |
| `--auth token`         | Enable token-based authentication                  |
| `--token <value>`      | The auth token (passed as `?token=` in the URL)    |
| `--port <number>`      | Gateway listen port (default: `18789`)             |

## How to restart the gateway

Use this when the gateway is already running and you want a clean restart (for example, after changing model or env settings).

<Info>
  We can't use the `openclaw gateway restart` command here. Some SDK environments cannot target a specific Unix user in `commands.run`. The commands below use the default command user context.
</Info>

<CodeGroup>
  ```typescript JavaScript & TypeScript theme={"theme":{"light":"github-light","dark":"github-dark-default"}}
  const TOKEN = process.env.OPENCLAW_APP_TOKEN || 'my-gateway-token'
  const PORT = 18789

  // 1) Kill existing gateway processes if present
  await sandbox.commands.run(
    `bash -lc 'for p in "[o]penclaw gateway" "[o]penclaw-gateway"; do for pid in $(pgrep -f "$p" || true); do kill "$pid" >/dev/null 2>&1 || true; done; done'`
  )
  await new Promise((r) => setTimeout(r, 1000))

  // 2) Start gateway again
  await sandbox.commands.run(
    `openclaw gateway --allow-unconfigured --bind lan --auth token --token ${TOKEN} --port ${PORT}`,
    { background: true }
  )

  // 3) Wait for listening socket
  for (let i = 0; i < 45; i++) {
    const probe = await sandbox.commands.run(
      `bash -lc 'ss -ltn | grep -q ":${PORT} " && echo ready || echo waiting'`
    )
    if (probe.stdout.trim() === 'ready') break
    await new Promise((r) => setTimeout(r, 1000))
  }
  ```

  ```python Python theme={"theme":{"light":"github-light","dark":"github-dark-default"}}
  import os, time

  TOKEN = os.environ.get("OPENCLAW_APP_TOKEN", "my-gateway-token")
  PORT = 18789

  # 1) Kill existing gateway processes if present
  sandbox.commands.run(
      """bash -lc 'for p in "[o]penclaw gateway" "[o]penclaw-gateway"; do
  for pid in $(pgrep -f "$p" || true); do
    kill "$pid" >/dev/null 2>&1 || true
  done
  done'"""
  )
  time.sleep(1)

  # 2) Start gateway again
  sandbox.commands.run(
      f"openclaw gateway --allow-unconfigured --bind lan --auth token --token {TOKEN} --port {PORT}",
      background=True,
  )

  # 3) Wait for listening socket
  for _ in range(45):
      probe = sandbox.commands.run(
          f'bash -lc \'ss -ltn | grep -q ":{PORT} " && echo ready || echo waiting\''
      )
      if probe.stdout.strip() == "ready":
          break
      time.sleep(1)
  ```
</CodeGroup>

## Turn insecure flags off (recommended after testing)

Use this to restore secure device authentication after initial testing.

<CodeGroup>
  ```typescript JavaScript & TypeScript theme={"theme":{"light":"github-light","dark":"github-dark-default"}}
  const TOKEN = process.env.OPENCLAW_APP_TOKEN || 'my-gateway-token'
  const PORT = 18789

  await sandbox.commands.run(
    `bash -lc 'openclaw config set gateway.controlUi.allowInsecureAuth false && ` +
      `openclaw config set gateway.controlUi.dangerouslyDisableDeviceAuth false'`
  )

  await sandbox.commands.run(
    `bash -lc 'for p in "[o]penclaw gateway" "[o]penclaw-gateway"; do for pid in $(pgrep -f "$p" || true); do kill "$pid" >/dev/null 2>&1 || true; done; done'`
  )

  await sandbox.commands.run(
    `openclaw gateway --allow-unconfigured --bind lan --auth token --token ${TOKEN} --port ${PORT}`,
    { background: true }
  )
  ```

  ```python Python theme={"theme":{"light":"github-light","dark":"github-dark-default"}}
  import os

  TOKEN = os.environ.get("OPENCLAW_APP_TOKEN", "my-gateway-token")
  PORT = 18789

  sandbox.commands.run(
      "bash -lc 'openclaw config set gateway.controlUi.allowInsecureAuth false && "
      "openclaw config set gateway.controlUi.dangerouslyDisableDeviceAuth false'"
  )

  sandbox.commands.run(
      """bash -lc 'for p in "[o]penclaw gateway" "[o]penclaw-gateway"; do
  for pid in $(pgrep -f "$p" || true); do
    kill "$pid" >/dev/null 2>&1 || true
  done
  done'"""
  )

  sandbox.commands.run(
      f"openclaw gateway --allow-unconfigured --bind lan --auth token --token {TOKEN} --port {PORT}",
      background=True,
  )
  ```
</CodeGroup>

## Related

<CardGroup cols={1}>
  <Card title="OpenClaw Telegram" icon="message-circle" href="/docs/agents/openclaw/openclaw-telegram">
    Connect OpenClaw to Telegram and approve pairing
  </Card>
</CardGroup>