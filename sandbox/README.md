# CounterForge DVAA Lab (sandbox)

## Build / up / down

```powershell
docker compose -f sandbox/compose.dvaa.yml config --quiet
docker compose -f sandbox/compose.dvaa.yml build
docker compose -f sandbox/compose.dvaa.yml up -d
docker compose -f sandbox/compose.dvaa.yml down
```

Build clones pinned DVAA `57918267d8d529ceec6d40fc9836ab09d128eee4`, applies `provider-baseurl.patch`, and installs from `node:24-alpine` (reuse from `.research/dvaa/Dockerfile`).

## LLM mode (runtime only — dashboard enabled by removing `--only`)

Dashboards run on the full fleet (`--offline` kept for telemetry disable).
Enable LLM via POST to each dashboard with dummy key and local Ollama endpoint.

```bash
# dvaa-qwen (dashboard 9000) — model qwen2.5:3b
curl -s -X POST http://127.0.0.1:9000/api/llm/configure \
  -H 'Content-Type: application/json' \
  -d '{"provider":"openai","apiKey":"dummy","model":"qwen2.5:3b"}'

# dvaa-llama (dashboard 9100) — model llama3.2:3b
curl -s -X POST http://127.0.0.1:9100/api/llm/configure \
  -H 'Content-Type: application/json' \
  -d '{"provider":"openai","apiKey":"dummy","model":"llama3.2:3b"}'
```

`OPENAI_BASE_URL` is set to `http://host.docker.internal:11434/v1` in both services; `DVAA_HOST=0.0.0.0`. Verify the patch is active by checking `src/llm/provider.js` inside the container (`process.env.OPENAI_BASE_URL || 'https://api.openai.com...'`).

## Canary / exfil convention

DVAA RAG exfil injects `http://127.0.0.1:65500/api/canary/exfil-test?data=...`. Within containers, reach the collector as `http://canary:65500/api/canary/exfil-test` (shared `lab` network, `internal: true`; verified reachable to `host.docker.internal:11434`). The collector (`sandbox/collector/`) records all hits in memory; `GET /hits` returns JSON; anything else returns `200 CANARY RECEIPT`.

## Verification (do not start the stack if not needed)

```bash
# Health
curl -s http://127.0.0.1:9000/health
curl -s http://127.0.0.1:9100/health

# Agent API shape (per .research/dvaa/src/index.js)
curl -s -X POST http://127.0.0.1:7005/v1/chat/completions \
  -H 'Content-Type: application/json' -d '{"messages":[{"role":"user","content":"hi"}]}'

# Collector
curl -s http://127.0.0.1:65500/hits
```

Port bindings are loopback-only (`127.0.0.1`). Hardening preserved: `cap_drop: ALL`, `security_opt: no-new-privileges:true`, `read_only`, `tmpfs /tmp`, resource limits, `init`, `restart: 'no'`, healthchecks.
