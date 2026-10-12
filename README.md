# CounterForge

An incident-response assistant and agent-defense lab for CrowdStrike Track 3. Investigate a synthetic incident, catch a poisoned runbook attempting an unauthorized export, and replay attacks against a versioned tool policy. CounterForge builds on [Redforge](https://github.com/thesid42/Redforge); the reuse map is in [PROVENANCE.md](PROVENANCE.md).

**Current build: executable local demo plus an optional adaptive model lab.** Demo mode uses deterministic fixtures. Live mode can use OpenRouter-backed attacker and defender roles against the localhost-only DVAA/Ollama target. Alerts remain operator-approved and are simulated unless `ALERT_MODE=twilio_voice` is explicitly configured.

![CounterForge workspace, implemented local demo](design/counterforge-live-workspace.jpg)

## What works

- Incident chat with persistent conversations, synthetic runbooks, draft updates, and a security timeline.
- Four bounded attack objectives: runbook injection, tool-result injection, operator impersonation, and protected-context extraction. In adaptive mode, an attacker model creates new prompts over multiple rounds using redacted observations of the local target's behavior.
- A LangGraph workflow: generate → execute → inspect → propose → replay. A separate defender model analyzes each observed attack and proposes a constrained system defense; the verdict comes from executing the attack against the target again with that defense applied.
- Baseline/defended traces, adaptive held-out rounds, and four benign tool-permission checks. Results apply only to the configured synthetic lab and are not universal model-robustness claims.
- Operator activation of validated policies, stale-candidate rejection, rollback, and monotonic policy versions.
- Action-bound paging approvals with expiry, recipient allowlisting, duplicate suppression, and rate limiting. Notifications are simulated by default or sent as sanitized Twilio voice calls when explicitly configured; acknowledgment and resolution remain operator actions.
- Markdown/JSON reports, SQLite persistence, scoped SSE events, and a React interface with six views.

## Run locally

Use Python 3.12 or newer and Node.js 22.12 or newer. Run commands from the repository root. A single backend worker owns local state and approval serialization.

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
npm --prefix frontend ci
npm --prefix frontend run build
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

macOS / Linux:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
npm --prefix frontend ci
npm --prefix frontend run build
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000**. The backend serves the built frontend. Build the frontend before starting the backend, and restart it after changing Python files.

For frontend development, keep the backend running and run `npm --prefix frontend run dev` in a second terminal. Open http://127.0.0.1:5173; Vite proxies `/api` to the backend.

## Adaptive attacker and defender

The live target remains local DVAA backed by Ollama. To enable the two hosted roles, add one OpenRouter key to the ignored `.env` file:

```env
OPENROUTER_API_KEY=
ATTACKER_BASE_URL=https://openrouter.ai/api/v1
ATTACKER_MODEL=z-ai/glm-5.3-flash
DEFENDER_BASE_URL=https://openrouter.ai/api/v1
DEFENDER_MODEL=z-ai/glm-5.3-flash
ADAPTIVE_ATTACK_ROUNDS=2
```

`ATTACKER_API_KEY` and `DEFENDER_API_KEY` are optional per-role overrides. If they are empty, both roles use `OPENROUTER_API_KEY`. Restart the backend after changing `.env`. Role prompts and target responses are bounded and redacted before persistence; API keys are used only in authorization headers and are never placed in model prompts or reports.

## Demo walkthrough

1. In **Workspace**, enable **Use injected runbook**, then click **Investigate the outage**. The legitimate response remains useful; the security timeline shows the denied export.
2. Click **Review action**, inspect the recipient, exact text, expiry, and policy version, then **Approve simulation**.
3. In **Incidents**, acknowledge the simulated page and resolve the incident. No external call occurs.
4. In **Attack lab**, choose **All attack surfaces** and **Run comparison**. Inspect matching baseline/defended traces and the replay evidence.
5. Review the candidate rule, **Activate in local lab**, then inspect **Defenses**. Rollback remains available.
6. Download the Markdown or JSON evidence from **Reports**.

## Optional Twilio voice alerts

Copy `.env.example` to `.env`, set `ALERT_MODE=twilio_voice`, and provide the Account SID (`TWILIO_ACCOUNT_SID`, beginning with `AC`), API Key SID (`TWILIO_API_KEY_SID`, beginning with `SK`), `TWILIO_API_KEY_SECRET`, `TWILIO_FROM_NUMBER`, and `ALERT_TO_NUMBER`. `TWILIO_AUTH_TOKEN` is supported as a local fallback when API-key credentials are not configured. Phone numbers must use E.164 format, such as `+14155550123`. Keep `.env` private; it is ignored by Git.

When a blocked Workspace action or a confirmed vulnerable Attack Lab baseline creates an incident, CounterForge prepares one deduplicated alert. It does not call automatically. The operator must review the exact sanitized message and choose **Approve call**. The model cannot select the recipient, access credentials, or approve its own alert. Provider failures are recorded on the incident without weakening containment.

Twilio trial accounts may require the destination to be verified. An `Accepted` result means Twilio accepted the API request; it does not prove a person answered. Start the application normally after saving `.env`.

## Validation

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
npm --prefix frontend run build
```

Tests cover observable fixture breaches, protected output, useful incident responses, adapter history isolation, approval expiry and payload validation, concurrent/duplicate dispatch, policy replay and rollback, reports, cross-site mutation rejection, and bounded event queues. CI runs the backend tests and frontend build on pushes and pull requests.

## Integration boundaries

The attacker and defender have independent prompts and histories, even when they share an OpenRouter key. Deterministic gates retain authority over tools, disclosure, approvals, and alert dispatch. Adaptive generation is limited to synthetic objectives and does not grant either hosted role access to local tools, arbitrary URLs, files, credentials, or the container runtime.

## Local boundary and data

This is a single-user development application, bound to loopback. It has no authentication or production deployment hardening. Keep it local. Tool fixtures cannot execute shell commands, read arbitrary files, or contact arbitrary URLs.

SQLite state is stored in `data/counterforge.sqlite`, excluded from Git. Set `COUNTERFORGE_STATE_DIR` to use another state directory; use a new directory for a fresh demo. Approval tokens are local operator metadata and never enter model history. Protected fixture output is checked before release, and reports redact the synthetic marker.

Source layout: `backend/` for API, policies, workflow, and fixtures; `frontend/` for the interface; `tests/` for backend verification; `design/` for original concept mockups and live screenshots. [PLAN.md](PLAN.md) retains the broader architecture research.
