# CounterForge

An incident-response assistant and agent-defense lab for CrowdStrike Track 3. Investigate a synthetic incident, catch a poisoned runbook attempting an unauthorized export, and replay attacks against a versioned tool policy. CounterForge builds on [Redforge](https://github.com/thesid42/Redforge); the reuse map is in [PROVENANCE.md](PROVENANCE.md).

**Current build: executable local demo.** The assistant and attacker use deterministic fixtures. No LLM endpoint, external export, PagerDuty alert, or phone call is invoked. The UI and reports label this explicitly. Credentials are unnecessary.

![CounterForge workspace, implemented local demo](design/counterforge-live-workspace.jpg)

## What works

- Incident chat with persistent conversations, synthetic runbooks, draft updates, and a security timeline.
- Four attack fixtures: runbook injection, tool-result injection, operator impersonation, and protected-context extraction.
- A LangGraph workflow: generate → execute → inspect → propose → replay. Each attack runs against disposable in-memory state; verdicts use actual fixture output and simulated tool side effects.
- Baseline/defended traces, two held-out fixture variants, and four benign tool-permission checks. These are fixture checks, not measurements of real-model robustness or semantic prompt resistance.
- Operator activation of validated policies, stale-candidate rejection, rollback, and monotonic policy versions.
- Action-bound paging approvals with expiry, recipient allowlisting, duplicate suppression, and rate limiting. Accepted notifications are simulated; acknowledgment and resolution are operator actions.
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

## Demo walkthrough

1. In **Workspace**, enable **Use injected runbook**, then click **Investigate the outage**. The legitimate response remains useful; the security timeline shows the denied export.
2. Click **Review action**, inspect the recipient, exact text, expiry, and policy version, then **Approve simulation**.
3. In **Incidents**, acknowledge the simulated page and resolve the incident. No external call occurs.
4. In **Attack lab**, choose **All attack surfaces** and **Run comparison**. Inspect matching baseline/defended traces and the replay evidence.
5. Review the candidate rule, **Activate in local lab**, then inspect **Defenses**. Rollback remains available.
6. Download the Markdown or JSON evidence from **Reports**.

## Validation

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
npm --prefix frontend run build
```

Tests cover observable fixture breaches, protected output, useful incident responses, adapter history isolation, approval expiry and payload validation, concurrent/duplicate dispatch, policy replay and rollback, reports, cross-site mutation rejection, and bounded event queues. CI runs the backend tests and frontend build on pushes and pull requests.

## Integration phase

The intended attacker uses a hosted GLM endpoint. GLM may also provide defense analysis in a separate session; deterministic gates retain authority over tools, disclosure, approvals, and dispatch. `.env.example` records proposed configuration names only: this build does not load or implement those endpoint settings. `backend/models.py` defines the adapter contract and an explicit unconfigured endpoint adapter.

Next implementation steps:

1. Add the GLM client, structured attack/tool schemas, bounded retries, cost limits, and independent attacker/defender histories.
2. Connect the CrowdStrike target through a target adapter. A supplied model or container can run locally; an API-only target remains remote.
3. Implement process/container isolation with resource limits, restricted network access, synthetic data, and separate credentials. Current fixture state isolation is **not** an OS sandbox and must not execute arbitrary tools or supplied model code.
4. Add PagerDuty Events or Twilio voice behind the existing approval boundary, with verified provider callbacks and durable delivery records.

## Local boundary and data

This is a single-user development application, bound to loopback. It has no authentication or production deployment hardening. Keep it local. Tool fixtures cannot execute shell commands, read arbitrary files, or contact arbitrary URLs.

SQLite state is stored in `data/counterforge.sqlite`, excluded from Git. Set `COUNTERFORGE_STATE_DIR` to use another state directory; use a new directory for a fresh demo. Approval tokens are local operator metadata and never enter model history. Protected fixture output is checked before release, and reports redact the synthetic marker.

Source layout: `backend/` for API, policies, workflow, and fixtures; `frontend/` for the interface; `tests/` for backend verification; `design/` for original concept mockups and live screenshots. [PLAN.md](PLAN.md) retains the broader architecture research.
