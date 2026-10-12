# CounterForge

An incident-response assistant and agent-defense lab for CrowdStrike Track 3. Investigate a synthetic incident, catch a poisoned runbook attempting an unauthorized export, and replay attacks against a versioned tool policy. CounterForge builds on [Redforge](https://github.com/thesid42/Redforge); the reuse map is in [PROVENANCE.md](PROVENANCE.md).

**Current build: executable local demo plus an optional adaptive model lab.** Demo mode uses deterministic fixtures. Live mode can use OpenRouter-backed attacker and defender roles against localhost persona targets or the legacy DVAA/Ollama target. Breach alerts are automatic by default, with a cooldown, and are simulated unless `ALERT_MODE=twilio_voice` is configured.

![Ask CounterForge with a fresh chat and no run selected](design/counterforge-chat.jpg)

## What works

- One CounterForge chat with persistent conversations, text configuration, security-test launches, and explanations of saved evidence.
- A simplified Workspace with chat, readable run names, and a run activity list that opens detailed results in Attack Lab. Configure and launch bounded tests through text; the evidence analyst explains results in plain language.
- Four bounded attack objectives: runbook injection, tool-result injection, operator impersonation, and protected-context extraction. In adaptive mode, an attacker model creates new prompts over multiple rounds using redacted observations of the local target's behavior.
- A LangGraph workflow: generate → execute → inspect → propose → replay. Persona agents receive the defender's rules before replay, with tool checks applied before execution. The UI distinguishes unsafe model replies from actions stopped by enforcement.
- Incident, support, and knowledge-assistant personas with different tools. Registering a target queues an autonomous security loop by default; manual start is also available. Later attempts use baseline and replay feedback plus strategies from earlier runs.
- The same payload and actual redacted target responses shown side by side, with defense rules on or off. Autonomous validation covers recorded attacks and one legitimate persona task; it is not a held-out robustness score.
- Operator activation of validated policies, stale-candidate rejection, rollback, and monotonic policy versions.
- Automatic breach paging with a fixed sanitized message and a cooldown between calls. Manual paging retains action-bound approval, expiry, recipient allowlisting, and duplicate suppression. Notifications are simulated by default or sent as Twilio voice calls when configured; acknowledgment and resolution remain operator actions.
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

Persona targets use a local OpenAI-compatible model endpoint, defaulting to Ollama at `http://127.0.0.1:11434/v1`. They expose only disposable, synthetic tools. The legacy DVAA adapter remains available; its endpoint ignores incoming system defenses, so those replays are repeated probes and cannot validate a defense. To enable the two hosted roles, add one OpenRouter key to the ignored `.env` file:

```env
OPENROUTER_API_KEY=
ATTACKER_BASE_URL=https://openrouter.ai/api/v1
ATTACKER_MODEL=z-ai/glm-5.3-flash
DEFENDER_BASE_URL=https://openrouter.ai/api/v1
DEFENDER_MODEL=z-ai/glm-5.3-flash
ADAPTIVE_ATTACK_ROUNDS=2
```

`ATTACKER_API_KEY` and `DEFENDER_API_KEY` are optional per-role overrides. If they are empty, both roles use `OPENROUTER_API_KEY`. Restart the backend after changing `.env`. Role prompts and target responses are bounded and redacted before persistence; API keys are used only in authorization headers and are never placed in model prompts or reports.

In **Attack lab**, choose a persona target and the visible **Defense rules** toggle. Expand **Register new agent** to set a local model, persona, and endpoint. Leave automatic evaluation enabled to queue the attack/defense loop on registration, or disable it and use **Run test** later. New registrations wait for the current run; registering the identical target again does not duplicate its run. **Advanced options** controls the one-to-three attempt limit. Rules-off runs repeat each payload without the proposed defense, while rules-on runs compare an unprotected baseline with a protected replay.

## Workspace chat

**Ask CounterForge** is the only Workspace chat. There is no separate incident demo chat or analyst label. Each new chat starts with **No run selected**. Select a readable name such as **Support · Context check 13** in **Run activity** to load its saved conversation, including its launch, follow-up questions, and automatic summary. Selecting another run switches to that run's conversation. Return to a running test to see its live progress and eventual summary; switching away does not stop it. Click the selected run again, or use **Clear selected run** beside the composer, to unselect it. The arrow beside each run opens its payloads, target responses, and advanced results in Attack Lab. **Continue in chat** returns to that run's conversation. Opening Attack Lab does not change the chat's selection.

Run selection belongs to each conversation and survives switching chats or reloading the page. Starting a test selects the newly created run. An unselected chat never silently uses the latest saved run; explicitly ask about the latest run or recent comparisons to access that evidence. User messages and their person icons sit on the right; CounterForge replies sit on the left. The input clears immediately on send; a failed request restores the draft without overwriting a newer draft.

Runs started from chat, Attack Lab, or agent registration post a short completion summary to the originating conversation automatically. The summary describes the attack methods, observed leaks or unauthorized actions, the defense comparison when available, and alert delivery. Progress appears while a watched run is active. Failed or incomplete checks are identified, and each completion is saved once, including after reconnecting or reloading. You do not need to ask for status, and clearing a selection does not reattach it when a summary arrives. Summaries use recorded results and remain available without an analyst provider connection.

Configure chat runs through text. Selectors, toggles, and advanced controls remain in Attack Lab. Chat preferences persist per conversation.

| Say this in chat | Result |
| --- | --- |
| Use the support assistant, defense off, one round, context check. | Save the setup without starting a run. |
| Start a new run. | Launch a test with the saved setup. |
| Run the knowledge assistant with defense on, one round, context check. | Configure and launch a test in one message. |
| Show settings. | Show the current chat setup. |
| Disable chat runs. / Enable chat runs. | Pause or allow launches from this conversation. Attack Lab remains available. |
| What happened in this run? | Explain the selected run; if none is selected, ask you to choose one. |
| Explain the latest run. | Explicitly select and explain the latest saved run. |
| Give details comparing the six latest checks. | Compare the six most recent saved runs using their recorded evidence. |
| Keep replies brief. / Use detailed replies. | Set the preferred explanation length. |

Supported personas are incident, support, and knowledge/research. Test surfaces include runbook, tool-result, authority, context, and all surfaces. Runs are limited to one through three rounds. Direct run and configuration commands are parsed by the server; saved evidence and analyst output cannot launch a run or change settings.

The evidence analyst uses a fixed system prompt in `backend/console.py` for consistent, everyday language. Replies use one or two short sentences by default; ask for details for a longer explanation. It describes what the attack tried, what the target did, and whether defense changed the outcome when relevant. For example, it says “revealed the test secret” instead of “leaked the synthetic canary,” and distinguishes a target refusing a request from a defense blocking its tool. New and displayed historical replies have em dashes and en dashes removed. The analyst uses saved evidence and cannot claim overall safety from a successful recorded test.

## Demo walkthrough

1. Start a **New chat** in Workspace. Configure a short test, for example **Use the support assistant, defense off, one round, context check.** Then say **Start a new run**.
2. The newly created run becomes the chat's selection. A short attack summary appears automatically when it completes. Ask follow-up questions for more detail, or clear the selection to return to a general conversation.
3. Use the run's arrow in **Run activity** to open **Attack lab**. Choose a target, attack surface, and **Defense rules** setting, then **Run test**. Select an attack to see its payload and both responses; expand **View full execution traces** for the evidence. **Advanced options** contains attempt limits and saved-defense controls.
4. Ask CounterForge to compare recent runs, or select a particular run to discuss its evidence. A defense is credited only when that run's own unprotected attempt breached and the same payload with defense did not.
5. Choose **Review defense**, then **Activate policy** when the recorded checks pass. Inspect **Defenses**; rollback remains available. Older DVAA runs without an applied defense are labeled as repeated probes and cannot be activated.
6. Review any generated security incident and alert delivery in **Incidents**. Acknowledgment and resolution remain operator actions. Download Markdown or JSON evidence from **Reports**.

## Optional Twilio voice alerts

Copy `.env.example` to `.env`, set `ALERT_MODE=twilio_voice`, and provide the Account SID (`TWILIO_ACCOUNT_SID`, beginning with `AC`), API Key SID (`TWILIO_API_KEY_SID`, beginning with `SK`), `TWILIO_API_KEY_SECRET`, `TWILIO_FROM_NUMBER`, and `ALERT_TO_NUMBER`. `TWILIO_AUTH_TOKEN` is supported as a local fallback when API-key credentials are not configured. Phone numbers must use E.164 format, such as `+14155550123`. Keep `.env` private; it is ignored by Git.

When an Attack Lab run records a breach, the server automatically sends the fixed message “CounterForge alert. Breach detected. Check the CounterForge platform.” to the configured on-call number. `AUTO_PAGE_ON_BREACH=true` enables this behavior by default; set it to `false` to use manual review and **Approve call** instead. `BREACH_PAGE_COOLDOWN_SECONDS=600` suppresses consecutive breach calls for ten minutes. Twilio speech pauses briefly and repeats the alert once. The model cannot choose the recipient, change the alert message, or access credentials. Provider failures and cooldown suppression are recorded on the incident and run.

Twilio trial accounts may require the destination to be verified. An `Accepted` result means Twilio accepted the API request; it does not prove a person answered. Start the application normally after saving `.env`.

## Validation

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
npm --prefix frontend run build
```

Tests cover observable fixture breaches, protected output, useful incident responses, adapter history isolation, approval expiry and payload validation, automatic breach paging and cooldowns, policy replay and rollback, reports, cross-site mutation rejection, and bounded event queues. Workspace checks cover text configuration, bounded launches, explicit run selection and clearing, conversation isolation, automatic completion summaries and reconnect deduplication, readable run names, and the analyst's plain-language prompt and punctuation rule. Autonomous checks cover persona tools, defense enforcement before execution, feedback, and registration queues. The current repository has no CI workflow; run the commands above locally.

## Integration boundaries

The attacker and defender have independent prompts and histories, even when they share an OpenRouter key. Deterministic gates retain authority over tools, disclosure, approvals, and alert dispatch. Adaptive generation is limited to synthetic objectives and does not grant either hosted role access to local tools, arbitrary URLs, files, credentials, or the container runtime.

## Local boundary and data

This is a single-user development application, bound to loopback. It has no authentication or production deployment hardening. Keep it local. Tool fixtures cannot execute shell commands, read arbitrary files, or contact arbitrary URLs.

SQLite state is stored in `data/counterforge.sqlite`, excluded from Git. Set `COUNTERFORGE_STATE_DIR` to use another state directory; use a new directory for a fresh demo. Approval tokens are local operator metadata and never enter model history. Protected fixture output is checked before release, and reports redact the synthetic marker.

Source layout: `backend/` for API, policies, workflow, and fixtures; `frontend/` for the interface; `tests/` for backend verification; `design/` for original concept mockups and live screenshots. [PLAN.md](PLAN.md) retains the broader architecture research.
