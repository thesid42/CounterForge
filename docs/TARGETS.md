# Organizer target environments: CounterForge integration

Inspected October 12, 2026. DVAA source commit: `57918267d8d529ceec6d40fc9836ab09d128eee4` (package version 0.9.3). The local research checkout is ignored by Git. No vulnerable service was launched and no attack was sent to either linked website.

## Recommendation

Use **DVAA as the local target application**, with CounterForge as the attacker/defender controller and evidence interface. Use **DVLLM for guided examples and supplementary manual exercises** until its automation interface and local deployment are verified.

[DVLLM's public site](https://www.dvllm.com/) describes a hosted training platform with OWASP LLM exercises and account access. Its landing page does not establish a public testing API, downloadable weights, or a self-hosted package; those capabilities remain unverified. Do not treat a URL to that site as a model endpoint.

[DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent) supplies source, agent definitions, and local protocol servers. It is an agent application with an offline simulator and optional provider-backed responses, rather than a downloadable model.

## First demonstration

Start with **RAGBot** at `127.0.0.1:7005`. Its retrieved-document export scenario matches CounterForge's poisoned incident runbook. **RAGBot-AIM** at `127.0.0.1:7014` offers an upstream comparison for the same outbound tool path. Add ResearchBot's fetched-page injection later; defer MCP/A2A and persistent-memory scenarios until the first path is reproducible.

Use the upstream protected pair as a reference control. Our own defense should be demonstrated on a second copy of the same vulnerable target, with CounterForge's policy hook as the sole changed variable. Comparing unrelated agents cannot establish that our rule caused an improvement.

The inspected API accepts `POST /v1/chat/completions`; responses can include OpenAI-style tool calls plus `dvaa` execution metadata. Map attempts, execution, delivery results, and enforcement decisions into our trace schema. Preserve tool arguments privately and redact protected values before showing or exporting evidence.

## Attack → evidence → defense

1. The hosted GLM attacker receives the legitimate task, attack surface, bounded local tool inventory, and previous sanitized outcomes. It produces typed attack candidates; it cannot choose arbitrary external target URLs.
2. A DVAA adapter delivers the candidate to a pinned local target. The existing fixture runner remains available for offline rehearsal.
3. Observe the response and target-side tool events. A tool call in a completion is an attempted action, not proof of execution. Require a collector receipt containing the synthetic marker to prove exfiltration; absence of a receipt alone does not prove prevention.
4. The defender analyst proposes a typed rule from evidence. The trusted controller validates and replays it with benign requests and held-out attacks before operator activation.
5. Enforce the rule **inside the target before the outbound operation**. A completion proxy that inspects a reply after the target's internal tool has run cannot undo exfiltration. Hook the inspected `submit_to_index` execution boundary, or require tool execution to pass through our broker.
6. A blocked action creates a sanitized CounterForge incident. Existing expiring approvals govern escalation; live provider integration remains a separate phase.

Candidate controls: source authority, destination and data-class allowlists, disclosure checks, typed tool arguments, and approval-gated privileged actions. The rule must preserve the legitimate document-reading task. Generate and replay the same attack bytes against baseline and defended copies; reset target and collector state between runs.

## Model behavior and honest scoring

DVAA is offline and deterministic by default. Its [A/B demo documentation](https://github.com/opena2a-org/damn-vulnerable-ai-agent/blob/57918267d8d529ceec6d40fc9836ab09d128eee4/DEMO_BUILD.md) limits AIM's RAG claim to the outbound `submit_to_index` action; in-chat leaks remain possible. Its research-agent path keeps tool decisions deterministic even when an LLM narrates the result. Label this as tool-boundary validation, not evidence that an LLM selected or resisted the exploit.

For a real model attack/defense demonstration, explicitly connect a target model and use its structured tool decisions rather than merely asking it to narrate scripted decisions. The GLM attacker can remain hosted while the target application/tools stay local. Hosted target inference would still be remote inference; the UI must state that distinction.

The inspected [provider implementation](https://github.com/opena2a-org/damn-vulnerable-ai-agent/blob/57918267d8d529ceec6d40fc9836ab09d128eee4/src/llm/provider.js) directly calls OpenAI/Anthropic URLs; an arbitrary GLM endpoint is not exposed by that configuration. A generic endpoint adapter is needed for GLM target inference. Upstream provider failures can fall back to canned responses, so record the actual mode per request and exclude fallback results from live-model metrics.

## Isolation and prepared profile

`sandbox/compose.dvaa.yml` pins the inspected source and starts only the two RAG agents. It publishes loopback ports, uses an internal network, drops capabilities, limits resources, and supplies disposable writable `/tmp` storage. It mounts no host directories or Docker socket. This is a prepared profile, not a verified running sandbox: Docker CLI is installed on this workstation, but the Linux engine was unavailable during inspection.

```powershell
docker compose -f sandbox/compose.dvaa.yml config --quiet
docker compose -f sandbox/compose.dvaa.yml up --build -d
docker compose -f sandbox/compose.dvaa.yml down
```

Building needs network access to fetch source and dependencies. Runtime target egress is restricted by the internal network. Later, place a synthetic collector on that same network. Container `127.0.0.1` refers to the container itself, so the upstream host-loopback collector demo cannot be copied unchanged into this topology. The scoped profile has no upstream dashboard; CounterForge will use the agent APIs when its adapter is implemented.

Keep hosted GLM credentials and alert-provider credentials in the trusted controller. If target inference is hosted, add a narrow trusted model proxy rather than unrestricted target internet access. Before calling this runtime verified, test startup, health, permitted collector delivery, denied export, resets, resource limits, and benign task completion.

## Current implementation versus next work

CounterForge's chat, fixture loop, policy activation, approval workflow, and reports work today. DVAA is inspected and its deployment profile is prepared. The application is **not yet connected to DVAA**, and no DVAA results appear in our metrics.

Next work is the DVAA transport/trace adapter and disposable collector, then the CounterForge enforcement hook with matched replay. Add hosted GLM generation after credentials are available. Keep LangGraph as the controller; optionally use DVAA's bundled HackMyAgent to supply an independent attack suite once the primary demonstration works.
