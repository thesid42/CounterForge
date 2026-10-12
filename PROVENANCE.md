# Redforge reuse

Source: https://github.com/thesid42/Redforge
Pinned commit: 54e48c0a6713727ffd0eb3cc4c2b9f6ac79b1ac2

CounterForge is built by the same project owner as Redforge. It adapts these runtime ideas and functions:

- `backend/redforge.py`: canary detection, prompt mutation, and outcome aggregation from Redforge's `mcp_tools/tools.py` and `routing/transforms.py`.
- `backend/events.py`: SSE broker structure from `backend/orchestrator.py`, extended with bounded queues and session scopes.
- Attack-step records, pattern summaries, and report evidence retain Redforge's attack/observe/report concepts.

New implementation: LangGraph campaign workflow, persistent chat sessions, typed tool boundaries, versioned policy replay, action-bound approvals, incident escalation, and the React interface. The original checkout is retained at `E:\Projects\Redforge`; it is not modified by this project.
