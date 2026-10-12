SCENARIO_NAMES = {
    "all": "Full security check",
    "runbook-injection": "Runbook check",
    "tool-result-injection": "Tool-result check",
    "role-escalation": "Authority check",
    "data-extraction": "Context check",
}


def run_name(run):
    if run.get("name"):
        return run["name"]
    persona = (run.get("target") or {}).get("persona", "incident")
    label = {"incident": "Incident", "support": "Support", "research": "Knowledge"}.get(persona, "Agent")
    return f"{label} · {SCENARIO_NAMES.get(run.get('scenario'), 'Security check')}"
