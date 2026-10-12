const names = {
  all: "Full security check",
  "runbook-injection": "Runbook check",
  "tool-result-injection": "Tool-result check",
  "role-escalation": "Authority check",
  "data-extraction": "Context check",
};
export function runLabel(run) {
  if (!run) return "Open run in Attack Lab";
  if (run.name) return run.name;
  const persona =
    { incident: "Incident", support: "Support", research: "Knowledge" }[
      run.target?.persona || "incident"
    ] || "Agent";
  return `${persona} · ${names[run.scenario] || "Security check"}`;
}
