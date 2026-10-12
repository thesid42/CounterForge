import { useEffect, useState } from "react";
import {
  CheckCircle2,
  ChevronDown,
  Clock3,
  FlaskConical,
  Loader2,
  Shield,
  TriangleAlert,
} from "lucide-react";
import "./attack-lab.css";
import { runLabel } from "./runNames";

const STEPS = ["Prepare", "Test attacks", "Check defense"];
const STAGE_LABELS = {
  queued: "Waiting to start…",
  generate: "Preparing attacks…",
  execute: "Testing the target…",
  inspect: "Reviewing findings…",
  propose: "Preparing a defense…",
  replay: "Checking the defense…",
};
function Outcome({ value }) {
  const verdict = value?.verdict;
  const label =
    {
      succeeded: "Breach",
      blocked: "No breach",
      error: "Error",
      skipped: "Skipped",
    }[verdict] || "Pending";
  return <span className={`al-outcome ${verdict || "pending"}`}>{label}</span>;
}
function TextPreview({ text, empty = "Waiting for the target response…" }) {
  const [expanded, setExpanded] = useState(false);
  const value = text || empty;
  const long = value.length > 420;
  return (
    <>
      <pre className="al-evidence-text">
        {long && !expanded ? value.slice(0, 420) + "…" : value}
      </pre>
      {long && (
        <button
          type="button"
          className="cf-text-button"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Show less" : "Show full text"}
        </button>
      )}
    </>
  );
}
function responseText(value) {
  if (!value) return "";
  const text = value.response_content || value.output || "";
  const calls = value.tool_calls?.length
    ? "\nTool requests: " +
      value.tool_calls
        .map((c) => `${c.name}(${JSON.stringify(c.arguments)})`)
        .join("; ")
    : "";
  return text + calls;
}

function BatchAttack({
  overview,
  scenario,
  applyDefense,
  locked,
  openRun,
  sessionId,
  selectedBatchId,
}) {
  const bots = (overview.targets || []).filter((t) => t.adapter === "dvaa");
  const [picked, setPicked] = useState([]);
  const [batch, setBatch] = useState(null);
  const [error, setError] = useState("");
  const live = batch?.status === "running";
  const allPicked = bots.length > 0 && picked.length === bots.length;
  useEffect(() => {
    fetch(selectedBatchId ? "/api/lab/batches/" + selectedBatchId : "/api/lab/batches")
      .then((r) => r.json())
      .then((value) => { if (selectedBatchId) setBatch(value); else if (value?.[0]) setBatch(value[0]); })
      .catch(() => {});
  }, [selectedBatchId]);
  useEffect(() => {
    if (!live) return;
    const timer = setInterval(async () => {
      const next = await fetch("/api/lab/batches/" + batch.id).then((r) =>
        r.json(),
      );
      setBatch(next);
    }, 3000);
    return () => clearInterval(timer);
  }, [live, batch?.id]);
  const toggle = (id) =>
    setPicked((cur) =>
      cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id],
    );
  async function launch() {
    setError("");
    const res = await fetch("/api/lab/batches", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_ids: picked,
        scenario,
        apply_defense: applyDefense,
        workspace_session_id: sessionId || null,
      }),
    });
    const body = await res.json();
    if (!res.ok) return setError(body.detail || "Could not start the batch");
    setBatch(body);
  }
  return (
    <section className="panel al-batch" aria-label="Attack multiple bots">
      <div className="al-batch-head">
        <div className="al-batch-title">
          <h3>Attack multiple DVAA bots at once</h3>
          <p className="muted">
            Run the selected attack surface against several bots in parallel.
          </p>
        </div>
        <div className="al-batch-actions">
          <span className="al-batch-count" aria-live="polite">
            <strong>{picked.length}</strong> of {bots.length} selected
          </span>
          <button
            type="button"
            className="cf-text-button al-select-all"
            disabled={live || locked}
            onClick={() => setPicked(allPicked ? [] : bots.map((b) => b.id))}
          >
            {allPicked ? "Clear selection" : `Select all ${bots.length}`}
          </button>
          <button
            className="button primary"
            disabled={!picked.length || live || locked}
            onClick={launch}
          >
            {live ? (
              <Loader2 size={16} className="spin" />
            ) : (
              <FlaskConical size={16} />
            )}
            {live
              ? "Running batch…"
              : picked.length
                ? `Attack ${picked.length} ${picked.length === 1 ? "bot" : "bots"}`
                : "Run batch"}
          </button>
        </div>
      </div>
      <div className="al-batch-grid">
        {bots.map((b) => {
          const name = b.name.replace("DVAA ", "");
          const selected = picked.includes(b.id);
          return (
            <label
              key={b.id}
              className={"al-batch-bot " + (selected ? "on" : "")}
            >
              <input
                type="checkbox"
                checked={selected}
                disabled={live || locked}
                onChange={() => toggle(b.id)}
                aria-label={`Select ${name} on port ${b.port}`}
              />
              <span className="al-batch-bot-copy">
                <strong title={name}>{name}</strong>
                <small>
                  Port {b.port}
                  <span className={"lvl " + b.security_level}>
                    {b.security_level}
                  </span>
                </small>
              </span>
            </label>
          );
        })}
      </div>
      {error && <p className="al-batch-error">{error}</p>}
      {batch && (
        <details className="al-batch-results" open={live || undefined}>
          <summary>
            <span>
              {live ? (
                <Loader2 size={14} className="spin" />
              ) : (
                <CheckCircle2 size={14} />
              )}
              {live ? "Batch in progress" : "Latest batch results"}
            </span>
            <small>{batch.runs.length} bots</small>
            <ChevronDown size={14} />
          </summary>
          <div className="al-batch-table-wrap">
            <table className="al-batch-table">
              <thead>
                <tr>
                  <th>Bot</th>
                  <th>Status</th>
                  <th>Breaches</th>
                  <th>{batch.apply_defense ? "No breach with defense" : "No breach on repeat"}</th>
                  <th>Alert</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {batch.runs.map((r) => (
                  <tr key={r.run_id}>
                    <td>
                      {(r.target || "").replace("DVAA ", "")}{" "}
                      <small>:{r.port}</small>
                    </td>
                    <td>
                      {["running", "batched"].includes(r.status) ? (
                        <span className="al-batch-status">
                          <Loader2 size={13} className="spin" />{" "}
                          {STAGE_LABELS[r.stage] || "Waiting…"}
                        </span>
                      ) : r.status === "failed" ? (
                        <span className="al-outcome error">Failed</span>
                      ) : (
                        <span className="al-outcome blocked">Done</span>
                      )}
                    </td>
                    <td>
                      {r.attacks ? (
                        <span
                          className={
                            "al-outcome " +
                            (r.breaches ? "succeeded" : "blocked")
                          }
                        >
                          {r.breaches}/{r.attacks}
                        </span>
                      ) : (
                        "–"
                      )}
                    </td>
                    <td>
                      {r.attacks ? `${r.blocked_after}/${r.attacks}` : "–"}
                    </td>
                    <td>
                      {r.page === "Accepted"
                        ? batch.page?.mode === "simulated" ? "Simulated" : "Accepted"
                        : r.page === "Suppressed"
                          ? "Suppressed"
                          : "–"}
                    </td>
                    <td>
                      {r.status === "completed" && (
                        <button
                          type="button"
                          className="cf-text-button"
                          onClick={() => openRun(r.run_id)}
                        >
                          Open
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </section>
  );
}

export default function AttackLab({
  overview,
  sessionId,
  run,
  result,
  selectedResult,
  setSelectedResult,
  scenario,
  setScenario,
  scenarios,
  applyDefense,
  setApplyDefense,
  busy,
  startRun,
  openRun,
  resumeRunChat,
  clearDefense,
  activate,
  viewRule,
  traces,
  attackLabel,
  targetId,
  setTargetId,
  rounds,
  setRounds,
  registerTarget,
}) {
  const [registration, setRegistration] = useState({
    name: "",
    persona: "incident",
    model: "qwen2.5:3b",
    base_url: "http://127.0.0.1:11434/v1",
    auto_run: true,
  });
  const activeRun = overview.runs.find((r) =>
    ["queued", "running"].includes(r.status),
  );
  const running = ["queued", "running"].includes(run?.status);
  const locked = busy || running || !!activeRun;
  const rows = run?.results || [];
  const completed = run?.status === "completed";
  const legacyLive =
    (run?.mode?.includes("dvaa") ||
      rows.some((r) => r.baseline?.mode === "dvaa")) &&
    (!run?.adaptive || !rows.every((r) => r.defended?.defense_supported));
  const canActivate =
    completed &&
    run.validated &&
    !legacyLive &&
    !run.activated &&
    run.base_version === overview.policy.version;
  const stageIndex = ["queued", "generate"].includes(run?.stage)
    ? 0
    : ["execute", "inspect"].includes(run?.stage)
      ? 1
      : 2;
  const breaches = rows.filter(
    (r) => r.baseline?.verdict === "succeeded",
  ).length;
  const afterBreaches = rows.filter(
    (r) => r.defended?.verdict === "succeeded",
  ).length;
  const pending = rows.some(
    (r) =>
      !r.defended ||
      ["error", "skipped"].includes(r.defended.verdict) ||
      r.baseline?.verdict === "error",
  );

  const selectedTarget = overview.targets?.find((t) => t.id === targetId);
  const rulesOn = run?.apply_defense !== false;
  const afterLabel = legacyLive
    ? "Replay"
    : rulesOn
      ? "Rules on"
      : "Rules off · repeat";
  return (
    <div className="attack-lab">
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <FlaskConical size={14} /> ATTACK LAB
          </div>
          <h1>
            Test your defenses<span className="title-dot">.</span>
          </h1>
          <p>
            Choose what to test. See what happened before and after defense.
          </p>
        </div>
      </div>

      <section className="panel al-launch" aria-label="New evaluation">
        <div className="al-target-row">
          <div className="al-scenario">
            <label htmlFor="lab-target">Target agent</label>
            <select
              id="lab-target"
              value={targetId}
              disabled={locked}
              onChange={(e) => {
                setTargetId(e.target.value);
                setApplyDefense(false);
              }}
            >
              <optgroup label="DVAA personas (live fleet)">
                {(overview.targets || [])
                  .filter((t) => t.adapter === "dvaa")
                  .map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name.replace("DVAA ", "")} · :{t.port} ·{" "}
                      {t.security_level?.toUpperCase()}
                    </option>
                  ))}
              </optgroup>
              <optgroup label="CounterForge agents">
                {(overview.targets || [])
                  .filter((t) => t.adapter !== "dvaa")
                  .map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name} · {t.model}
                    </option>
                  ))}
              </optgroup>
            </select>
          </div>
          <label className="al-rules-toggle">
            <input
              type="checkbox"
              checked={applyDefense}
              disabled={locked}
              onChange={(e) => setApplyDefense(e.target.checked)}
            />
            <Shield size={15} />
            {applyDefense ? "Defense rules on" : "Defense rules off"}
          </label>
        </div>
        <p className="al-persona-note">
          {(selectedTarget?.adapter === "dvaa" &&
            `${selectedTarget.description} (DVAA on :${selectedTarget.port})`) ||
            overview.personas?.[selectedTarget?.persona]?.description ||
            "Select a registered local target."}
        </p>
        <div className="al-launch-row">
          <div className="al-scenario">
            <label htmlFor="lab-scenario">Attack surface</label>
            <select
              id="lab-scenario"
              value={scenario}
              disabled={locked}
              onChange={(e) => setScenario(e.target.value)}
            >
              {scenarios.map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          </div>
          <button
            className="button primary"
            disabled={locked}
            onClick={startRun}
          >
            {locked ? (
              <Loader2 size={16} className="spin" />
            ) : (
              <FlaskConical size={16} />
            )}
            {running || activeRun ? "Run in progress" : "Run test"}
          </button>
        </div>
        <p className="al-launch-note">
          <Shield size={14} />
          {applyDefense
            ? "Includes a defense comparison"
            : "Tests the same payload again without defense rules"}
          <span>
            ·{" "}
            {overview.lab_ready
              ? "Live target"
              : overview.mode === "demo"
                ? "Fixture simulation"
                : "Target setup required"}
          </span>
        </p>
        {!overview.lab_ready && overview.mode !== "demo" && (
          <p className="al-setup-note">
            Complete target and model setup in Settings before running a test.
          </p>
        )}
        <details className="al-advanced">
          <summary>
            Advanced options <ChevronDown size={14} />
          </summary>
          <div className="al-options">
            <label>
              Autonomous rounds{" "}
              <select
                aria-label="Autonomous rounds"
                value={rounds}
                disabled={locked}
                onChange={(e) => setRounds(Number(e.target.value))}
              >
                {[1, 2, 3].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
            <p>
              Generate an attack, observe the target, propose a defense, and
              retest with a new strategy each round.
            </p>
            <p>
              Attacker: {overview.attacker_model || "Not configured"}
              <br />
              Defender: {overview.defender_model || "Not configured"} ·{" "}
              {overview.attack_rounds || 1} rounds
            </p>
            {overview.active_defense?.system_prompt && (
              <button
                className="button"
                disabled={locked}
                onClick={clearDefense}
              >
                Clear saved defense
              </button>
            )}
          </div>
        </details>
      </section>

      <BatchAttack
        overview={overview}
        scenario={scenario}
        applyDefense={applyDefense}
        locked={locked}
        openRun={openRun}
        sessionId={sessionId}
        selectedBatchId={run?.batch_id}
      />

      <details className="panel al-register">
        <summary>
          Register a new agent <ChevronDown size={14} />
        </summary>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            const value = await registerTarget({
              ...registration,
              scenario,
              apply_defense: applyDefense,
              rounds,
            });
            if (value) setRegistration((current) => ({ ...current, name: "" }));
          }}
        >
          <label>
            Agent name
            <input
              required
              maxLength={80}
              value={registration.name}
              onChange={(e) =>
                setRegistration({ ...registration, name: e.target.value })
              }
            />
          </label>
          <label>
            Persona
            <select
              value={registration.persona}
              onChange={(e) =>
                setRegistration({ ...registration, persona: e.target.value })
              }
            >
              {Object.entries(overview.personas || {}).map(([id, p]) => (
                <option key={id} value={id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Model
            <select
              value={registration.model}
              onChange={(e) =>
                setRegistration({ ...registration, model: e.target.value })
              }
            >
              <option>qwen2.5:3b</option>
              <option>llama3.2:3b</option>
            </select>
          </label>
          <label>
            Local model endpoint
            <input
              required
              value={registration.base_url}
              onChange={(e) =>
                setRegistration({ ...registration, base_url: e.target.value })
              }
            />
          </label>
          <label className="al-auto-register">
            <input
              type="checkbox"
              checked={registration.auto_run}
              onChange={(e) =>
                setRegistration({ ...registration, auto_run: e.target.checked })
              }
            />{" "}
            Start the security loop automatically
          </label>
          <button className="button primary" disabled={busy}>
            {registration.auto_run ? "Register & test" : "Register agent"}
          </button>
        </form>
      </details>

      {activeRun && !running && (
        <div className="al-active-notice" role="status">
          Another test is running.{" "}
          <button
            className="text-link"
            disabled={busy}
            onClick={() => openRun(activeRun.id)}
          >
            View progress
          </button>
        </div>
      )}
      {running && (
        <section className="panel al-progress" role="status" aria-live="polite">
          <strong>
            <Loader2 size={17} className="spin" />
            {STAGE_LABELS[run.stage] || "Test in progress…"}
          </strong>
          <ol>
            {STEPS.map((step, i) => (
              <li
                key={step}
                className={
                  i === stageIndex ? "current" : i < stageIndex ? "done" : ""
                }
              >
                <span>
                  {i < stageIndex ? <CheckCircle2 size={14} /> : i + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>
          <button className="button" onClick={() => resumeRunChat(run.id)}>
            Continue in chat
          </button>
        </section>
      )}
      {run?.status === "failed" && (
        <div className="al-failure" role="alert">
          <TriangleAlert size={17} />
          <div>
            <strong>Test stopped early</strong>
            <p>
              {run.error || "The evaluation could not be completed."} Partial
              results are inconclusive.
            </p>
          </div>
        </div>
      )}

      {rows.length > 0 ? (
        <section className="panel al-results">
          <div className="al-results-heading">
            <div>
              <h2>{completed ? "Test results" : "Results so far"}</h2>
              <p>
                {completed
                  ? `${rows.length} attacks · ${breaches} baseline breaches · ${pending ? "Comparison incomplete" : `${afterBreaches} replay breaches`}`
                  : "Results appear as each stage finishes."}
              </p>
            </div>
            <span className="al-run-id">{runLabel(run)}</span>
            <button
              className="button"
              onClick={() => resumeRunChat(run.id)}
              disabled={busy}
            >
              Continue in chat
            </button>
          </div>
          {run?.page && (
            <p className="al-limitation" role="status">
              {run.page.mode === "simulated"
                ? "Simulated alert"
                : "Voice alert"}
              :{" "}
              {run.page.status === "Accepted"
                ? "accepted"
                : run.page.status === "Suppressed"
                  ? "suppressed by the recent-page cooldown"
                  : "failed"}
              .
            </p>
          )}
          {legacyLive && (
            <p className="al-limitation">
              DVAA replay does not verify an applied model defense. Historical
              gateway labels may reflect filtering after execution.
            </p>
          )}
          <div className="al-result-layout">
            <div
              className="al-result-list"
              role="group"
              aria-label="Attack results"
            >
              <div className="al-column-labels">
                <span>Attack</span>
                <span>Rules off</span>
                <span>
                  {legacyLive ? "Replay" : rulesOn ? "Rules on" : "Repeat"}
                </span>
              </div>
              {rows.map((r, i) => (
                <button
                  key={r.id}
                  className={`al-result-row ${selectedResult === i ? "selected" : ""}`}
                  aria-pressed={selectedResult === i}
                  onClick={() => setSelectedResult(i)}
                >
                  <span className="al-attack-name">
                    {attackLabel(r, run.scenario)}
                    {r.round && <small>Round {r.round}</small>}
                  </span>
                  <Outcome value={r.baseline} />
                  <Outcome value={r.defended} />
                </button>
              ))}
            </div>
            <div className="al-finding">
              {result && (
                <>
                  <h3>{attackLabel(result, run.scenario)}</h3>
                  <div className="al-finding-evidence">
                    <small>Rules off</small>
                    <Outcome value={result.baseline} />
                    <p>
                      {result.baseline?.reason ||
                        "Waiting for the baseline result."}
                    </p>
                  </div>
                  <div className="al-finding-evidence">
                    <small>{afterLabel}</small>
                    <Outcome value={result.defended} />
                    <p>
                      {result.defended?.reason || "Waiting for the comparison."}
                    </p>
                  </div>
                  <p className="al-model-behavior">
                    {run.target_model ||
                      run.target?.model ||
                      "Model not recorded"}
                    {run.target?.persona
                      ? ` · ${overview.personas?.[run.target.persona]?.name || run.target.persona}`
                      : ""}
                  </p>
                  {result.strategy && (
                    <p className="al-strategy">
                      {result.strategy.length > 180
                        ? result.strategy.slice(0, 180) + "…"
                        : result.strategy}
                    </p>
                  )}
                  {result.defense?.rationale && (
                    <details className="al-rationale">
                      <summary>
                        Defense explanation <ChevronDown size={14} />
                      </summary>
                      <p>{result.defense.rationale}</p>
                    </details>
                  )}
                </>
              )}
            </div>
          </div>
          {result && (
            <div
              className="al-payload-comparison"
              key={`payload-${run.id}-${result.id}`}
            >
              <div className="al-payload">
                <h3>Attack payload</h3>
                <TextPreview
                  text={result.baseline?.request_content || result.payload}
                  empty="Payload was not recorded."
                />
              </div>
              <div className="al-response-pair">
                {[
                  ["Rules off", result.baseline],
                  [afterLabel, result.defended],
                ].map(([label, value]) => (
                  <section key={label} className="al-response">
                    <div>
                      <h3>Target response · {label}</h3>
                      <Outcome value={value} />
                    </div>
                    <TextPreview text={responseText(value)} />
                    {value?.model_verdict && (
                      <p className="al-model-behavior">
                        Model behavior:{" "}
                        {value.model_verdict === "succeeded"
                          ? "unsafe reply or tool request"
                          : value.model_verdict === "error"
                            ? "request failed"
                            : "no unsafe behavior observed"}
                        {value.defense_enforced
                          ? " · tool/output gate intervened"
                          : ""}
                      </p>
                    )}
                  </section>
                ))}
              </div>
            </div>
          )}
          <details className="al-traces" key={`traces-${run.id}-${result?.id}`}>
            <summary>
              View full execution traces <ChevronDown size={14} />
            </summary>
            <div className="comparison-grid">{traces}</div>
          </details>
          {completed && (
            <div className="al-results-actions">
              <span>
                <Shield size={15} />
                {run.activated
                  ? "Policy activated"
                  : legacyLive
                    ? "Defense unverified"
                    : run.validated
                      ? "Passed recorded checks"
                      : "Review findings before activating"}
              </span>
              <div>
                <a className="text-link" href={`/api/reports/${run.id}`}>
                  Export report
                </a>
                {run.candidate && (
                  <button className="button" onClick={viewRule}>
                    Review defense
                  </button>
                )}
                {canActivate && (
                  <button
                    className="button primary"
                    disabled={busy}
                    onClick={activate}
                  >
                    Activate policy
                  </button>
                )}
              </div>
            </div>
          )}
        </section>
      ) : (
        !running && (
          <section className="panel al-empty">
            <FlaskConical size={28} />
            <h2>
              {run?.status === "failed"
                ? "No results recorded"
                : "Ready for your first test"}
            </h2>
            <p>
              Run a test above to find weaknesses and check the proposed
              defense.
            </p>
            <ol>
              <li>
                <span>1</span>Choose an attack surface
              </li>
              <li>
                <span>2</span>Run the test
              </li>
              <li>
                <span>3</span>Review the comparison
              </li>
            </ol>
          </section>
        )
      )}

      <details className="al-history panel">
        <summary>
          <span>
            <Clock3 size={16} /> Previous runs
          </span>
          <span>
            {overview.runs.length} saved <ChevronDown size={14} />
          </span>
        </summary>
        <div className="al-history-list">
          {overview.runs.length ? (
            overview.runs.map((item) => (
              <button
                key={item.id}
                className={`al-history-row ${run?.id === item.id ? "selected" : ""}`}
                disabled={busy}
                onClick={() => openRun(item.id)}
              >
                <div>
                  <strong>{runLabel(item)}</strong>
                  <small>
                    {item.created_at
                      ? new Date(item.created_at).toLocaleString()
                      : "Time not recorded"}
                  </small>
                </div>
                <span>
                  {item.status === "running"
                    ? "In progress"
                    : item.status === "failed"
                      ? "Failed"
                      : "Complete"}
                </span>
              </button>
            ))
          ) : (
            <p>No saved runs yet.</p>
          )}
        </div>
      </details>
      <p className="al-footer">
        Results apply to this lab run. Errors and skipped replays leave the
        comparison incomplete.
      </p>
    </div>
  );
}
