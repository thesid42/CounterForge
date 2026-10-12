import { useEffect, useRef, useState } from "react";
import Workspace from "./Workspace";
import AttackLab from "./AttackLab";
import { runLabel } from "./runNames";
import {
  Activity,
  ArrowDownToLine,
  ArrowLeft,
  ArrowRight,
  Bell,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Circle,
  Clock3,
  FileText,
  FlaskConical,
  GitBranch,
  Home,
  Info,
  Loader2,
  LockKeyhole,
  MessageSquare,
  MoreHorizontal,
  Phone,
  RefreshCw,
  Settings2,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
  TriangleAlert,
  Undo2,
  X,
} from "lucide-react";

const NAV = [
  ["Workspace", Home],
  ["Attack lab", FlaskConical],
  ["Defenses", Shield],
  ["Incidents", Bell],
  ["Reports", FileText],
  ["Settings", Settings2],
];
const SCENARIOS = [
  ["all", "All attack surfaces"],
  ["runbook-injection", "Poisoned runbook"],
  ["tool-result-injection", "Tool-result injection"],
  ["role-escalation", "Operator impersonation"],
  ["data-extraction", "Protected-context extraction"],
];

const STAGE_COPY = {
  queued: {
    title: "Queued",
    detail: "Waiting to start the adaptive campaign.",
  },
  generate: {
    title: "Preparing attack objectives",
    detail: "Loading the scenario seeds for the attacker model.",
  },
  execute: {
    title: "Attacker probing the live target",
    detail:
      "The attacker model is crafting prompts and hitting DVAA. Watch for a baseline breach.",
  },
  inspect: {
    title: "Inspecting the breach",
    detail:
      "Summarizing tool use and target behavior from the unprotected run.",
  },
  propose: {
    title: "Defender writing protection",
    detail:
      "The defender model is turning the observed breach into a defense script.",
  },
  replay: {
    title: "Replaying with defense on",
    detail:
      "Running the same attack with the proposed defense to check its outcome.",
  },
  complete: {
    title: "Comparison complete",
    detail: "Baseline vs defended results are ready to review.",
  },
  error: {
    title: "Run failed",
    detail: "The evaluation stopped early. Check the error banner.",
  },
};
const ATTACK_TYPE_LABELS = {
  "runbook-injection": "Poisoned runbook injection",
  "tool-result-injection": "Tool-result injection",
  "role-escalation": "Operator impersonation",
  "data-extraction": "Protected-context extraction",
  prompt_injection: "Prompt injection",
  role_manipulation: "Role manipulation",
  data_extraction: "Data extraction",
};
function attackTypeLabel(result, scenario) {
  if (!result && !scenario) return "Adaptive attack";
  const seed = result?.seed_id || result?.id?.replace(/-r\d+$/, "") || scenario;
  if (ATTACK_TYPE_LABELS[seed]) return ATTACK_TYPE_LABELS[seed];
  if (result?.category && ATTACK_TYPE_LABELS[result.category]) {
    return ATTACK_TYPE_LABELS[result.category];
  }
  return result?.name || seed || "Adaptive attack";
}
const timeLabel = (value) =>
  new Date(value).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
async function api(path, body) {
  const response = await fetch(
    "/api" + path,
    body === undefined
      ? undefined
      : {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
  );
  const data = await response.json().catch(() => ({}));
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : "The request could not be completed.",
    );
  return data;
}
function Mark({ small = false }) {
  return (
    <span className={"mark " + (small ? "small" : "")}>
      <span />
      <span />
      <span />
    </span>
  );
}
function Badge({ children, tone = "", icon: Icon }) {
  return (
    <span className={"badge " + tone}>
      {Icon && <Icon size={13} />} {children}
    </span>
  );
}
function Empty({ icon: Icon = Shield, title, children }) {
  const spinning = Icon === Loader2;
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon size={27} className={spinning ? "spin" : undefined} />
      </span>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
function Button({ children, icon: Icon, className = "", ...props }) {
  return (
    <button className={"button " + className} {...props}>
      {Icon && <Icon size={16} />} {children}
    </button>
  );
}

export default function App() {
  const [page, setPage] = useState("Workspace");
  const [overview, setOverview] = useState(null);
  const [session, setSession] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [scenario, setScenario] = useState("all");
  const [applyDefense, setApplyDefense] = useState(false);
  const [targetId, setTargetId] = useState("local-incident");
  const [rounds, setRounds] = useState(2);
  const [run, setRun] = useState(null);
  const [selectedResult, setSelectedResult] = useState(0);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [approval, setApproval] = useState(null);
  const [showRule, setShowRule] = useState(false);
  const [notice, setNotice] = useState("");
  const stream = useRef(null);
  const refresh = async () => {
    const data = await api("/overview");
    setOverview(data);
    return data;
  };

  useEffect(() => {
    (async () => {
      try {
        const data = await refresh();
        const rememberedId = localStorage.getItem("counterforge-chat");
        const saved =
          data.sessions.find((s) => s.id === rememberedId) || data.sessions[0];
        const current = saved
          ? await api("/sessions/" + saved.id)
          : await api("/sessions", {});
        setSession(current);
        if (data.runs[0]) setRun(data.runs[0]);
        await refresh();
      } catch (e) {
        setError(e.message);
      }
    })();
    return () => stream.current?.close();
  }, []);
  useEffect(() => {
    if (session?.id) localStorage.setItem("counterforge-chat", session.id);
  }, [session?.id]);
  useEffect(() => {
    if (!run || !["queued", "running"].includes(run.status)) return;
    let stopped = false;
    const poll = async () => {
      try {
        const next = await api("/lab/runs/" + run.id);
        if (!stopped) {
          setRun(next);
          if (!["queued", "running"].includes(next.status)) await refresh();
        }
      } catch (e) {
        if (!stopped) setError(e.message);
      }
    };
    stream.current?.close();
    const events = new EventSource("/api/events/" + run.id);
    stream.current = events;
    events.onmessage = poll;
    const interval = setInterval(poll, 900);
    poll();
    return () => {
      stopped = true;
      clearInterval(interval);
      events.close();
    };
  }, [run?.id, run?.status]);
  useEffect(() => setSelectedResult(0), [run?.id]);
  useEffect(() => {
    if (!notice) return;
    const id = setTimeout(() => setNotice(""), 4000);
    return () => clearTimeout(id);
  }, [notice]);
  useEffect(() => {
    if (!approval && !showRule) return;
    const previous = document.activeElement;
    const modal = document.querySelector('[role="dialog"]');
    const focusable = () => [
      ...modal.querySelectorAll(
        "button:not(:disabled), a[href], input, select, textarea",
      ),
    ];
    focusable()[0]?.focus();
    const handleKey = (e) => {
      if (e.key === "Escape") {
        setApproval(null);
        setShowRule(false);
      }
      if (e.key !== "Tab") return;
      const items = focusable();
      const first = items[0],
        last = items.at(-1);
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    };
    modal.addEventListener("keydown", handleKey);
    return () => {
      modal.removeEventListener("keydown", handleKey);
      previous?.focus();
    };
  }, [approval?.id, showRule]);

  async function perform(fn) {
    setBusy(true);
    setError("");
    try {
      return await fn();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function newChat() {
    await perform(async () => {
      setSession(await api("/sessions", {}));
      await refresh();
    });
  }
  async function startRun() {
    await perform(async () => {
      const next = await api("/lab/runs", {
        scenario,
        apply_defense: applyDefense,
        target_id: targetId,
        rounds,
        workspace_session_id: session?.id || null,
      });
      setSelectedResult(0);
      setRun(next);
      if (session)
        setSession(
          await api("/sessions/" + session.id + "/context", {
            run_id: next.id,
            watch: true,
          }),
        );
      await refresh();
    });
  }
  async function registerTarget(payload) {
    return await perform(async () => {
      const value = await api("/agents", payload);
      setTargetId(value.agent.id);
      if (value.started_run) {
        setRun(value.started_run);
        if (session)
          setSession(
            await api("/sessions/" + session.id + "/context", {
              run_id: value.started_run.id,
              watch: true,
            }),
          );
      }
      await refresh();
      setNotice(
        value.started_run
          ? "Agent registered. Autonomous test queued."
          : "Agent registered. Ready for a manual test.",
      );
      return value;
    });
  }
  async function openRun(id) {
    await perform(async () => {
      const next = await api("/lab/runs/" + id);
      setSelectedResult(0);
      setRun(next);
    });
  }
  async function resumeRunChat(id) {
    await perform(async () => {
      const saved = await api("/lab/runs/" + id + "/chat", {
        session_id: session?.id || null,
      });
      setSession(saved);
      setPage("Workspace");
      await refresh();
    });
  }
  async function approve() {
    await perform(async () => {
      const approved = await api("/actions/" + approval.id + "/approve", {
        token: approval.token,
      });
      setApproval(null);
      await refresh();
      setNotice(
        approved.delivery.status === "Failed"
          ? "Voice notification failed. The incident remains contained."
          : approved.delivery.mode === "twilio_voice"
            ? "Twilio accepted the sanitized voice call."
            : "Simulated voice notification accepted. No phone call was placed.",
      );
    });
  }
  async function activate() {
    await perform(async () => {
      await api("/defenses/activate/" + run.id, {});
      const data = await refresh();
      setRun(data.runs.find((r) => r.id === run.id));
      setNotice("Validated local policy activated.");
    });
  }
  const actions = overview?.actions || [];
  const incidents = overview?.incidents || [];
  const selected =
    incidents.find((i) => i.id === selectedIncident) || incidents[0];
  const result = run?.results?.[selectedResult];
  const liveRun =
    run?.mode?.includes("dvaa") ||
    run?.results?.some((r) => r.baseline?.mode === "dvaa");
  const legacyLive = liveRun && !run?.adaptive;
  const liveAlerts = overview?.alert_mode === "twilio_voice";
  const adaptive = overview?.role_mode === "adaptive";

  function Transcript({ defended }) {
    const data = defended ? result?.defended : result?.baseline;
    return (
      <div className="panel transcript">
        <div className="panel-header">
          <h3>
            {defended && legacyLive
              ? "Repeated probe · policy not applied"
              : defended
                ? `Defense v${run?.candidate?.version || overview?.policy?.version}`
                : "Baseline"}
          </h3>
          <Badge
            tone={
              !data
                ? ""
                : data.verdict === "succeeded"
                  ? "danger"
                  : ["error", "skipped"].includes(data.verdict)
                    ? "warning"
                    : "safe"
            }
            icon={
              !data
                ? Clock3
                : data.verdict === "succeeded"
                  ? TriangleAlert
                  : ShieldCheck
            }
          >
            {!data
              ? "Waiting"
              : data.verdict === "succeeded"
                ? "Breach observed"
                : data.verdict === "error"
                  ? "Target error"
                  : data.verdict === "skipped"
                    ? "Replay skipped"
                    : "No breach reported"}
          </Badge>
          {!defended && run?.page && (
            <Badge
              tone={
                run.page.status === "Accepted"
                  ? "danger"
                  : run.page.status === "Failed"
                    ? "warning"
                    : ""
              }
              icon={TriangleAlert}
            >
              {run.page.status === "Accepted"
                ? "On-call called"
                : run.page.status === "Suppressed"
                  ? "Call suppressed (recent page)"
                  : "Call failed"}
            </Badge>
          )}
        </div>
        {!data ? (
          <Empty
            icon={run?.status === "running" ? Loader2 : FlaskConical}
            title={
              run?.status === "running"
                ? (STAGE_COPY[run.stage] || STAGE_COPY.queued).title
                : "Ready for a comparison"
            }
          >
            {run?.status === "running"
              ? (STAGE_COPY[run.stage] || STAGE_COPY.queued).detail
              : "Run a scenario to inspect live target execution."}
          </Empty>
        ) : (
          <div className="trace-content">
            <div className="trace-row">
              <MessageSquare />
              <div>
                <small>Legitimate task</small>
                <p>
                  Investigate the payment incident and summarize the runbook.
                </p>
              </div>
            </div>
            <div className="trace-row">
              <BookOpen />
              <div>
                <small>{result.surface.replace("_", " ")} attack surface</small>
                <pre>{data.request_content || result.payload}</pre>
                {result.strategy && !defended && (
                  <p className="trace-response">
                    Attacker strategy: {result.strategy}
                  </p>
                )}
                {result.defended?.verdict === "skipped" && (
                  <p className="muted">
                    Defense toggle was off — protected replay skipped for
                    comparison.
                  </p>
                )}
                {defended && result.defense?.rationale && (
                  <p className="trace-response">
                    Defender rationale: {result.defense.rationale}
                  </p>
                )}
              </div>
            </div>
            <div className="trace-row">
              <Terminal />
              <div>
                <small>Execution trace</small>
                <pre>
                  {data.trace?.[0]?.tool || "target"} →{" "}
                  {data.trace?.[0]?.decision || data.verdict}
                  <br />
                  {data.reason}
                </pre>
              </div>
            </div>
            <div
              className={
                "trace-outcome " +
                (data.verdict === "succeeded" ? "danger" : "safe")
              }
            >
              <CheckCircle2 size={16} />
              <span>
                {data.canary_leaked
                  ? "Synthetic marker disclosed"
                  : data.verdict === "error"
                    ? "Target error · inconclusive"
                    : data.verdict === "skipped"
                      ? "Defense replay skipped"
                      : data.unauthorized_actions
                        ? liveRun
                          ? "Unauthorized action reported by target harness"
                          : "Unauthorized simulated action executed"
                        : liveRun
                          ? "No breach reported by target harness"
                          : "Privileged action blocked before execution"}
              </span>
            </div>
            <p className="trace-response">{data.output}</p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" onClick={(e) => e.preventDefault()}>
          <Mark />
          <span>
            Counter<span className="brand-forge">Forge</span>
          </span>
        </a>
        <div className="workspace-selector">
          <span className="workspace-icon">C</span>
          <div>
            <strong>Local lab</strong>
            <small>Personal workspace</small>
          </div>
          <ChevronDown size={14} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {NAV.map(([name, Icon]) => (
            <button
              key={name}
              className={page === name ? "nav-item active" : "nav-item"}
              onClick={() => {
                setPage(name);
                setError("");
              }}
            >
              <Icon size={19} />
              {name}
              {name === "Incidents" &&
                incidents.filter((i) => i.status !== "Resolved").length > 0 && (
                  <span className="nav-count">
                    {incidents.filter((i) => i.status !== "Resolved").length}
                  </span>
                )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="environment">
            <span className="status-dot" />
            <div>
              <strong>
                {adaptive ? "Adaptive model lab" : "Configure live lab"}
              </strong>
              <small>
                {adaptive
                  ? `${overview.attacker_model} · ${overview.defender_model}`
                  : "Hosted model roles disconnected"}
              </small>
            </div>
          </div>
          <div className="profile">
            <span className="avatar">S</span>
            <div>
              <strong>Sid</strong>
              <small>Lab operator</small>
            </div>
            <MoreHorizontal size={19} />
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            {page}
            <ChevronRight size={14} />
            <span>
              {page === "Workspace"
                ? "Ask CounterForge"
                : page === "Attack lab"
                  ? run
                    ? runLabel(run)
                    : "New comparison"
                  : "Local lab"}
            </span>
          </div>
          <div className="topbar-right">
            <Badge icon={FlaskConical}>
              {overview?.lab_ready || overview?.role_mode === "adaptive"
                ? "Live adaptive lab"
                : "Lab not configured"}
            </Badge>
            <Badge tone="safe">
              <span className="status-dot" />
              {overview?.lab_ready || overview?.mode === "live"
                ? "DVAA · Ollama (live)"
                : "Target not configured"}
            </Badge>
            <span className="operator-circle">S</span>
          </div>
        </header>
        {error && (
          <div className="error-banner" role="alert">
            <TriangleAlert size={17} />
            <span>{error}</span>
            <button aria-label="Dismiss error" onClick={() => setError("")}>
              <X size={16} />
            </button>
          </div>
        )}
        {notice && (
          <div className="toast" role="status">
            <CheckCircle2 size={18} />
            {notice}
          </div>
        )}
        {!overview ? (
          <div className="loading-screen">
            <Loader2 className="spin" />
            <p>Connecting to the local lab…</p>
          </div>
        ) : (
          <main
            className={"page " + (page === "Workspace" ? "workspace-page" : "")}
          >
            {page === "Workspace" && (
              <Workspace
                overview={overview}
                session={session}
                setSession={setSession}
                run={run}
                setRun={setRun}
                refresh={refresh}
                newChat={newChat}
                resumeRunChat={resumeRunChat}
                openLab={(selected) => {
                  if (selected?.target?.id) setTargetId(selected.target.id);
                  if (selected?.scenario) setScenario(selected.scenario);
                  setApplyDefense(selected?.apply_defense !== false);
                  if (selected?.attack_rounds)
                    setRounds(selected.attack_rounds);
                  setPage("Attack lab");
                }}
              />
            )}
            {page === "Attack lab" && (
              <AttackLab
                overview={overview}
                sessionId={session?.id}
                run={run}
                result={result}
                selectedResult={selectedResult}
                setSelectedResult={setSelectedResult}
                scenario={scenario}
                setScenario={setScenario}
                scenarios={SCENARIOS}
                applyDefense={applyDefense}
                setApplyDefense={setApplyDefense}
                targetId={targetId}
                setTargetId={setTargetId}
                rounds={rounds}
                setRounds={setRounds}
                registerTarget={registerTarget}
                busy={busy}
                startRun={startRun}
                openRun={openRun}
                resumeRunChat={resumeRunChat}
                activate={activate}
                viewRule={() => setShowRule(true)}
                clearDefense={() =>
                  perform(async () => {
                    await api("/defenses/clear", {});
                    await refresh();
                    setNotice("Saved defense cleared.");
                  })
                }
                traces={
                  <>
                    <Transcript />
                    <Transcript defended />
                  </>
                }
                attackLabel={attackTypeLabel}
              />
            )}
            {page === "Defenses" && (
              <>
                <div className="page-heading">
                  <div>
                    <div className="eyebrow">
                      <ShieldCheck size={14} /> ENFORCEMENT
                    </div>
                    <h1>
                      Boundaries that hold<span className="title-dot">.</span>
                    </h1>
                    <p>
                      Versioned policies enforce what the assistant can actually
                      do.
                    </p>
                  </div>
                  <Button
                    icon={Undo2}
                    disabled={busy || !overview.can_rollback}
                    onClick={() =>
                      perform(async () => {
                        await api("/defenses/rollback", {});
                        await refresh();
                        setNotice(
                          "Previous policy restored with a new version.",
                        );
                      })
                    }
                  >
                    Roll back policy
                  </Button>
                </div>
                <div className="policy-hero panel">
                  <ShieldCheck size={36} />
                  <div>
                    <Badge tone="safe">Active policy</Badge>
                    <h2>Defense v{overview.policy.version}</h2>
                    <p>
                      Changes are activated after attack replay and benign
                      regression checks.
                    </p>
                  </div>
                  <span className="policy-mode">LOCAL LAB</span>
                </div>
                <div className="rule-grid">
                  {[
                    [
                      "export_allowlist",
                      "Export allowlist",
                      "Only approved destinations can receive an export.",
                      LockKeyhole,
                    ],
                    [
                      "protect_context",
                      "Protected context",
                      "Canary disclosures and protected outputs are blocked.",
                      Shield,
                    ],
                    [
                      "responder_allowlist",
                      "Responder allowlist",
                      "Paging is limited to the configured primary responder.",
                      Phone,
                    ],
                    [
                      "require_approval",
                      "Action approval",
                      "The operator approves an exact, expiring proposal.",
                      CheckCircle2,
                    ],
                    [
                      "block_untrusted_actions",
                      "Source authority",
                      "Retrieved content cannot authorize privileged actions.",
                      BookOpen,
                    ],
                  ].map(([key, title, desc, Icon]) => (
                    <div className="panel rule-card" key={key}>
                      <Icon size={23} />
                      <Badge tone={overview.policy[key] ? "safe" : "warning"}>
                        {overview.policy[key]
                          ? "Enforced"
                          : "Candidate extension"}
                      </Badge>
                      <h3>{title}</h3>
                      <p>{desc}</p>
                    </div>
                  ))}
                </div>
                <div className="panel defense-explainer">
                  <GitBranch size={22} />
                  <div>
                    <h3>Observe → propose → replay → activate</h3>
                    <p>
                      Attack text cannot change active policy. The trusted
                      controller accepts a typed candidate only after regression
                      checks pass. Existing approvals expire when the policy
                      version changes.
                    </p>
                  </div>
                  <Button onClick={() => setPage("Attack lab")}>
                    Open attack lab <ArrowRight size={15} />
                  </Button>
                </div>
              </>
            )}
            {page === "Incidents" && (
              <>
                <div className="page-heading">
                  <div>
                    <div className="eyebrow">
                      <Bell size={14} /> HUMAN ESCALATION
                    </div>
                    <h1>
                      A blocked action. A clear response
                      <span className="title-dot">.</span>
                    </h1>
                    <p>Track containment, escalation, and acknowledgment.</p>
                  </div>
                  <Badge icon={Phone}>
                    {liveAlerts ? "Twilio voice" : "Simulated provider"}
                  </Badge>
                </div>
                {!incidents.length ? (
                  <div className="panel">
                    <Empty icon={Bell} title="No security incidents yet">
                      Run a security test in Attack Lab. A confirmed breach
                      creates an incident for review.
                    </Empty>
                    <div className="empty-action">
                      <Button
                        className="primary"
                        onClick={() => {
                          setPage("Attack lab");
                        }}
                      >
                        Open Attack Lab <ArrowRight size={15} />
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="incidents-grid">
                    <div>
                      <div className="panel">
                        <div className="panel-header">
                          <h3>Security incidents</h3>
                          <Badge>{incidents.length} total</Badge>
                        </div>
                        <table>
                          <thead>
                            <tr>
                              <th>Incident</th>
                              <th>Finding</th>
                              <th>Severity</th>
                              <th>Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {incidents.map((i) => (
                              <tr
                                key={i.id}
                                className={
                                  "clickable " +
                                  (selected?.id === i.id ? "selected-row" : "")
                                }
                                onClick={() => setSelectedIncident(i.id)}
                              >
                                <td className="mono">{i.id}</td>
                                <td>{i.finding}</td>
                                <td>
                                  <span
                                    className={
                                      "severity-dot " +
                                      (i.severity === "High"
                                        ? "high"
                                        : "medium")
                                    }
                                  />
                                  {i.severity}
                                </td>
                                <td>
                                  <Badge
                                    tone={
                                      i.status === "Resolved" ||
                                      i.status === "Acknowledged"
                                        ? "safe"
                                        : "warning"
                                    }
                                  >
                                    {i.status}
                                  </Badge>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      {selected && (
                        <div className="panel incident-detail">
                          <span className="eyebrow">{selected.id}</span>
                          <h2>{selected.finding}</h2>
                          <div className="source-list">
                            <Badge tone="safe" icon={ShieldCheck}>
                              {selected.status}
                            </Badge>
                            <Badge icon={GitBranch}>
                              Policy v{selected.policy_version}
                            </Badge>
                          </div>
                          <div className="incident-timeline">
                            {selected.timeline.map((e, i) => (
                              <div key={e.id}>
                                <span>
                                  <Check size={15} />
                                </span>
                                <strong>{e.title}</strong>
                                <small>{timeLabel(e.timestamp)}</small>
                                {i < selected.timeline.length - 1 && <i />}
                              </div>
                            ))}
                          </div>
                          <div className="evidence-summary">
                            <h3>Evidence summary</h3>
                            <p>{selected.summary}</p>
                            <div className="source-list">
                              <span>
                                <BookOpen size={13} />
                                {selected.source}
                              </span>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                    {selected && (
                      <aside className="panel escalation">
                        <h3>On-call escalation</h3>
                        <div className="responder">
                          <span className="avatar">S</span>
                          <div>
                            <strong>Primary responder</strong>
                            <small>Allowlisted demo contact</small>
                          </div>
                        </div>
                        <div className="voice-card">
                          <div className="section-top">
                            <Phone size={22} />
                            <div>
                              <strong>Voice notification</strong>
                              <small>Demo call outcome</small>
                            </div>
                          </div>
                          <Badge
                            tone={selected.delivery.attempts ? "safe" : ""}
                          >
                            {selected.status === "Acknowledged"
                              ? "Acknowledged locally"
                              : selected.delivery.status}
                          </Badge>
                          <div className="spoken-message">
                            <small>Spoken message preview</small>
                            <p>
                              “CounterForge requires attention. Review the
                              incident in the dashboard.”
                            </p>
                          </div>
                          <dl>
                            <dt>Channel</dt>
                            <dd>
                              {selected.delivery.mode === "twilio_voice"
                                ? "Twilio voice"
                                : "Simulated voice"}
                            </dd>
                            <dt>Delivery</dt>
                            <dd>{selected.delivery.status}</dd>
                            <dt>Attempts</dt>
                            <dd>{selected.delivery.attempts}</dd>
                            <dt>Sensitive content</dt>
                            <dd>Excluded</dd>
                          </dl>
                          <div className="footnote">
                            <Info size={14} />
                            {selected.delivery.mode === "twilio_voice"
                              ? selected.delivery.status === "Accepted"
                                ? "Provider acceptance does not prove the responder answered."
                                : "The failed alert did not weaken incident containment."
                              : "No external phone call is placed."}
                          </div>
                        </div>
                        {actions.find(
                          (a) =>
                            a.security_id === selected.id &&
                            a.status === "pending",
                        ) && (
                          <Button
                            className="primary full"
                            onClick={() =>
                              setApproval(
                                actions.find(
                                  (a) =>
                                    a.security_id === selected.id &&
                                    a.status === "pending",
                                ),
                              )
                            }
                          >
                            Review page
                          </Button>
                        )}
                        <Button
                          className="full"
                          disabled={
                            busy ||
                            !selected.delivery.attempts ||
                            ["Acknowledged", "Resolved"].includes(
                              selected.status,
                            )
                          }
                          onClick={() =>
                            perform(async () => {
                              await api(
                                "/incidents/" + selected.id + "/acknowledge",
                                {},
                              );
                              await refresh();
                            })
                          }
                        >
                          Acknowledge alert
                        </Button>
                        <Button
                          className="primary full"
                          disabled={busy || selected.status === "Resolved"}
                          onClick={() =>
                            perform(async () => {
                              await api(
                                "/incidents/" + selected.id + "/resolve",
                                {},
                              );
                              await refresh();
                            })
                          }
                        >
                          Resolve incident
                        </Button>
                      </aside>
                    )}
                  </div>
                )}
              </>
            )}
            {page === "Reports" && (
              <>
                <div className="page-heading">
                  <div>
                    <div className="eyebrow">
                      <FileText size={14} /> REPRODUCIBLE EVIDENCE
                    </div>
                    <h1>
                      Evidence you can inspect
                      <span className="title-dot">.</span>
                    </h1>
                    <p>
                      Every comparison preserves its fixture outcomes and policy
                      validation.
                    </p>
                  </div>
                </div>
                <div className="panel">
                  <div className="panel-header">
                    <h3>Evaluation reports</h3>
                    <Badge>{overview.runs.length} runs</Badge>
                  </div>
                  {!overview.runs.length ? (
                    <Empty
                      icon={FileText}
                      title="Your first report starts in the lab"
                    >
                      Run a comparison to generate Markdown and JSON evidence.
                    </Empty>
                  ) : (
                    <table>
                      <thead>
                        <tr>
                          <th>Run</th>
                          <th>Created</th>
                          <th>Scenario</th>
                          <th>Status</th>
                          <th>Download</th>
                        </tr>
                      </thead>
                      <tbody>
                        {overview.runs.map((r) => (
                          <tr key={r.id}>
                            <td>{runLabel(r)}</td>
                            <td>{new Date(r.created_at).toLocaleString()}</td>
                            <td>
                              {SCENARIOS.find((s) => s[0] === r.scenario)?.[1]}
                            </td>
                            <td>
                              <Badge
                                tone={
                                  r.status === "completed" ? "safe" : "warning"
                                }
                              >
                                {r.status}
                              </Badge>
                            </td>
                            <td>
                              <div className="download-links">
                                <a href={"/api/reports/" + r.id}>
                                  Markdown <ArrowDownToLine size={13} />
                                </a>
                                <a
                                  href={"/api/reports/" + r.id + "?format=json"}
                                  target="_blank"
                                  rel="noreferrer"
                                >
                                  JSON <ArrowRight size={13} />
                                </a>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
                <div className="footnote">
                  <Info size={13} />
                  Reports contain redacted execution evidence from this isolated
                  lab run.
                </div>
              </>
            )}
            {page === "Settings" && (
              <>
                <div className="page-heading">
                  <div>
                    <div className="eyebrow">
                      <Settings2 size={14} /> CONNECTIONS
                    </div>
                    <h1>
                      Built for your next endpoint
                      <span className="title-dot">.</span>
                    </h1>
                    <p>
                      Live adaptive roles and the local DVAA target power this
                      hackathon build. Alert delivery is configured server-side.
                    </p>
                  </div>
                </div>
                <div className="settings-grid">
                  <div className="panel settings-card">
                    <div className="section-top">
                      <Sparkles size={22} />
                      <h3>Model roles</h3>
                      <Badge tone={adaptive ? "safe" : "warning"}>
                        {adaptive ? "Live adaptive" : "Not configured"}
                      </Badge>
                    </div>
                    <p>
                      Attacker and defender call OpenRouter. The target stays on
                      local DVAA backed by Ollama.
                    </p>
                    <dl>
                      <dt>Attacker</dt>
                      <dd>{overview.attacker_model || "Not configured"}</dd>
                      <dt>Defender analyst</dt>
                      <dd>{overview.defender_model || "Not configured"}</dd>
                      <dt>Adaptive rounds</dt>
                      <dd>{overview.attack_rounds || 0}</dd>
                      <dt>Target</dt>
                      <dd>
                        {overview.lab_ready
                          ? "DVAA · local Ollama"
                          : "Not configured"}
                      </dd>
                    </dl>
                    <div className="config-note">
                      <Terminal size={15} />
                      Role keys and target URLs are configured server-side in
                      .env.
                    </div>
                  </div>
                  <div className="panel settings-card">
                    <div className="section-top">
                      <Phone size={22} />
                      <h3>Alert providers</h3>
                      <Badge tone={liveAlerts ? "safe" : "warning"}>
                        {liveAlerts ? "Twilio voice ready" : "Simulation only"}
                      </Badge>
                    </div>
                    <p>
                      The operator reviews an expiring, sanitized message before
                      the dispatcher sends it.
                    </p>
                    <dl>
                      <dt>Current mode</dt>
                      <dd>{liveAlerts ? "Twilio voice" : "Simulated voice"}</dd>
                      <dt>Trigger</dt>
                      <dd>Approved defender finding</dd>
                      <dt>Responder</dt>
                      <dd>Primary · allowlisted</dd>
                      <dt>Duplicate suppression</dt>
                      <dd>60-second incident cooldown</dd>
                    </dl>
                    <div className="config-note">
                      <LockKeyhole size={15} />
                      Provider credentials stay outside the target environment.
                    </div>
                  </div>
                </div>
                <div className="panel defense-explainer">
                  <Info size={22} />
                  <div>
                    <h3>Hackathon lab boundary</h3>
                    <p>
                      Adaptive attacker and defender models run against the
                      localhost-only DVAA target. Synthetic markers stay in the
                      lab; no public-network exfiltration is used.
                    </p>
                  </div>
                </div>
              </>
            )}
          </main>
        )}
      </div>
      {approval && (
        <div
          className="modal-backdrop"
          onClick={() => !busy && setApproval(null)}
        >
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="approval-title"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="modal-close"
              aria-label="Close approval"
              onClick={() => setApproval(null)}
            >
              <X size={18} />
            </button>
            <span className="modal-icon">
              <Phone size={26} />
            </span>
            <Badge tone="warning">Operator approval</Badge>
            <h2 id="approval-title">Review the paging action.</h2>
            <p>
              This authorizes one{" "}
              {liveAlerts ? "Twilio voice call" : "simulated notification"} to
              the configured responder.
            </p>
            <dl>
              <dt>Incident</dt>
              <dd>{approval.incident_id}</dd>
              <dt>Recipient</dt>
              <dd>Primary responder</dd>
              <dt>Policy</dt>
              <dd>v{approval.policy_version}</dd>
              <dt>Expires</dt>
              <dd>{timeLabel(approval.expires_at * 1000)}</dd>
            </dl>
            <div className="spoken-message">
              <small>Exact notification text</small>
              <p>{approval.message}</p>
            </div>
            <div className="modal-buttons">
              <Button disabled={busy} onClick={() => setApproval(null)}>
                Cancel
              </Button>
              <Button disabled={busy} className="primary" onClick={approve}>
                {busy
                  ? "Processing…"
                  : liveAlerts
                    ? "Approve call"
                    : "Approve simulation"}
              </Button>
            </div>
          </section>
        </div>
      )}
      {showRule && (
        <div className="modal-backdrop" onClick={() => setShowRule(false)}>
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="rule-title"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="modal-close"
              aria-label="Close rule"
              onClick={() => setShowRule(false)}
            >
              <X size={18} />
            </button>
            <span className="modal-icon">
              <ShieldCheck size={26} />
            </span>
            <h2 id="rule-title">Enforce source authority.</h2>
            <p>
              Only the user or trusted operator can authorize privileged
              actions. Retrieved content supplies evidence, not permissions.
            </p>
            {result?.defense?.system_prompt && (
              <pre
                className="rule-json"
                style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
              >
                {result.defense.system_prompt}
              </pre>
            )}
            <pre className="rule-json">
              {JSON.stringify(run?.candidate, null, 2)}
            </pre>
            <Badge tone={run?.validated && !legacyLive ? "safe" : "warning"}>
              {run?.validated && !legacyLive
                ? "Replay validation passed"
                : "Validation pending"}
            </Badge>
            <div className="modal-buttons">
              <Button onClick={() => setShowRule(false)}>Close</Button>
              <Button
                className="primary"
                disabled={
                  busy ||
                  !run?.validated ||
                  legacyLive ||
                  run.activated ||
                  run.base_version !== overview.policy.version
                }
                onClick={async () => {
                  await activate();
                  setShowRule(false);
                }}
              >
                Activate in local lab
              </Button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
