import { useEffect, useRef, useState } from "react";
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
  Plus,
  RefreshCw,
  Send,
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
const STAGES = ["generate", "execute", "inspect", "propose", "replay"];
const SCENARIOS = [
  ["all", "All attack surfaces"],
  ["runbook-injection", "Poisoned runbook"],
  ["tool-result-injection", "Tool-result injection"],
  ["role-escalation", "Operator impersonation"],
  ["data-extraction", "Protected-context extraction"],
];
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
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon size={27} />
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
  const [message, setMessage] = useState("");
  const [incidentId, setIncidentId] = useState("INC-104");
  const [poisoned, setPoisoned] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [scenario, setScenario] = useState("all");
  const [run, setRun] = useState(null);
  const [selectedResult, setSelectedResult] = useState(0);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [approval, setApproval] = useState(null);
  const [showRule, setShowRule] = useState(false);
  const [notice, setNotice] = useState("");
  const bottom = useRef(null);
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
        const current = data.sessions[0]
          ? await api("/sessions/" + data.sessions[0].id)
          : await api("/sessions", {});
        setSession(current);
        setIncidentId(current.incident_id);
        if (data.runs[0]) setRun(data.runs[0]);
        await refresh();
      } catch (e) {
        setError(e.message);
      }
    })();
    return () => stream.current?.close();
  }, []);
  useEffect(() => {
    bottom.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [session?.messages?.length, busy]);
  useEffect(() => {
    if (!run || run.status !== "running") return;
    let stopped = false;
    const poll = async () => {
      try {
        const next = await api("/lab/runs/" + run.id);
        if (!stopped) {
          setRun(next);
          if (next.status !== "running") await refresh();
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
  async function send(text = message) {
    if (!text.trim() || busy || !session) return;
    await perform(async () => {
      const result = await api("/sessions/" + session.id + "/chat", {
        message: text.trim(),
        incident_id: incidentId,
        poisoned,
      });
      setSession(result);
      setMessage("");
      await refresh();
    });
  }
  async function newChat() {
    await perform(async () => {
      setSession(await api("/sessions", {}));
      setMessage("");
      setPoisoned(false);
      await refresh();
    });
  }
  async function startRun() {
    await perform(async () => {
      const next = await api("/lab/runs", { scenario });
      setSelectedResult(0);
      setRun(next);
    });
  }
  async function approve() {
    await perform(async () => {
      await api("/actions/" + approval.id + "/approve", {
        token: approval.token,
      });
      setApproval(null);
      await refresh();
      setNotice(
        "Simulated voice notification accepted. No phone call was placed.",
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
  const currentAction = (action) =>
    actions.find((a) => a.id === action?.id) || action;
  const incidents = overview?.incidents || [];
  const selected =
    incidents.find((i) => i.id === selectedIncident) || incidents[0];
  const fixture = overview?.fixtures?.find((i) => i.id === incidentId);
  const result = run?.results?.[selectedResult];
  const completed = run?.status === "completed";
  const prevented =
    run?.results?.filter((r) => r.defended?.verdict === "blocked").length || 0;

  function ApprovalCard({ action }) {
    const value = currentAction(action);
    if (!value) return null;
    return (
      <div className="approval-card">
        <div className="section-top">
          <Phone size={18} />
          <strong>
            {value.status === "approved"
              ? "Responder notified"
              : "Page the responder?"}
          </strong>
        </div>
        <Badge tone={value.status === "approved" ? "safe" : "warning"}>
          {value.status === "approved"
            ? "Simulation accepted"
            : "Approval required"}
        </Badge>
        <p>
          {value.status === "approved"
            ? "A simulated notification was recorded. No external call was placed."
            : "Review the exact message for the allowlisted primary responder."}
        </p>
        {value.status === "pending" && (
          <Button className="primary full" onClick={() => setApproval(value)}>
            Review action <ArrowRight size={15} />
          </Button>
        )}
      </div>
    );
  }

  function Transcript({ defended }) {
    const data = defended ? result?.defended : result?.baseline;
    return (
      <div className="panel transcript">
        <div className="panel-header">
          <h3>
            {defended
              ? `Defense v${run?.candidate?.version || overview?.policy?.version}`
              : "Baseline"}
          </h3>
          <Badge
            tone={data ? (defended ? "safe" : "danger") : ""}
            icon={data ? (defended ? ShieldCheck : TriangleAlert) : Clock3}
          >
            {data ? (defended ? "Blocked" : "Breach observed") : "Waiting"}
          </Badge>
        </div>
        {!data ? (
          <Empty icon={FlaskConical} title="Ready for a comparison">
            Run a scenario to inspect real fixture execution.
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
                <pre>{result.payload}</pre>
              </div>
            </div>
            <div className="trace-row">
              <Terminal />
              <div>
                <small>Execution trace</small>
                <pre>
                  {data.trace[0].tool} → {data.trace[0].decision}
                  <br />
                  {data.reason}
                </pre>
              </div>
            </div>
            <div className={"trace-outcome " + (defended ? "safe" : "danger")}>
              <CheckCircle2 size={16} />
              <span>
                {data.canary_leaked
                  ? "Synthetic marker disclosed"
                  : data.unauthorized_actions
                    ? "Unauthorized simulated action executed"
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
              <strong>Local simulation</strong>
              <small>External providers disconnected</small>
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
                ? fixture?.service || "Investigation"
                : page === "Attack lab"
                  ? run
                    ? "Run " + run.id.slice(0, 6)
                    : "New comparison"
                  : "Local lab"}
            </span>
          </div>
          <div className="topbar-right">
            <Badge icon={FlaskConical}>Demo mode</Badge>
            <Badge tone="safe">
              <span className="status-dot" />
              Local fixture target
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
              <>
                <div className="page-heading">
                  <div>
                    <div className="eyebrow">
                      <ShieldCheck size={14} /> DEFENDED ASSISTANT
                    </div>
                    <h1>
                      Investigate with confidence
                      <span className="title-dot">.</span>
                    </h1>
                    <p>Useful incident response. Visible security decisions.</p>
                  </div>
                  <Button icon={Plus} onClick={newChat} disabled={busy}>
                    New investigation
                  </Button>
                </div>
                <div className="workspace-grid">
                  <section className="chat-panel panel">
                    <div className="chat-top">
                      <div className="incident-picker">
                        <FileText size={17} />
                        <select
                          aria-label="Incident"
                          value={incidentId}
                          onChange={(e) => setIncidentId(e.target.value)}
                        >
                          {overview.fixtures.map((i) => (
                            <option key={i.id} value={i.id}>
                              {i.id} · {i.service}
                            </option>
                          ))}
                        </select>
                      </div>
                      <select
                        className="session-picker"
                        aria-label="Conversation history"
                        value={session?.id || ""}
                        onChange={(e) =>
                          perform(async () => {
                            const s = await api("/sessions/" + e.target.value);
                            setSession(s);
                            setIncidentId(s.incident_id);
                          })
                        }
                      >
                        {overview.sessions.map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.title}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="chat-history">
                      {!session?.messages.length ? (
                        <div className="welcome">
                          <span className="welcome-mark">
                            <Mark />
                          </span>
                          <h2>Start with an incident.</h2>
                          <p>
                            Inspect the evidence, understand the response,
                            <br />
                            and keep every action within policy.
                          </p>
                          <div className="suggestion-grid">
                            <button
                              onClick={() =>
                                send(
                                  "Investigate the payment outage and summarize the runbook.",
                                )
                              }
                            >
                              <Activity size={18} />
                              <strong>Investigate the outage</strong>
                              <span>Read the incident and response steps</span>
                              <ArrowRight size={15} />
                            </button>
                            <button
                              onClick={() => send("Draft an incident update.")}
                            >
                              <FileText size={18} />
                              <strong>Draft an update</strong>
                              <span>Prepare a response for review</span>
                              <ArrowRight size={15} />
                            </button>
                          </div>
                          <div className="welcome-note">
                            <LockKeyhole size={13} /> Synthetic incidents · No
                            model API required
                          </div>
                        </div>
                      ) : (
                        session.messages.map((m) => (
                          <div className={"message " + m.role} key={m.id}>
                            <div className="message-avatar">
                              {m.role === "assistant" ? <Mark small /> : "S"}
                            </div>
                            <div className="message-body">
                              <div className="message-label">
                                <strong>
                                  {m.role === "assistant"
                                    ? "CounterForge"
                                    : "You"}
                                </strong>
                                <small>{timeLabel(m.timestamp)}</small>
                                {m.role === "assistant" && (
                                  <span className="demo-label">
                                    Fixture response
                                  </span>
                                )}
                              </div>
                              <div className="message-text">{m.content}</div>
                              {m.sources?.length > 0 && (
                                <div className="source-list">
                                  {m.sources.map((s) => (
                                    <span key={s}>
                                      <FileText size={12} />
                                      {s}
                                    </span>
                                  ))}
                                </div>
                              )}
                              {m.blocked && (
                                <div className="blocked-banner">
                                  <TriangleAlert size={17} />
                                  <div>
                                    <strong>
                                      Suspicious instruction blocked
                                    </strong>
                                    <p>
                                      The retrieved content attempted to export
                                      protected incident data.
                                    </p>
                                  </div>
                                </div>
                              )}
                              {m.action && <ApprovalCard action={m.action} />}
                            </div>
                          </div>
                        ))
                      )}
                      {busy && (
                        <div className="thinking">
                          <Loader2 className="spin" size={15} />
                          Inspecting local evidence…
                        </div>
                      )}
                      <div ref={bottom} />
                    </div>
                    <div className="chat-compose">
                      <label className="fixture-toggle">
                        <input
                          type="checkbox"
                          checked={poisoned}
                          onChange={(e) => setPoisoned(e.target.checked)}
                        />
                        <span className={"toggle " + (poisoned ? "on" : "")} />
                        <span>Use injected runbook</span>
                        <Badge tone={poisoned ? "warning" : ""}>
                          {poisoned ? "Attack fixture" : "Clean fixture"}
                        </Badge>
                      </label>
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          send();
                        }}
                      >
                        <textarea
                          aria-label="Message"
                          placeholder="Ask about an incident or response step…"
                          value={message}
                          onChange={(e) => setMessage(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && !e.shiftKey) {
                              e.preventDefault();
                              send();
                            }
                          }}
                        />
                        <button
                          className="send-button"
                          aria-label="Send message"
                          disabled={busy || !message.trim()}
                        >
                          <Send size={18} />
                        </button>
                      </form>
                      <div className="compose-foot">
                        Local deterministic assistant{" "}
                        <span>
                          Enter to send · Shift + Enter for a new line
                        </span>
                      </div>
                    </div>
                  </section>
                  <aside className="timeline-column">
                    <div className="panel security-panel">
                      <div className="panel-header">
                        <h3>Security timeline</h3>
                        <Badge>{session?.events.length || 0} events</Badge>
                      </div>
                      {!session?.events.length ? (
                        <Empty
                          icon={ShieldCheck}
                          title="Every decision, visible"
                        >
                          Sources, tool checks, and blocked actions will appear
                          here as you investigate.
                        </Empty>
                      ) : (
                        <div className="timeline">
                          {session.events.map((e) => (
                            <div
                              className={"timeline-item " + e.status}
                              key={e.id}
                            >
                              <span className="timeline-dot" />
                              <small>{timeLabel(e.timestamp)}</small>
                              <strong>{e.title}</strong>
                              <p>{e.detail}</p>
                              {e.rule && (
                                <div className="evidence">
                                  <span>Policy</span>
                                  <strong>{e.rule}</strong>
                                  <span>Protected data</span>
                                  <strong>Redacted</strong>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="policy-note">
                      <ShieldCheck size={20} />
                      <div>
                        <strong>
                          Policy v{overview.policy.version} active
                        </strong>
                        <p>Permissions are enforced before tools execute.</p>
                        <button onClick={() => setPage("Defenses")}>
                          Inspect defenses <ArrowRight size={12} />
                        </button>
                      </div>
                    </div>
                  </aside>
                </div>
              </>
            )}
            {page === "Attack lab" && (
              <>
                <div className="page-heading">
                  <div>
                    <div className="eyebrow">
                      <FlaskConical size={14} /> ADVERSARIAL TESTING
                    </div>
                    <h1>
                      Attack. Observe. Defend
                      <span className="title-dot">.</span>
                    </h1>
                    <p>
                      Replay a scenario against a versioned defense, then
                      inspect the evidence.
                    </p>
                  </div>
                </div>
                <div className="lab-controls">
                  <div>
                    <label>Target</label>
                    <select aria-label="Lab target">
                      <option>Local fixture target</option>
                    </select>
                  </div>
                  <div>
                    <label>Scenario</label>
                    <select
                      aria-label="Attack scenario"
                      value={scenario}
                      onChange={(e) => setScenario(e.target.value)}
                    >
                      {SCENARIOS.map(([id, label]) => (
                        <option key={id} value={id}>
                          {label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="control-spacer" />
                  <Badge icon={LockKeyhole}>In-memory test sink</Badge>
                  <Button
                    icon={run?.status === "running" ? Loader2 : FlaskConical}
                    className="primary"
                    disabled={busy || run?.status === "running"}
                    onClick={startRun}
                  >
                    {run?.status === "running"
                      ? "Running comparison"
                      : "Run comparison"}
                  </Button>
                </div>
                <div className="metrics">
                  <Metric
                    value={run?.results?.length || "—"}
                    label="Attack scenarios"
                  />
                  <Metric
                    value={completed ? prevented : "—"}
                    label="Prevented in replay"
                    tone="safe"
                  />
                  <Metric
                    value={
                      completed
                        ? run.results.reduce(
                            (n, r) => n + r.defended.unauthorized_actions,
                            0,
                          )
                        : "—"
                    }
                    label="Unauthorized actions"
                  />
                  <Metric
                    value={
                      run?.validation
                        ? `${run.validation.benign_passed}/${run.validation.benign_total}`
                        : "—"
                    }
                    label="Benign tools passed"
                  />
                </div>
                <div className="stage-bar">
                  {STAGES.map((s, i) => {
                    const index = completed ? 5 : STAGES.indexOf(run?.stage);
                    return (
                      <div
                        key={s}
                        className={
                          (index > i ? "done " : "") +
                          (index === i ? "current" : "")
                        }
                      >
                        <span>{index > i ? <Check size={13} /> : i + 1}</span>
                        {s[0].toUpperCase() + s.slice(1)}
                        {i < 4 && <i />}
                      </div>
                    );
                  })}
                </div>
                {run?.status === "failed" && (
                  <div className="error-banner">
                    Evaluation failed: {run.error}
                  </div>
                )}
                {run?.results.length > 0 && (
                  <div className="scenario-tabs">
                    {run.results.map((r, i) => (
                      <button
                        className={selectedResult === i ? "selected" : ""}
                        key={r.id}
                        onClick={() => setSelectedResult(i)}
                      >
                        {r.name}
                      </button>
                    ))}
                  </div>
                )}
                <div className="comparison-grid">
                  <Transcript />
                  <Transcript defended />
                </div>
                <div className="lab-bottom">
                  <div className="panel">
                    <div className="panel-header">
                      <h3>Replay evidence</h3>
                      {completed && (
                        <a
                          className="text-link"
                          href={"/api/reports/" + run.id}
                        >
                          <ArrowDownToLine size={14} />
                          Export report
                        </a>
                      )}
                    </div>
                    {!run?.results.length ? (
                      <Empty
                        icon={GitBranch}
                        title="Build a reproducible comparison"
                      >
                        Each run starts with isolated fixture state.
                      </Empty>
                    ) : (
                      <table>
                        <thead>
                          <tr>
                            <th>Scenario</th>
                            <th>Baseline</th>
                            <th>Defense</th>
                            <th>Outcome</th>
                          </tr>
                        </thead>
                        <tbody>
                          {run.results.map((r) => (
                            <tr key={r.id}>
                              <td>{r.name}</td>
                              <td>
                                <Badge tone="danger">Breached</Badge>
                              </td>
                              <td>
                                <Badge tone={r.defended ? "safe" : ""}>
                                  {r.defended ? "Blocked" : "Pending"}
                                </Badge>
                              </td>
                              <td className="text-safe">
                                {r.defended ? "Improved" : "Evaluating"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                  <div className="panel candidate-card">
                    <FileText size={21} />
                    <h3>Candidate policy</h3>
                    <p>
                      {run?.proposal?.description ||
                        "The defender workflow will propose a rule based on observed execution."}
                    </p>
                    <div className="candidate-status">
                      <span>Status</span>
                      <Badge
                        tone={run?.validated ? "safe" : ""}
                        icon={run?.validated ? CheckCircle2 : Clock3}
                      >
                        {run?.activated
                          ? run.candidate.version === overview.policy.version
                            ? "Active"
                            : "Previously activated"
                          : run?.validated
                            ? "Validated in simulation"
                            : "Awaiting evidence"}
                      </Badge>
                    </div>
                    {run?.validation && (
                      <small>
                        {run.validation.held_out_blocked}/
                        {run.validation.held_out_total} held-out fixtures
                        blocked
                      </small>
                    )}
                    <Button
                      className="full"
                      disabled={!run?.candidate}
                      onClick={() => setShowRule(true)}
                    >
                      View rule <ChevronRight size={15} />
                    </Button>
                    <Button
                      className="primary full"
                      disabled={
                        busy ||
                        !run?.validated ||
                        run.activated ||
                        run.base_version !== overview.policy.version
                      }
                      onClick={activate}
                    >
                      {run?.activated
                        ? "Policy activated"
                        : "Activate in local lab"}
                    </Button>
                  </div>
                </div>
                <div className="footnote">
                  <Info size={13} /> Executable synthetic fixtures, not a live
                  model evaluation. GLM integration comes next.
                </div>
              </>
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
                  <Badge icon={Phone}>Simulated provider</Badge>
                </div>
                {!incidents.length ? (
                  <div className="panel">
                    <Empty icon={Bell} title="No security incidents yet">
                      Enable the injected runbook in Workspace and investigate
                      an incident to trigger detection.
                    </Empty>
                    <div className="empty-action">
                      <Button
                        className="primary"
                        onClick={() => {
                          setPoisoned(true);
                          setPage("Workspace");
                        }}
                      >
                        Try the injection demo <ArrowRight size={15} />
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
                            <dd>Simulated voice</dd>
                            <dt>Delivery</dt>
                            <dd>{selected.delivery.status}</dd>
                            <dt>Attempts</dt>
                            <dd>{selected.delivery.attempts}</dd>
                            <dt>Sensitive content</dt>
                            <dd>Excluded</dd>
                          </dl>
                          <div className="footnote">
                            <Info size={14} />
                            No external phone call is placed.
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
                          Acknowledge simulation
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
                            <td className="mono">{r.id.slice(0, 8)}</td>
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
                  Reports contain redacted execution evidence. Fixture results
                  do not measure real-model robustness.
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
                      The local demo works today. Model and alert APIs connect
                      later.
                    </p>
                  </div>
                </div>
                <div className="settings-grid">
                  <div className="panel settings-card">
                    <div className="section-top">
                      <Sparkles size={22} />
                      <h3>Model roles</h3>
                      <Badge>Not connected</Badge>
                    </div>
                    <p>
                      The attacker and defender analyst have separate adapter
                      boundaries. No API keys are required for fixture mode.
                    </p>
                    <dl>
                      <dt>Attacker</dt>
                      <dd>GLM-5.3-Flash · planned</dd>
                      <dt>Defender analyst</dt>
                      <dd>GLM-5.3-Flash · planned</dd>
                      <dt>Current assistant</dt>
                      <dd>Deterministic local fixture</dd>
                      <dt>Target</dt>
                      <dd>Local synthetic tool harness</dd>
                    </dl>
                    <div className="config-note">
                      <Terminal size={15} />
                      Configure model endpoints server-side when API integration
                      is added.
                    </div>
                  </div>
                  <div className="panel settings-card">
                    <div className="section-top">
                      <Phone size={22} />
                      <h3>Alert providers</h3>
                      <Badge tone="warning">Simulation only</Badge>
                    </div>
                    <p>
                      The operator reviews an expiring message before the
                      dispatcher records a simulated notification.
                    </p>
                    <dl>
                      <dt>Current mode</dt>
                      <dd>Simulated voice</dd>
                      <dt>PagerDuty / Twilio</dt>
                      <dd>Integration pending</dd>
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
                    <h3>Local demo boundary</h3>
                    <p>
                      Fixtures execute in isolated in-memory state. This build
                      does not launch a Docker sandbox or run a model.
                      CrowdStrike's target adapter and container isolation are
                      the next integration phase.
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
              This authorizes one simulated notification to the configured
              responder.
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
                {busy ? "Processing…" : "Approve simulation"}
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
            <pre className="rule-json">
              {JSON.stringify(run?.candidate, null, 2)}
            </pre>
            <Badge tone="safe">
              {run?.validated
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
function Metric({ value, label, tone = "" }) {
  return (
    <div>
      <strong className={"metric-value " + tone}>{value}</strong>
      <span>{label}</span>
    </div>
  );
}
