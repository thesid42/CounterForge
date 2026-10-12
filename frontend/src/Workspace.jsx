import { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  Clock3,
  FlaskConical,
  Loader2,
  Plus,
  Send,
  Sparkles,
  TriangleAlert,
  UserRound,
  X,
} from "lucide-react";
import { runLabel } from "./runNames";
import "./workspace.css";

const date = (v) =>
  v
    ? new Date(v).toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Time not recorded";
const stageLabels = {
  queued: "Queued",
  generate: "Preparing attacks",
  execute: "Testing target",
  inspect: "Reviewing findings",
  propose: "Preparing defense",
  replay: "Checking results",
  complete: "Completed",
  error: "Failed",
};
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
  const value = await response.json();
  if (!response.ok)
    throw new Error(
      typeof value.detail === "string"
        ? value.detail
        : "Request could not be completed",
    );
  return value;
}

function RunList({ runs, selectedId, select, open, disabled }) {
  return (
    <div className="cf-recent">
      {runs.map((r) => (
        <div
          key={r.id}
          className={"cf-run-row " + (selectedId === r.id ? "selected" : "")}
        >
          <button
            className="cf-select-run"
            disabled={disabled}
            aria-label={`${selectedId === r.id ? "Unselect" : "Select"} ${runLabel(r)} for chat`}
            aria-pressed={selectedId === r.id}
            onClick={() => select(selectedId === r.id ? null : r.id)}
          >
            <span className={`cf-run-dot ${r.status}`} />
            <div>
              <strong>{runLabel(r)}</strong>
              <small>
                {date(r.created_at)} · Defense{" "}
                {r.apply_defense === false ? "off" : "on"}
              </small>
              <small>
                {["queued", "running"].includes(r.status)
                  ? stageLabels[r.stage] || "In progress"
                  : r.status === "failed"
                    ? "Failed"
                    : "Completed"}
              </small>
            </div>
            {["queued", "running"].includes(r.status) ? (
              <Loader2 size={14} className="spin" />
            ) : null}
          </button>
          <button
            className="cf-open-run"
            aria-label={`Open ${runLabel(r)} in Attack Lab`}
            onClick={() => open(r.id)}
            disabled={disabled}
          >
            <ArrowRight size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}

function MessageContent({ content, role, detailed }) {
  const [expanded, setExpanded] = useState(!!detailed);
  // Apply the punctuation rule to saved replies as well as new ones.
  const display =
    role === "assistant"
      ? content.replace(/\s*[\u2013\u2014]+\s*/g, ", ")
      : content;
  const words = display.split(/\s+/);
  const long = role === "assistant" && words.length > 45;
  return (
    <>
      <div className="cf-message-content">
        {long && !expanded ? words.slice(0, 40).join(" ") + "…" : display}
      </div>
      {long && (
        <button
          className="cf-text-button"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Show less" : "Show details"}
        </button>
      )}
    </>
  );
}

export default function Workspace({
  overview,
  session,
  setSession,
  run,
  setRun,
  refresh,
  newChat,
  openLab,
  resumeRunChat,
}) {
  const [workspace, setWorkspace] = useState(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [optimistic, setOptimistic] = useState("");
  const bottom = useRef(null);
  const requestVersion = useRef(0);
  const busyRef = useRef(false);
  busyRef.current = busy;
  useEffect(() => {
    let disposed = false;
    const load = async () => {
      try {
        const next = await api("/workspace");
        if (!disposed) setWorkspace(next);
      } catch (e) {
        if (!disposed) setError(e.message);
      }
    };
    load();
    const timer = setInterval(load, 3000);
    return () => {
      disposed = true;
      clearInterval(timer);
    };
  }, [overview, run?.stage]);
  useEffect(() => {
    if (!session?.id) return;
    const sid = session.id;
    let disposed = false;
    let loading = false;
    const load = async () => {
      if (loading || busyRef.current) return;
      loading = true;
      const version = requestVersion.current;
      try {
        const next = await api("/sessions/" + sid);
        if (!disposed && !busyRef.current && version === requestVersion.current)
          setSession((current) => (current?.id === sid ? next : current));
      } catch (e) {
        if (!disposed) setError(e.message);
      } finally {
        loading = false;
      }
    };
    const events = new EventSource("/api/events/" + sid);
    events.onmessage = load;
    load();
    const timer = setInterval(load, 3000);
    return () => {
      disposed = true;
      clearInterval(timer);
      events.close();
    };
  }, [session?.id, setSession]);
  useEffect(() => {
    bottom.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [session?.id, session?.console_run_id, session?.console_messages?.length, busy]);
  useEffect(() => {
    setMessage("");
    setError("");
  }, [session?.id]);
  const runs = workspace?.runs || [];
  const selectedId = session?.console_run_id || null;
  const selectedRun = runs.find((r) => r.id === selectedId);
  const preferences = session?.console_config;
  const messages = (session?.console_messages || []).filter(
    (m) => !selectedId ||
      (m.run_id || m.completion_run_id || m.card?.run_id) === selectedId,
  );
  async function selectRun(id) {
    if (busy || !session) return;
    requestVersion.current += 1;
    setBusy(true);
    setError("");
    try {
      if (id) await resumeRunChat(id);
      else setSession(await api("/sessions/" + session.id + "/context", { run_id: null }));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function open(id) {
    try {
      setError("");
      const selected = await api("/lab/runs/" + id);
      setRun(selected);
      openLab(selected);
    } catch (e) {
      setError(e.message);
    }
  }
  async function send(text = message) {
    if (busy || !session || !text.trim()) return;
    requestVersion.current += 1;
    const draft = text.trim();
    setBusy(true);
    setError("");
    setOptimistic(draft);
    setMessage("");
    try {
      const result = await api("/sessions/" + session.id + "/console", {
        message: draft,
        run_id: selectedId,
      });
      setSession(result.session);
      setOptimistic("");
      if (result.started_run) setRun(result.started_run);
      await refresh();
    } catch (e) {
      setError(e.message);
      setMessage((current) => current || draft);
    } finally {
      setBusy(false);
      setOptimistic("");
    }
  }
  const targetName =
    overview.targets?.find(
      (t) => t.id === (preferences?.target_id || "local-incident"),
    )?.name || "Incident assistant";
  const readable = (content) =>
    runs.reduce(
      (text, saved) =>
        text
          .replaceAll(saved.id, runLabel(saved))
          .replaceAll(saved.id.slice(0, 8), runLabel(saved)),
      content,
    );
  return (
    <div className="cf-workspace">
      <div className="cf-heading">
        <div>
          <div className="eyebrow">
            <Sparkles size={14} /> SECURITY LAB WORKSPACE
          </div>
          <h1>
            Ask CounterForge<span className="title-dot">.</span>
          </h1>
          <p>Ask a question, configure a test, or start a run.</p>
        </div>
        <div className="cf-heading-actions">
          <button
            className="button"
            disabled={busy}
            onClick={async () => {
              requestVersion.current += 1;
              setBusy(true);
              try {
                await newChat();
              } finally {
                setBusy(false);
              }
            }}
          >
            <Plus size={16} /> New chat
          </button>
        </div>
      </div>
      <div className="cf-layout">
        <section className="cf-conversation panel">
          <div className="cf-chat-header">
            <div>
              <span className="cf-ai-icon">
                <Sparkles size={17} />
              </span>
              <div>
                <strong>CounterForge</strong>
              </div>
            </div>
            <select
              aria-label="Workspace conversation"
              value={session?.id || ""}
              disabled={busy}
              onChange={async (e) => {
                try {
                  setSession(await api("/sessions/" + e.target.value));
                } catch (err) {
                  setError(err.message);
                }
              }}
            >
              {overview.sessions.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id === session?.id && selectedRun ? runLabel(selectedRun) : s.title}
                </option>
              ))}
            </select>
          </div>
          <div className="cf-messages" aria-live="polite">
            {!messages.length && (
              <div className="cf-welcome">
                <span className="cf-welcome-icon">
                  <Sparkles size={28} />
                </span>
                <h2>How can I help?</h2>
                <p>
                  Try “Use the support assistant, defense off, one round.” Then
                  say “Start a new run.”
                </p>
                <p>
                  Ask “show settings” to check your setup, or “disable chat
                  runs” to pause chat launches.
                </p>
              </div>
            )}
            {messages.map((m) => (
              <div key={m.id} className={"cf-message " + m.role}>
                <span className="cf-message-icon">
                  {m.role === "assistant" ? (
                    <Sparkles size={16} />
                  ) : (
                    <UserRound size={16} />
                  )}
                </span>
                <div>
                  <div className="cf-message-meta">
                    <strong>
                      {m.role === "assistant" ? "CounterForge" : "You"}
                    </strong>
                    {m.role === "user" && <small>{date(m.timestamp)}</small>}
                  </div>
                  <MessageContent
                    content={readable(m.content)}
                    role={m.role}
                    detailed={m.detailed}
                  />
                  {m.card?.type === "history" && (
                    <div className="cf-inline-card">
                      <RunList
                        runs={m.card.runs}
                        selectedId={selectedId}
                        select={selectRun}
                        disabled={busy}
                        open={open}
                      />
                    </div>
                  )}
                  {m.card?.type === "run" && (
                    <div className="cf-run-actions">
                      <button
                        className="cf-run-link"
                        onClick={() => open(m.card.run_id)}
                      >
                        <FlaskConical size={15} />
                        {m.card.name ||
                          runLabel(runs.find((r) => r.id === m.card.run_id))}
                        <ArrowRight size={14} />
                      </button>
                    </div>
                  )}
                </div>
              </div>
            ))}
            {(session?.console_pending_runs || []).map((id) => {
              const active = runs.find((r) => r.id === id);
              return active && (!selectedId || selectedId === id) && ["queued", "running"].includes(active.status) ? (
                <div key={id} className="cf-run-progress" role="status">
                  <Loader2 size={15} className="spin" />
                  <span>
                    {runLabel(active)}:{" "}
                    {stageLabels[active.stage] || "In progress"}. Summary will
                    appear here automatically.
                  </span>
                </div>
              ) : null;
            })}
            {busy && (
              <>
                {optimistic && (
                  <div className="cf-message user">
                    <span className="cf-message-icon">
                      <UserRound size={16} />
                    </span>
                    <div className="cf-message-content">{optimistic}</div>
                  </div>
                )}
                <div className="cf-thinking">
                  <Loader2 size={15} className="spin" /> Working…
                </div>
              </>
            )}
            <div ref={bottom} />
          </div>
          {error && (
            <div className="cf-error" role="alert">
              <TriangleAlert size={15} />
              <span>{error}</span>
              <button
                aria-label="Dismiss workspace error"
                onClick={() => setError("")}
              >
                <X size={14} />
              </button>
            </div>
          )}
          <div className="cf-composer">
            {selectedRun ? (
              <div className="cf-analysis-context">
                <span>Selected: {runLabel(selectedRun)}</span>
                <button
                  aria-label="Clear selected run"
                  disabled={busy}
                  onClick={() => selectRun(null)}
                >
                  <X size={13} />
                </button>
              </div>
            ) : (
              <div className="cf-analysis-context">No run selected</div>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                send();
              }}
            >
              <textarea
                aria-label="Workspace message"
                placeholder="Ask CounterForge…"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                onKeyDown={(e) => {
                  if (
                    e.key === "Enter" &&
                    !e.shiftKey &&
                    !e.nativeEvent.isComposing
                  ) {
                    e.preventDefault();
                    send();
                  }
                }}
              />
              <button
                aria-label="Send workspace message"
                disabled={busy || !session || !message.trim()}
              >
                <Send size={18} />
              </button>
            </form>
            <div className="cf-composer-foot">
              <span>
                {targetName} · Defense{" "}
                {preferences?.apply_defense === false ? "off" : "on"} ·{" "}
                {preferences?.rounds || 2}{" "}
                {preferences?.rounds === 1 ? "round" : "rounds"}
                {preferences?.allow_runs === false
                  ? " · Chat runs disabled"
                  : ""}
              </span>
              <span>Enter to send</span>
            </div>
          </div>
        </section>
        <aside className="panel cf-activity" aria-label="Run activity">
          <div className="cf-section-title">
            <h3>
              <Clock3 size={15} /> Run activity
            </h3>
          </div>
          <p>Select a run to load its conversation. Use the arrow for Attack Lab details.</p>
          {runs.length ? (
            <RunList
              runs={runs.slice(0, 12)}
              selectedId={selectedId}
              select={selectRun}
              disabled={busy}
              open={open}
            />
          ) : (
            <p>No runs yet. Start one from chat.</p>
          )}
        </aside>
      </div>
    </div>
  );
}
