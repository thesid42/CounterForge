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

function RunList({ runs, selectedId, open }) {
  return (
    <div className="cf-recent">
      {runs.map((r) => (
        <button
          key={r.id}
          className={selectedId === r.id ? "selected" : ""}
          onClick={() => open(r.id)}
          aria-label={`Open ${runLabel(r)} in Attack Lab`}
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
          ) : (
            <ArrowRight size={14} />
          )}
        </button>
      ))}
    </div>
  );
}

function MessageContent({ content, role, detailed }) {
  const [expanded, setExpanded] = useState(!!detailed);
  const words = content.split(/\s+/);
  const long = role === "assistant" && words.length > 45;
  return (
    <>
      <div className="cf-message-content">
        {long && !expanded ? words.slice(0, 40).join(" ") + "…" : content}
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
  openIncidentDemo,
}) {
  const [workspace, setWorkspace] = useState(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [optimistic, setOptimistic] = useState("");
  const bottom = useRef(null);
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
    bottom.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [session?.console_messages?.length, busy]);
  useEffect(() => setMessage(""), [session?.id]);
  const runs = workspace?.runs || [];
  const preferences = session?.console_config;
  const messages = session?.console_messages || [];
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
    const draft = text.trim();
    setBusy(true);
    setError("");
    setOptimistic(draft);
    setMessage("");
    try {
      const result = await api("/sessions/" + session.id + "/console", {
        message: draft,
        run_id: run?.id || null,
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
            Your lab. In conversation<span className="title-dot">.</span>
          </h1>
          <p>Ask a question, configure a test, or start a run.</p>
        </div>
        <div className="cf-heading-actions">
          <button className="cf-text-button" onClick={openIncidentDemo}>
            Incident demo <ArrowRight size={14} />
          </button>
          <button className="button" disabled={busy} onClick={newChat}>
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
                <small>Evidence analyst</small>
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
                  {s.title}
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
                <h2>What would you like to test?</h2>
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
                  {m.role === "assistant" ? <Sparkles size={16} /> : "S"}
                </span>
                <div>
                  <div className="cf-message-meta">
                    <strong>
                      {m.role === "assistant" ? "CounterForge" : "You"}
                    </strong>
                    <small>
                      {m.role === "assistant"
                        ? [
                            "Chat settings",
                            "Run controller",
                            "Saved evidence",
                          ].includes(m.source)
                          ? m.source
                          : "Evidence analyst"
                        : date(m.timestamp)}
                    </small>
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
                        selectedId={run?.id}
                        open={open}
                      />
                    </div>
                  )}
                  {m.card?.type === "run" && (
                    <button
                      className="cf-run-link"
                      onClick={() => open(m.card.run_id)}
                    >
                      <FlaskConical size={15} />
                      {m.card.name ||
                        runLabel(runs.find((r) => r.id === m.card.run_id))}
                      <ArrowRight size={14} />
                    </button>
                  )}
                </div>
              </div>
            ))}
            {busy && (
              <>
                {optimistic && (
                  <div className="cf-message user">
                    <span className="cf-message-icon">S</span>
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
            {run && (
              <div className="cf-analysis-context">
                Asking about {runLabel(run)}
              </div>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                send();
              }}
            >
              <textarea
                aria-label="Workspace message"
                placeholder="Ask about a run, change settings, or say “start a new run”…"
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
          <p>Open a run for its results in Attack Lab.</p>
          {runs.length ? (
            <RunList
              runs={runs.slice(0, 12)}
              selectedId={run?.id}
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
