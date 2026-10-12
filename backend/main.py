import asyncio
import os
from uuid import uuid4
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from .fixtures import INCIDENTS
from .config import settings
from .console import (
    ConsoleRequest,
    ResumeRunRequest,
    RunContextRequest,
    WorkspaceConsole,
    assistant_config,
    run_summary,
    activity_runs,
)
from .models import ApprovalRequest, ChatRequest, LabBatchRequest, LabRequest
from .roles import live_lab_ready, role_models_configured
from .service import LabService, now
from .workflow import make_graph, new_campaign, run_campaign
from .agents import AgentRegistration, PERSONAS, register_agent, resolve_target, target_catalog
from .policy import redact
from .run_names import run_name


def create_app(service=None):
    service = service or LabService()
    tasks = set()

    async def drain_runs():
        while True:
            pending = sorted((r for r in service.store.list("run") if r["status"] == "queued"), key=lambda r: r.get("created_at", ""))
            if not pending:
                return
            state = {**pending[0], "status": "running"}
            service.store.put("run", state["id"], state)
            await run_campaign(service, graph, state)
            await console.publish_run_completion(state["id"])
            agent = service.store.get("agent", state.get("target", {}).get("id", "")) if state.get("target") else None
            if agent:
                result = service.store.get("run", state["id"])
                service.store.put("agent", agent["id"], {**agent, "last_run_id": state["id"], "status": result["status"]})

    def schedule():
        if not any(not t.done() for t in tasks):
            task = asyncio.create_task(drain_runs())
            tasks.add(task)
            task.add_done_callback(tasks.discard)

    @asynccontextmanager
    async def lifespan(app):
        for run in service.store.list("run"):
            if run["status"] in {"running", "batched"}:
                service.store.put("run", run["id"], {**run, "status": "failed", "stage": "error", "error": "Backend restarted during evaluation"})
        for batch in service.store.list("batch"):
            if batch["status"] == "running":
                await finalize_batch(batch["id"])
        for session in service.store.list("session"):
            await console.sync_run_updates(session["id"])
        schedule()
        yield
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    app = FastAPI(title="CounterForge", lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"])
    app.state.service = service
    graph = make_graph(service)

    async def launch(payload, enqueue=False):
        if any(not t.done() for t in tasks) and not enqueue:
            raise HTTPException(409, "A comparison is already running")
        if not live_lab_ready() and not (payload.target_id and role_models_configured()) and not settings.ALLOW_SIMULATION:
            raise HTTPException(
                409,
                "Live lab is not configured. Set MODEL_MODE=live, TARGET_BASE_URL, and OpenRouter attacker/defender keys.",
            )
        try:
            target = resolve_target(service, payload.target_id) if payload.target_id else None
            state = new_campaign(service, payload.scenario, apply_defense=payload.apply_defense,
                                 target=target, autonomous=payload.autonomous, rounds=payload.rounds)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        queued = {**state, "status": "queued"}
        service.store.put("run", state["id"], queued)
        schedule()
        return queued if enqueue else state

    async def run_batch(batch_id, states):
        limit = asyncio.Semaphore(max(1, int(os.getenv("LAB_PARALLEL", "4"))))

        async def one(state):
            async with limit:
                running = {**state, "status": "running"}
                service.store.put("run", state["id"], running)
                try:
                    await run_campaign(service, graph, running)
                except Exception:
                    latest = service.store.get("run", state["id"]) or running
                    service.store.put("run", state["id"], {**latest, "status": "failed", "stage": "error", "error": "Evaluation could not finish"})

        await asyncio.gather(*(one(s) for s in states), return_exceptions=True)
        await finalize_batch(batch_id)
        # Schedule queued registrations after this batch releases admission.
        asyncio.get_running_loop().call_soon(schedule)

    async def finalize_batch(batch_id):
        batch = service.store.get("batch", batch_id)
        members = [service.store.get("run", rid) for rid in batch["run_ids"]]
        batch = {**batch, "status": "failed" if any(r["status"] == "failed" for r in members) else "completed", "completed_at": now()}
        findings = service.record_lab_findings({"id": batch_id, "results": [row for r in members for row in r.get("results", [])]})
        if findings:
            batch.update(security_incident_id=findings["incident"]["id"], alert_action_id=findings["action"]["id"], page=findings.get("page"))
            incident = findings["incident"]
            incident.update(title=batch.get("name", "Multi-agent test"), run_ids=batch["run_ids"], batch_id=batch_id)
            service.store.put("incident", incident["id"], incident)
            for r in members:
                service.store.put("run", r["id"], {**r, "security_incident_id": incident["id"], "alert_action_id": findings["action"]["id"], "page": findings.get("page")})
        service.store.put("batch", batch_id, batch)
        for r in members:
            await console.publish_run_completion(r["id"])

    def batch_view(batch):
        runs = [service.store.get("run", rid) or {} for rid in batch["run_ids"]]
        rows = []
        for r in runs:
            results = r.get("results") or []
            rows.append({"run_id": r.get("id"), "target": (r.get("target") or {}).get("name"),
                         "port": (r.get("target") or {}).get("port"), "status": r.get("status"), "stage": r.get("stage"),
                         "attacks": len(results),
                         "breaches": sum((x.get("baseline") or {}).get("verdict") == "succeeded" for x in results),
                         "blocked_after": sum((x.get("defended") or {}).get("verdict") == "blocked" for x in results),
                         "page": (r.get("page") or {}).get("status"), "error": r.get("error")})
        return {**batch, "runs": rows}

    async def launch_batch(payload: LabBatchRequest):
        if any(not t.done() for t in tasks):
            raise HTTPException(409, "A comparison is already running")
        if not live_lab_ready() and not role_models_configured() and not settings.ALLOW_SIMULATION:
            raise HTTPException(409, "Live lab is not configured.")
        if payload.workspace_session_id:
            try:
                service.session(payload.workspace_session_id)
            except KeyError as exc:
                raise HTTPException(404, "Workspace conversation not found") from exc
        batch_id = uuid4().hex
        states = []
        try:
            targets = [resolve_target(service, tid) for tid in dict.fromkeys(payload.target_ids)]
            for target in targets:
                state = new_campaign(service, payload.scenario, apply_defense=payload.apply_defense,
                                     target=target, autonomous=False, rounds=payload.rounds)
                state = {**state, "batch_id": batch_id, "status": "batched"}
                service.store.put("run", state["id"], state)
                states.append(state)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        batch = {"id": batch_id, "name": f"Multi-agent test {len(service.store.list('batch')) + 1}", "status": "running", "created_at": now(), "scenario": payload.scenario,
                 "apply_defense": payload.apply_defense, "run_ids": [s["id"] for s in states]}
        service.store.put("batch", batch_id, batch)
        if payload.workspace_session_id:
            await console.record_lab_launch(
                payload.workspace_session_id, states, batch=True
            )
        task = asyncio.create_task(run_batch(batch_id, states))
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return batch_view(batch)

    @app.post("/api/lab/batches")
    async def start_batch(payload: LabBatchRequest):
        return await launch_batch(payload)

    @app.get("/api/lab/batches")
    def list_batches():
        return sorted((batch_view(b) for b in service.store.list("batch")), key=lambda b: b["created_at"], reverse=True)[:10]

    @app.get("/api/lab/batches/{bid}")
    def get_batch(bid: str):
        batch = service.store.get("batch", bid)
        if not batch:
            raise HTTPException(404, "Batch not found")
        return batch_view(batch)

    console = WorkspaceConsole(service, launch, launch_batch)

    @app.get("/api/agents")
    def agents():
        return {"targets": target_catalog(service), "personas": PERSONAS}

    @app.post("/api/agents")
    async def register(payload: AgentRegistration):
        if payload.auto_run and not role_models_configured() and not settings.ALLOW_SIMULATION:
            raise HTTPException(409, "Configure attacker and defender models before starting an autonomous evaluation")
        agent, created = register_agent(service, payload)
        started = None
        if created and payload.auto_run:
            started = await launch(LabRequest(target_id=agent["id"], scenario=payload.scenario, apply_defense=payload.apply_defense, rounds=payload.rounds), enqueue=True)
            agent = {**agent, "last_run_id": started["id"], "status": "queued"}
            service.store.put("agent", agent["id"], agent)
        return {"agent": agent, "started_run": started, "created": created}

    @app.get("/api/workspace")
    def workspace():
        runs = sorted(service.store.list("run"), key=lambda r: r.get("created_at", ""), reverse=True)
        return {"assistant": assistant_config(), "runs": activity_runs(service),
                "target_model": settings.TARGET_MODEL or "Synthetic fixture", "target_mode": "dvaa" if settings.MODEL_MODE != "demo" and settings.TARGET_BASE_URL else "local-simulation"}

    @app.post("/api/sessions/{sid}/console")
    async def console_chat(sid: str, payload: ConsoleRequest):
        try:
            return await console.chat(sid, payload)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/sessions/{sid}/context")
    async def select_chat_run(sid: str, payload: RunContextRequest):
        try:
            return await console.select_run(sid, payload.run_id, payload.watch)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.middleware("http")
    async def local_origin(request: Request, call_next):
        # Single-user local lab: reject cross-site browser mutations.
        origin = request.headers.get("origin")
        if request.method not in {"GET", "HEAD", "OPTIONS"} and origin and origin not in {"http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:8000", "http://localhost:8000"}:
            return PlainTextResponse("Origin not allowed", status_code=403)
        return await call_next(request)

    def guarded(fn, *args):
        try:
            return fn(*args)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.get("/api/health")
    def health():
        live = settings.MODEL_MODE != "demo" and bool(settings.TARGET_BASE_URL)
        adaptive = live_lab_ready() or (settings.MODEL_MODE != "demo" and role_models_configured())
        return {
            "status": "ok",
            "name": "CounterForge",
            "model_mode": settings.MODEL_MODE,
            "target_mode": "dvaa" if live else "unconfigured",
            "role_mode": "adaptive" if adaptive else "unconfigured",
            "lab_ready": adaptive,
            "attacker_model": settings.ATTACKER_MODEL if adaptive else None,
            "defender_model": settings.DEFENDER_MODEL if adaptive else None,
            "attack_rounds": settings.ADAPTIVE_ATTACK_ROUNDS if adaptive else 0,
            "alert_mode": service.alert_dispatcher.mode,
            "policy_version": service.policy.version,
        }

    @app.get("/api/overview")
    def overview():
        adaptive = live_lab_ready() or (settings.MODEL_MODE != "demo" and role_models_configured())
        return {
            "sessions": [{"id": s["id"], "title": s["title"]} for s in service.store.list("session")],
            "incidents": service.store.list("incident"),
            "actions": service.store.list("action"),
            "runs": sorted(service.store.list("run"), key=lambda r: r.get("created_at") or "", reverse=True),
            "policy": service.policy.to_dict(),
            "can_rollback": bool(service.store.list("policy_history")),
            "fixtures": list(INCIDENTS.values()),
            "mode": "live" if adaptive else ("live" if settings.MODEL_MODE != "demo" else "demo"),
            "role_mode": "adaptive" if adaptive else "unconfigured",
            "lab_ready": adaptive,
            "attacker_model": settings.ATTACKER_MODEL if adaptive else None,
            "defender_model": settings.DEFENDER_MODEL if adaptive else None,
            "attack_rounds": settings.ADAPTIVE_ATTACK_ROUNDS if adaptive else 0,
            "alert_mode": service.alert_dispatcher.mode,
            "active_defense": service.get_active_defense(),
            "targets": target_catalog(service),
            "personas": PERSONAS,
        }

    @app.post("/api/sessions")
    def new_session():
        return service.new_session()

    @app.get("/api/sessions/{sid}")
    async def session(sid: str):
        try:
            return await console.sync_run_updates(sid)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/sessions/{sid}/chat")
    async def chat(sid: str, payload: ChatRequest):
        try:
            return await service.chat(sid, payload)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @app.post("/api/actions/{aid}/approve")
    def approve(aid: str, payload: ApprovalRequest):
        return guarded(service.approve_action, aid, payload.token)

    @app.post("/api/incidents/{iid}/{operation}")
    def incident_status(iid: str, operation: Literal["acknowledge", "resolve"]):
        return guarded(service.update_incident, iid, "Acknowledged" if operation == "acknowledge" else "Resolved")

    @app.post("/api/lab/runs")
    async def start_run(payload: LabRequest):
        if payload.workspace_session_id:
            try:
                service.session(payload.workspace_session_id)
            except KeyError as exc:
                raise HTTPException(404, "Workspace conversation not found") from exc
        started = await launch(payload)
        if payload.workspace_session_id:
            await console.record_lab_launch(
                payload.workspace_session_id, [started]
            )
        return started

    @app.get("/api/lab/runs/{rid}")
    def run(rid: str):
        value = service.store.get("run", rid)
        if not value:
            raise HTTPException(404, "Run not found")
        return value

    @app.post("/api/lab/runs/{rid}/chat")
    async def resume_run_chat(rid: str, payload: ResumeRunRequest):
        try:
            return await console.resume_run_chat(rid, payload.session_id)
        except KeyError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post("/api/defenses/activate/{rid}")
    def activate(rid: str):
        return guarded(service.activate, rid)

    @app.post("/api/defenses/rollback")
    def rollback():
        return guarded(service.rollback)

    @app.post("/api/defenses/clear")
    def clear_defense():
        return service.clear_active_defense()

    @app.get("/api/reports/{rid}")
    def report(rid: str, format: Literal["json", "markdown"] = "markdown"):
        value = run(rid)
        if format == "json":
            return value
        action = service.store.get("action", value.get("alert_action_id", ""))
        delivery = value.get("page") or (action or {}).get("delivery", {})
        if delivery.get("mode") == "twilio_voice":
            status = delivery["status"]
            alert_note = f"Twilio alert request: {status}."
            if status == "Accepted":
                alert_note += " Provider acceptance does not prove the responder answered."
        else:
            alert_note = "No live alert provider was called."
        if value.get("mode") == "managed-agent":
            mode_note = f"Model-backed {value.get('target', {}).get('persona', 'assistant')} persona, model {value.get('target_model')}, disposable local tools. Replay rules: {'on' if value.get('apply_defense') else 'off'}."
        elif value.get("adaptive"):
            mode_note = f"Adaptive model evaluation with attacker {value.get('role_models', {}).get('attacker')} and defender {value.get('role_models', {}).get('defender')} against the local DVAA target."
        elif value.get("mode") == "dvaa":
            mode_note = "Live local DVAA target evaluation."
        else:
            mode_note = "Simulation fallback (tests only). No hosted LLM was called."
        if not value.get("adaptive") and run_summary(value)["mode"] == "dvaa":
            mode_note += " Replay is a repeated probe; candidate policy is not enforced in the target."
        lines = ["# CounterForge evaluation", "", f"Mode: {mode_note} {alert_note}", f"Run: {run_name(value)}", f"Status: {value['status']}", "", "| Scenario | Baseline | Defense |", "| --- | --- | --- |"]
        lines.extend(f"| {r['name']} | {r['baseline']['verdict']} | {r.get('defended', {}).get('verdict', 'pending')} |" for r in value.get("results", []))
        for row in value.get("results", []):
            lines.extend(["", "## " + row["name"], "", "Attack payload:", "", redact(str(row.get("payload", ""))), "", "Target response (rules off):", "", redact(str(row.get("baseline", {}).get("response_content") or row.get("baseline", {}).get("output", ""))), "", "Target response (replay):", "", redact(str(row.get("defended", {}).get("response_content") or row.get("defended", {}).get("output", "")))])
        lines.extend(["", "Regression checks: " + json.dumps(value.get("validation", {})), "", "Candidate validated: " + str(value.get("validated", False)), "", "Protected markers are redacted. Outcomes apply only to this synthetic, isolated lab configuration."])
        return PlainTextResponse("\n".join(lines), headers={"Content-Disposition": f'attachment; filename="counterforge-{rid[:8]}.md"'})

    @app.get("/api/events/{scope}")
    async def events(scope: str, request: Request):
        if not service.store.get("session", scope) and not service.store.get("run", scope):
            raise HTTPException(404, "Event scope not found")
        queue = service.broker.subscribe(scope)
        async def stream():
            try:
                yield ": connected\n\n"
                while not await request.is_disconnected():
                    try:
                        value = await asyncio.wait_for(queue.get(), 10)
                        yield f"data: {json.dumps(value)}\n\n"
                        if value.get("type") == "finished":
                            break
                    except asyncio.TimeoutError:
                        yield ": heartbeat\n\n"
            finally:
                service.broker.unsubscribe(scope, queue)
        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})

    dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
    if dist.exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")
        @app.get("/")
        def index():
            return FileResponse(dist / "index.html")
    return app


app = create_app()
