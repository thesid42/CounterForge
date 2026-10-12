import asyncio
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
from .models import ApprovalRequest, ChatRequest, LabRequest
from .roles import live_lab_ready, role_models_configured
from .service import LabService
from .workflow import make_graph, new_campaign, run_campaign


def create_app(service=None):
    service = service or LabService()
    tasks = set()

    @asynccontextmanager
    async def lifespan(app):
        for run in service.store.list("run"):
            if run["status"] == "running":
                service.store.put("run", run["id"], {**run, "status": "failed", "stage": "error", "error": "Backend restarted during evaluation"})
        yield
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    app = FastAPI(title="CounterForge", lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"])
    app.state.service = service
    graph = make_graph(service)

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
        adaptive = live_lab_ready()
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
        adaptive = live_lab_ready()
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
        }

    @app.post("/api/sessions")
    def new_session():
        return service.new_session()

    @app.get("/api/sessions/{sid}")
    def session(sid: str):
        return guarded(service.session, sid)

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
        if any(not t.done() for t in tasks):
            raise HTTPException(409, "A comparison is already running")
        if not live_lab_ready() and not settings.ALLOW_SIMULATION:
            raise HTTPException(
                409,
                "Live lab is not configured. Set MODEL_MODE=live, TARGET_BASE_URL, and OpenRouter attacker/defender keys.",
            )
        try:
            state = new_campaign(service, payload.scenario, apply_defense=payload.apply_defense)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        task = asyncio.create_task(run_campaign(service, graph, state))
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return state

    @app.get("/api/lab/runs/{rid}")
    def run(rid: str):
        value = service.store.get("run", rid)
        if not value:
            raise HTTPException(404, "Run not found")
        return value

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
        if action and action.get("delivery", {}).get("mode") == "twilio_voice":
            status = action["delivery"]["status"]
            alert_note = f"Twilio alert request: {status}."
            if status == "Accepted":
                alert_note += " Provider acceptance does not prove the responder answered."
        else:
            alert_note = "No live alert provider was called."
        if value.get("adaptive"):
            mode_note = f"Adaptive model evaluation with attacker {value.get('role_models', {}).get('attacker')} and defender {value.get('role_models', {}).get('defender')} against the local DVAA target."
        elif value.get("mode") == "dvaa":
            mode_note = "Live local DVAA target evaluation."
        else:
            mode_note = "Simulation fallback (tests only). No hosted LLM was called."
        lines = ["# CounterForge evaluation", "", f"Mode: {mode_note} {alert_note}", f"Run: {rid}", f"Status: {value['status']}", "", "| Scenario | Baseline | Defense |", "| --- | --- | --- |"]
        lines.extend(f"| {r['name']} | {r['baseline']['verdict']} | {r.get('defended', {}).get('verdict', 'pending')} |" for r in value.get("results", []))
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
