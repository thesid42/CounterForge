import asyncio
import json
import time
from threading import Event
import httpx
import pytest
from fastapi.testclient import TestClient
from backend.config import settings
from backend.alerts import SimulatedAlertDispatcher
from backend.console import ConsoleRequest, WorkspaceConsole, evidence, run_summary
from backend.fixtures import CANARY
from backend.main import create_app
from backend.service import LabService
from backend.storage import Store
from backend.workflow import make_graph, new_campaign, run_campaign


@pytest.fixture
def lab(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", True)
    monkeypatch.setattr(settings, "ALERT_MODE", "simulated")
    monkeypatch.setattr(settings, "OPENROUTER_API_KEY", "")
    monkeypatch.setattr(settings, "MODEL_MODE", "demo")
    monkeypatch.setattr(settings, "TARGET_BASE_URL", "")
    monkeypatch.setattr(settings, "DEFENDER_API_KEY", "")
    service = LabService(Store(":memory:"), SimulatedAlertDispatcher())
    with TestClient(create_app(service)) as client:
        sid = client.post("/api/sessions").json()["id"]
        yield service, client, sid


def test_history_is_persisted_and_does_not_invent_runs(lab):
    service, client, sid = lab
    response = client.post(f"/api/sessions/{sid}/console", json={"message": "Show previous runs"})
    assert response.status_code == 200
    result = response.json()
    assert result["started_run"] is None
    assert result["session"]["console_messages"][-1]["card"]["runs"] == []
    assert client.get(f"/api/sessions/{sid}").json()["console_messages"] == result["session"]["console_messages"]
    assert not service.store.list("run")


def test_run_commands_and_legacy_lab_share_admission_gate(lab):
    service, client, sid = lab
    response = client.post(f"/api/sessions/{sid}/console", json={"message": "Start a new run", "scenario": "runbook-injection"})
    run = response.json()["started_run"]
    assert run["scenario"] == "runbook-injection"
    assert run["timeline"][0]["stage"] == "queued"
    assert client.post("/api/lab/runs", json={"scenario": "all"}).status_code == 409
    assert len(service.store.list("run")) == 1


def test_analysis_and_invalid_selection_never_start_runs(lab):
    service, client, sid = lab
    response = client.post(f"/api/sessions/{sid}/console", json={"message": "Explain how to start a new run"}).json()
    assert response["started_run"] is None
    assert response["session"]["console_messages"][-1]["source"] == "configuration"
    assert client.post(f"/api/sessions/{sid}/console", json={"message": "Start a new run", "run_id": "missing"}).status_code == 404
    assert client.post(f"/api/sessions/{sid}/console", json={"message": "Start a new run", "scenario": "arbitrary-target"}).status_code == 422
    assert not service.store.list("run")


def test_live_replays_cannot_be_presented_or_activated_as_defense(lab):
    service, client, sid = lab
    old = {"id": "old-live", "mode": "local-simulation", "status": "completed", "validated": True, "results": [{"name": "Old finding", "baseline": {"mode": "dvaa", "verdict": "error"}, "defended": {"verdict": "blocked"}}]}
    service.store.put("run", old["id"], old)
    summary = client.get("/api/workspace").json()["runs"][0]
    assert summary["mode"] == "dvaa" and not summary["defense_verified"]
    assert summary["errors"] == 1 and summary["baseline_breaches"] == 0
    assert "repeated probe" in client.get("/api/reports/old-live").text
    assert client.post("/api/defenses/activate/old-live").status_code == 409


def test_glm_receives_sanitized_evidence_and_has_no_tools(lab, monkeypatch):
    service, client, sid = lab
    monkeypatch.setattr(settings, "DEFENDER_API_KEY", "sk-or-test-private")
    monkeypatch.setattr(settings, "DEFENDER_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setattr(settings, "DEFENDER_MODEL", "glm-5.3-flash")
    service.store.put("run", "selected", {"id": "selected", "status": "completed", "approval_token": "PRIVATE-TOKEN", "results": [{"id": "finding", "baseline": {"verdict": "succeeded", "output": CANARY + " dvaa-admin-secret sk-or-test-private", "dvaa_metadata": {"private": "PRIVATE-METADATA"}}}]})
    sent = []
    def respond(request):
        assert request.url == "https://openrouter.ai/api/v1/chat/completions"
        body = json.loads(request.content)
        sent.append(body)
        return httpx.Response(200, json={"choices": [{"message": {"content": "Evidence: run selected. dvaa-admin-secret"}}]})
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(respond), **kwargs))
    result = client.post(f"/api/sessions/{sid}/console", json={"message": "Explain this finding", "run_id": "selected"}).json()
    assistant = result["session"]["console_messages"][-1]
    serialized = json.dumps(sent)
    assert sent[0]["model"] == "z-ai/glm-5.3-flash"
    assert "tools" not in sent[0]
    for secret in (CANARY, "dvaa-admin-secret", "sk-or-test-private", "PRIVATE-TOKEN", "PRIVATE-METADATA"):
        assert secret not in serialized
    assert assistant["source"] == "z-ai/glm-5.3-flash"
    assert "dvaa-admin-secret" not in assistant["content"]
    assert result["started_run"] is None


def test_provider_failure_is_not_a_fabricated_answer(lab, monkeypatch):
    service, client, sid = lab
    monkeypatch.setattr(settings, "DEFENDER_API_KEY", "test-key")
    monkeypatch.setattr(settings, "DEFENDER_BASE_URL", "https://openrouter.ai/api/v1")
    monkeypatch.setattr(settings, "DEFENDER_MODEL", "glm-5.3-flash")
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(lambda _: httpx.Response(401, json={"error": "private key details"})), **kwargs))
    response = client.post(f"/api/sessions/{sid}/console", json={"message": "Explain the evidence"}).json()
    answer = response["session"]["console_messages"][-1]
    assert answer["source"] == "provider-error" and "401" in answer["content"]
    assert "private key details" not in answer["content"]
    assert not service.store.list("run")


def test_campaign_preserves_recorded_timeline(lab):
    service, client, sid = lab
    state = new_campaign(service, "all")
    asyncio.run(run_campaign(service, make_graph(service), state))
    run = service.store.get("run", state["id"])
    assert [e["stage"] for e in run["timeline"]] == ["queued", "generate", "execute", "inspect", "propose", "replay", "complete"]
    assert run["target_model"] == "Synthetic fixture"
    assert run_summary(run)["defense_verified"]


def test_fixture_run_honors_defense_off(lab):
    service, client, sid = lab
    state = new_campaign(service, "all", apply_defense=False)
    asyncio.run(run_campaign(service, make_graph(service), state))
    run = service.store.get("run", state["id"])
    assert run["status"] == "completed" and not run["validated"]
    assert all(r["defended"]["verdict"] == r["baseline"]["verdict"] == "succeeded" for r in run["results"])
    assert not run_summary(run)["defense_verified"]


def test_adaptive_live_summary_and_activation_keep_upstream_behavior(lab):
    service, client, sid = lab
    run = {"id": "adaptive-live", "mode": "adaptive-dvaa", "adaptive": True,
           "status": "completed", "validated": True, "base_version": service.policy.version,
           "candidate": {**service.policy.to_dict(), "version": service.policy.version + 1},
           "results": [{"name": "Adaptive attack", "baseline": {"mode": "dvaa", "verdict": "succeeded"},
                        "defended": {"verdict": "blocked", "defense_enforced": True, "defense_supported": True}}]}
    service.store.put("run", run["id"], run)
    summary = run_summary(run)
    assert summary["mode"] == "dvaa" and summary["defense_verified"]
    assert "generated defense" in summary["limitation"]
    assert "repeated probe" not in client.get("/api/reports/adaptive-live").text
    assert client.post("/api/defenses/activate/adaptive-live").status_code == 200


def test_workspace_start_respects_live_configuration_gate(lab, monkeypatch):
    service, client, sid = lab
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", False)
    response = client.post(f"/api/sessions/{sid}/console", json={"message": "Start a new run"})
    assert response.status_code == 409
    assert client.post("/api/lab/runs", json={"scenario": "all"}).status_code == 409
    assert not service.store.list("run")


def test_text_configuration_persists_and_controls_natural_chat_launches(lab):
    service, client, sid = lab
    launched = []
    async def start(request):
        launched.append(request)
        run = {"id": "internal-opaque-id", "name": "Support · Context check 1", "status": "queued", "results": []}
        service.store.put("run", run["id"], run)
        return run
    console = WorkspaceConsole(service, start)
    configured = asyncio.run(console.chat(sid, ConsoleRequest(message="Use the support assistant, defense off, one round, context check. Keep replies brief.")))
    assert configured["started_run"] is None
    assert configured["session"]["console_config"] == {"target_id": "local-support", "scenario": "data-extraction", "apply_defense": False, "rounds": 1, "allow_runs": True, "reply_style": "brief"}
    result = asyncio.run(console.chat(sid, ConsoleRequest(message="Could you start a new run?")))
    assert launched[0].target_id == "local-support"
    assert not launched[0].apply_defense and launched[0].rounds == 1
    assert "internal-opaque-id" not in result["session"]["console_messages"][-1]["content"]
    asyncio.run(console.chat(sid, ConsoleRequest(message="Disable chat runs")))
    with pytest.raises(ValueError, match="Chat runs are disabled"):
        asyncio.run(console.chat(sid, ConsoleRequest(message="Run the knowledge assistant with defense on")))
    assert len(launched) == 1
    asyncio.run(console.chat(sid, ConsoleRequest(message="Enable chat runs")))
    asyncio.run(console.chat(sid, ConsoleRequest(message="Please test the knowledge assistant with defense on, 2 rounds")))
    assert launched[-1].target_id == "local-research" and launched[-1].apply_defense and launched[-1].rounds == 2


def test_text_settings_reject_invalid_rounds_without_changing_configuration(lab):
    service, client, sid = lab
    assert client.post(f"/api/sessions/{sid}/console", json={"message": "Use support assistant, 99 rounds"}).status_code == 409
    assert "console_config" not in service.session(sid)
    response = client.post(f"/api/sessions/{sid}/console", json={"message": "Defense off"}).json()
    assert not response["session"]["console_config"]["apply_defense"]
    shown = client.post(f"/api/sessions/{sid}/console", json={"message": "Show settings"}).json()
    assert "defense off" in shown["session"]["console_messages"][-1]["content"]
    assert not service.store.list("run")


def test_brief_and_requested_details_have_separate_budgets_and_hide_run_ids(lab, monkeypatch):
    from backend.console import explain
    monkeypatch.setattr(settings, "DEFENDER_API_KEY", "test-key")
    sent = []
    opaque_id = "abcdef1234567890abcdef1234567890"
    original = httpx.AsyncClient
    def respond(request):
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": f"Run {opaque_id} observed a breach. " * 100}}]})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(respond), **kw))
    context = {"selected_run": {"id": opaque_id, "name": "Support · Context check 1"}}
    brief, _ = asyncio.run(explain("What happened?", [], context))
    detailed, _ = asyncio.run(explain("Give me details", [], context))
    assert len(brief.split()) <= 45 and len(detailed.split()) <= 120
    assert len(detailed.split()) > len(brief.split())
    assert opaque_id not in brief + detailed and "Support · Context check 1" in brief
    assert [r["max_tokens"] for r in sent] == [220, 450]


def test_analyst_has_consistent_plain_language_prompt_and_no_long_dashes(lab, monkeypatch):
    from backend.console import explain
    monkeypatch.setattr(settings, "DEFENDER_API_KEY", "test-key")
    captured = []
    original = httpx.AsyncClient
    def respond(request):
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "The target tried to reveal the test secret\u2014the defense blocked the tool. No secret escaped\u2013in this test."}}]})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(respond), **kw))
    answer, _ = asyncio.run(explain("What happened?", [], {"selected_run": None}))
    assert answer == "The target tried to reveal the test secret, the defense blocked the tool. No secret escaped, in this test."
    prompt = captured[0]["messages"][0]
    assert prompt["role"] == "system"
    for instruction in ("everyday language", "Never use em dashes", "'test secret' instead of 'synthetic canary'", "Distinguish unsafe model attempts from actual executed actions", "at most 35 words"):
        assert instruction in prompt["content"]


@pytest.mark.parametrize("question", ["Give details comparing the six latest context checks", "Compare previous runs"])
def test_comparison_questions_receive_all_recent_evidence(lab, monkeypatch, question):
    service, client, sid = lab
    monkeypatch.setattr(settings, "DEFENDER_API_KEY", "test-key")
    for index in range(6):
        service.store.put("run", f"run-{index}", {"id": f"run-{index}", "name": f"Context check {index}", "status": "completed", "created_at": str(index), "results": []})
    captured = []
    original = httpx.AsyncClient
    def respond(request):
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "All six recorded checks are available."}}]})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(respond), **kw))
    result = client.post(f"/api/sessions/{sid}/console", json={"message": question, "run_id": "run-5"}).json()
    context = captured[0]["messages"][-1]["content"]
    assert '"recent_runs"' in context
    assert all(f"Context check {index}" in context for index in range(6))
    assert result["session"]["console_messages"][-1]["card"]["type"] == "run"


def test_run_context_is_explicit_persistent_clearable_and_isolated_per_chat(lab, monkeypatch):
    service, client, sid = lab
    old = {"id": "old-run", "name": "Support · Context check 1", "status": "completed", "results": []}
    service.store.put("run", old["id"], old)
    captured = []
    async def explain(question, history, context, reply_style):
        captured.append((history, context))
        return "Select a run for results." if not context["selected_run"] else "This is the selected test.", "test"
    monkeypatch.setattr("backend.console.explain", explain)
    initial = client.post(f"/api/sessions/{sid}/console", json={"message": "What happened in this run?"}).json()
    assert captured[-1][1]["selected_run"] is None
    assert initial["session"]["console_run_id"] is None
    assert initial["session"]["console_messages"][-1]["card"] is None
    selected = client.post(f"/api/sessions/{sid}/context", json={"run_id": old["id"]}).json()
    assert selected["console_run_id"] == old["id"]
    assert client.get(f"/api/sessions/{sid}").json()["console_run_id"] == old["id"]
    client.post(f"/api/sessions/{sid}/console", json={"message": "Explain the attack"})
    assert captured[-1][1]["selected_run"]["id"] == old["id"]
    other = client.post("/api/sessions").json()
    assert other["title"] == "New chat" and other["console_run_id"] is None
    client.post(f"/api/sessions/{other['id']}/console", json={"message": "What happened?"})
    assert captured[-1][1]["selected_run"] is None
    assert client.post(f"/api/sessions/{sid}/context", json={"run_id": None}).json()["console_run_id"] is None
    client.post(f"/api/sessions/{sid}/console", json={"message": "What happened?"})
    history, context = captured[-1]
    assert context["selected_run"] is None
    assert not any(m.get("run_id") == old["id"] for m in history)
    assert client.post(f"/api/sessions/{sid}/context", json={"run_id": "missing"}).status_code == 404
    assert client.get(f"/api/sessions/{sid}").json()["console_run_id"] is None
    client.post(f"/api/sessions/{sid}/console", json={"message": "Explain the latest run"})
    assert captured[-1][1]["selected_run"]["id"] == old["id"]
    client.post(f"/api/sessions/{sid}/console", json={"message": "Hello", "run_id": None})
    assert captured[-1][1]["selected_run"] is None


@pytest.mark.parametrize("message", ["defense of do a run on one of teh assitants", "Defense off, do a run", "Can you do a new run with defense off?", "Perform a test without defense"])
def test_natural_run_requests_start_new_runs_instead_of_explaining_old_evidence(lab, message):
    service, client, sid = lab
    service.store.put("run", "old", {"id": "old", "status": "completed", "results": []})
    launched = []
    async def start(request):
        launched.append(request)
        return {"id": "new", "name": "Incident · Context check 2"}
    console = WorkspaceConsole(service, start)
    asyncio.run(console.select_run(sid, "old"))
    result = asyncio.run(console.chat(sid, ConsoleRequest(message=message)))
    assert len(launched) == 1 and not launched[0].apply_defense
    assert result["started_run"]["id"] == result["session"]["console_run_id"] == "new"
    assert result["session"]["console_messages"][-1]["card"]["run_id"] == "new"
    assert "Started Incident" in result["session"]["console_messages"][-1]["content"]


@pytest.mark.parametrize("message", ["Explain how to do a run", "What happened when I said defense off do a run?", "What does perform a test mean?"])
def test_questions_about_run_commands_do_not_launch(lab, message):
    from backend.chat_commands import parse_command, default_preferences
    command, _ = parse_command(message, default_preferences(), [])
    assert command is None


def test_completion_is_automatically_posted_once_to_origin_chat_without_a_status_question(lab, monkeypatch):
    service, client, sid = lab
    release = Event()
    async def campaign(service, graph, state):
        while not release.is_set():
            await asyncio.sleep(.01)
        service.store.put("run", state["id"], {**state, "status": "completed", "results": [{
            "id": "data-extraction-r1", "baseline": {"verdict": "succeeded", "canary_leaked": True},
            "defended": {"verdict": "succeeded"}}]})
    monkeypatch.setattr("backend.main.run_campaign", campaign)
    started = client.post(f"/api/sessions/{sid}/console", json={"message": "Start a new run with defense off"}).json()
    run_id = started["started_run"]["id"]
    assert started["session"]["console_pending_runs"] == [run_id]
    assert len(started["session"]["console_messages"]) == 2
    client.post(f"/api/sessions/{sid}/context", json={"run_id": None})
    other = client.post("/api/sessions").json()
    release.set()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        session = service.session(sid)  # Prove the completion worker posts it without a read endpoint.
        if any(m.get("completion_run_id") == run_id for m in session["console_messages"]):
            break
        time.sleep(.01)
    updates = [m for m in session["console_messages"] if m.get("completion_run_id")]
    assert len(updates) == 1
    assert "requests for protected context" in updates[0]["content"]
    assert "1 of 1" in updates[0]["content"] and "No defense was tested" in updates[0]["content"]
    assert updates[0]["detailed"] and updates[0]["content"].count("\n\n") >= 2
    assert sum(m["role"] == "user" for m in session["console_messages"]) == 1
    assert session["console_run_id"] is None and session["console_pending_runs"] == []
    assert client.get(f"/api/sessions/{other['id']}").json()["console_messages"] == []
    assert len(client.get(f"/api/sessions/{sid}").json()["console_messages"]) == 3
    assert len(client.get(f"/api/sessions/{sid}").json()["console_messages"]) == 3


def test_completion_summary_explains_methods_counts_partial_checks_and_alert_acceptance():
    from backend.console import completion_summary
    run = {"id": "internal", "name": "Support · Full security check 2", "status": "completed", "apply_defense": True,
           "results": [{"id": "runbook-injection-r1", "baseline": {"verdict": "succeeded", "canary_leaked": True}, "defended": {"verdict": "blocked"}},
                       {"id": "role-escalation-r1", "baseline": {"verdict": "error"}, "defended": {"verdict": "skipped"}}],
           "page": {"mode": "twilio_voice", "status": "Accepted"}}
    text = completion_summary(run)
    assert "instructions hidden in runbooks" in text and "fake operator authority" in text
    assert "Without defense, 1 of 1" in text and "With defense, 0 of 1" in text
    assert "results are incomplete" in text and "Voice alert accepted" in text
    assert "answered" not in text and "internal" not in text and "\u2014" not in text
    unsupported = completion_summary({**run, "results": [{"baseline": {"verdict": "succeeded"}, "defended": {"verdict": "blocked", "defense_supported": False}}]})
    assert "do not measure defense effectiveness" in unsupported
    failed = completion_summary({"id": "failed", "status": "failed", "results": []})
    assert "stopped before finishing" in failed and "No attack results" in failed


def test_finished_run_catches_up_after_reload_but_is_not_duplicated(lab):
    service, client, sid = lab
    service.store.put("run", "finished", {"id": "finished", "status": "failed", "results": []})
    session = service.session(sid)
    session["console_messages"] = [{"id": "launch", "role": "assistant", "source": "Run controller", "card": {"type": "run", "run_id": "finished"}}]
    service.store.put("session", sid, session)
    first = client.get(f"/api/sessions/{sid}").json()
    second = client.get(f"/api/sessions/{sid}").json()
    assert first == second and len(first["console_messages"]) == 2
    assert first["console_messages"][-1]["completion_run_id"] == "finished"
    assert first["console_run_id"] is None


def test_lab_started_run_can_be_watched_even_if_it_finished_before_chat_attached(lab):
    service, client, sid = lab
    service.store.put("run", "fast", {"id": "fast", "status": "completed", "results": []})
    client.post(f"/api/sessions/{sid}/context", json={"run_id": "fast", "watch": True})
    session = client.get(f"/api/sessions/{sid}").json()
    assert len(session["console_messages"]) == 1
    assert session["console_messages"][0]["completion_run_id"] == "fast"


def test_report_uses_automatic_voice_delivery_instead_of_pending_manual_action(lab):
    service, client, sid = lab
    service.store.put("run", "paged", {"id": "paged", "status": "completed", "results": [], "page": {"mode": "twilio_voice", "status": "Accepted"}})
    report = client.get("/api/reports/paged").text
    assert "Twilio alert request: Accepted" in report
    assert "does not prove the responder answered" in report


def test_continue_in_chat_restores_origin_and_does_not_mix_new_conversations(lab):
    service, client, sid = lab
    service.store.put("run", "owned", {"id": "owned", "status": "completed", "results": []})
    origin = service.session(sid)
    origin["console_messages"] = [{"id": "start", "role": "assistant", "source": "Run controller", "card": {"run_id": "owned"}}]
    service.store.put("session", sid, origin)
    client.get(f"/api/sessions/{sid}")  # Catch up its saved completion.
    other = client.post("/api/sessions").json()
    resumed = client.post("/api/lab/runs/owned/chat", json={"session_id": other["id"]}).json()
    assert resumed["id"] == sid and resumed["console_run_id"] == "owned"
    assert len(resumed["console_messages"]) == 2
    assert client.get(f"/api/sessions/{other['id']}").json()["console_messages"] == []
    service.store.put("run", "external", {"id": "external", "status": "completed", "results": []})
    attached = client.post("/api/lab/runs/external/chat", json={"session_id": other["id"]}).json()
    assert attached["id"] == other["id"] and attached["console_run_id"] == "external"
    assert attached["console_messages"][0]["completion_run_id"] == "external"
    assert client.post("/api/lab/runs/external/chat", json={"session_id": sid}).json()["id"] == other["id"]
    assert client.post("/api/lab/runs/missing/chat", json={"session_id": other["id"]}).status_code == 404


def test_switch_run_conversation_restores_running_run_and_keeps_updates_in_origin(lab):
    service, client, sid = lab
    service.store.put("run", "active", {"id": "active", "status": "running", "results": []})
    service.store.put("run", "older", {"id": "older", "status": "completed", "results": []})
    origin = service.session(sid)
    origin["console_messages"] = [{"id": "launch", "role": "assistant", "run_id": "active", "source": "Run controller", "card": {"run_id": "active"}}]
    origin["console_pending_runs"] = ["active"]
    service.store.put("session", sid, origin)
    older = client.post("/api/lab/runs/older/chat", json={"session_id": sid}).json()
    assert older["id"] != sid and older["console_run_id"] == "older"
    active = client.post("/api/lab/runs/active/chat", json={"session_id": older["id"]}).json()
    assert active["id"] == sid and active["console_run_id"] == "active"
    assert active["console_pending_runs"] == ["active"]
    assert len(active["console_messages"]) == 1
    service.store.put("run", "active", {"id": "active", "status": "completed", "results": []})
    completed = client.get(f"/api/sessions/{sid}").json()
    assert completed["console_messages"][-1]["completion_run_id"] == "active"
    assert completed["console_pending_runs"] == []
    assert all(m.get("run_id") == "older" for m in client.get(f"/api/sessions/{older['id']}").json()["console_messages"])
    assert client.post("/api/lab/runs/active/chat", json={"session_id": older["id"]}).json() == completed
