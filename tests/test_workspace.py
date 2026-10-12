import asyncio
import json
import httpx
import pytest
from fastapi.testclient import TestClient
from backend.config import settings
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
    service = LabService(Store(":memory:"))
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
        return {"id": "internal-opaque-id", "name": "Support · Context check 1"}
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
