import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from time import time
import pytest
from fastapi.testclient import TestClient
from backend.events import EventBroker
from backend.fixtures import ATTACKS, CANARY
from backend.main import create_app
from backend.models import ChatRequest
from backend.policy import Policy, check_output, evaluate_tool
from backend.service import LabService, execute_lab_attack
from backend.storage import Store
from backend.workflow import make_graph, new_campaign, run_campaign


@pytest.fixture
def service():
    return LabService(Store(":memory:"))


@pytest.fixture
def client(service):
    with TestClient(create_app(service)) as client:
        yield client


@pytest.mark.parametrize("attack", ATTACKS)
def test_baseline_and_defended_execution_have_observable_side_effects(attack):
    baseline = execute_lab_attack(attack, Policy(export_allowlist=False, protect_context=False, responder_allowlist=False))
    defended = execute_lab_attack(attack, Policy(block_untrusted_actions=True))
    assert baseline["verdict"] == "succeeded"
    assert baseline["canary_leaked"] or baseline["unauthorized_actions"]
    assert defended["verdict"] == "blocked"
    assert not defended["canary_leaked"] and defended["unauthorized_actions"] == 0
    assert CANARY not in json.dumps(baseline) + json.dumps(defended)


def test_permissions_do_not_depend_on_attack_wording():
    assert not evaluate_tool(Policy(), "unknown_shell", {"cmd": "echo hello"}).allowed
    assert not evaluate_tool(Policy(), "export_incident", {"destination": "internal-archive"}).allowed
    assert not evaluate_tool(Policy(), "request_page", {"responder_id": "stranger"}).allowed
    assert evaluate_tool(Policy(), "request_page", {"responder_id": "primary"}).allowed
    assert not evaluate_tool(Policy(block_untrusted_actions=True), "request_page", {"responder_id": "primary"}, "runbook").allowed


def test_output_gate_detects_case_and_fragment_disclosure():
    assert not check_output(CANARY.lower())
    assert not check_output("The key contains fake and 8427")
    assert check_output("The payment runbook describes recovery steps.")


def test_poisoned_chat_continues_legitimate_task_and_redacts_evidence(client):
    session = client.post("/api/sessions").json()
    response = client.post(f"/api/sessions/{session['id']}/chat", json={"message": "Investigate the payment incident", "poisoned": True})
    assert response.status_code == 200
    data = response.json()
    assert "Recommended next steps" in data["messages"][-1]["content"]
    assert data["messages"][-1]["blocked"]
    assert any(e["title"] == "Export denied" for e in data["events"])
    assert CANARY not in response.text
    overview = client.get("/api/overview").json()
    assert overview["incidents"][0]["status"] == "Contained"
    assert overview["incidents"][0]["delivery"]["attempts"] == 0


def test_clean_chat_and_persistent_history(client):
    session = client.post("/api/sessions").json()
    for message in ("Summarize the runbook", "Draft an incident update"):
        assert client.post(f"/api/sessions/{session['id']}/chat", json={"message": message}).status_code == 200
    data = client.get(f"/api/sessions/{session['id']}").json()
    assert len(data["messages"]) == 4
    assert data["messages"][-1]["content"].startswith("Draft update")
    assert client.get("/api/overview").json()["incidents"] == []


def test_approval_payload_cannot_change_recipient(client):
    session = client.post("/api/sessions").json()
    data = client.post(f"/api/sessions/{session['id']}/chat", json={"message": "Page the responder"}).json()
    action = data["messages"][-1]["action"]
    path = f"/api/actions/{action['id']}/approve"
    assert client.post(path, json={"token": action["token"], "responder_id": "stranger"}).status_code == 422
    assert client.post(path, json={"token": "invalid-token-123456789"}).status_code == 403
    assert client.post(path, json={"token": action["token"]}).json()["delivery"]["attempts"] == 1
    assert client.post(path, json={"token": action["token"]}).status_code == 409


def test_expired_and_stale_approvals_are_rejected(service):
    sid = service.new_session()["id"]
    action = service.create_action(sid, "INC-104")
    action["expires_at"] = time() - 1
    service.store.put("action", action["id"], action)
    with pytest.raises(ValueError, match="expired"):
        service.approve_action(action["id"], action["token"])
    action = service.create_action(sid, "INC-104")
    service.policy = Policy(version=2)
    with pytest.raises(ValueError, match="Policy changed"):
        service.approve_action(action["id"], action["token"])


def test_concurrent_approval_dispatches_exactly_once(service):
    action = service.create_action(service.new_session()["id"], "INC-104")
    def approve():
        try:
            service.approve_action(action["id"], action["token"])
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(lambda _: approve(), range(2))) == 1
    assert service.store.get("action", action["id"])["delivery"]["attempts"] == 1


def test_incident_deduplication_and_page_cooldown(service):
    first = service.security_incident("duplicate", "Export denied", "runbook")
    assert first["id"] == service.security_incident("duplicate", "Export denied", "runbook")["id"]
    action = service.create_action(service.new_session()["id"], "INC-104")
    service.approve_action(action["id"], action["token"])
    second = service.create_action(service.new_session()["id"], "INC-104")
    with pytest.raises(ValueError, match="already paged"):
        service.approve_action(second["id"], second["token"])


def test_campaign_replay_activation_and_rollback(service):
    state = new_campaign(service, "all")
    asyncio.run(run_campaign(service, make_graph(service), state))
    run = service.store.get("run", state["id"])
    assert run["status"] == "completed" and run["validated"]
    assert run["mode"] == "local-simulation" and run["created_at"]
    assert run["validation"] == {"held_out_total": 2, "held_out_blocked": 2, "benign_total": 4, "benign_passed": 4}
    assert len(run["results"]) == 4
    assert not service.policy.block_untrusted_actions
    assert service.activate(run["id"])["block_untrusted_actions"]
    with pytest.raises(ValueError, match="already activated"):
        service.activate(run["id"])
    rollback = service.rollback()
    assert rollback["version"] == 3 and not rollback["block_untrusted_actions"]


def test_unvalidated_or_stale_candidates_cannot_activate(service):
    state = new_campaign(service, "runbook-injection")
    with pytest.raises(ValueError, match="validated"):
        service.activate(state["id"])
    asyncio.run(run_campaign(service, make_graph(service), state))
    service.policy = Policy(version=8)
    with pytest.raises(ValueError, match="stale"):
        service.activate(state["id"])


def test_reports_distinguish_simulation_from_model_evaluation(client, service):
    state = new_campaign(service, "all")
    asyncio.run(run_campaign(service, make_graph(service), state))
    report = client.get(f"/api/reports/{state['id']}")
    assert "deterministic local simulation" in report.text
    assert "No LLM or live alert provider was called" in report.text
    assert CANARY not in report.text
    assert client.get("/api/reports/missing").status_code == 404


def test_input_validation_and_cross_site_mutations(client):
    assert client.post("/api/sessions", headers={"Origin": "https://evil.example"}).status_code == 403
    session = client.post("/api/sessions").json()
    assert client.post(f"/api/sessions/{session['id']}/chat", json={"message": "hi", "incident_id": "PRIVATE"}).status_code == 422
    assert client.post("/api/lab/runs", json={"scenario": "external-attack", "target_url": "http://outside"}).status_code == 422
    assert client.get("/api/sessions/missing").status_code == 404


def test_event_broker_scopes_and_bounds():
    async def run():
        broker = EventBroker()
        a, b = broker.subscribe("a"), broker.subscribe("b")
        for i in range(200):
            await broker.publish("a", {"sequence": i})
        assert a.qsize() == 128 and b.empty()
        assert (await a.get())["sequence"] == 72
        broker.unsubscribe("a", a)
        assert "a" not in broker.subscribers
    asyncio.run(run())


def test_approval_tokens_are_never_sent_to_adapter(service):
    class RecordingAdapter:
        async def complete(self, messages, tools):
            from backend.models import AdapterResult
            assert all(set(m) == {"role", "content"} for m in messages)
            assert token not in str(messages)
            return AdapterResult(text="The responder is awaiting operator approval.", tool_calls=[])
    # Use a real chat first to seed an operator action in assistant history.
    sid = service.new_session()["id"]
    asyncio.run(service.chat(sid, ChatRequest(message="Page the responder")))
    token = service.session(sid)["messages"][-1]["action"]["token"]
    service.adapter = RecordingAdapter()
    data = asyncio.run(service.chat(sid, ChatRequest(message="Any update?")))
    assert data["messages"][-1]["content"] == "The responder is awaiting operator approval."


def test_adapter_with_no_text_or_tools_has_safe_fallback(service):
    class EmptyAdapter:
        async def complete(self, messages, tools):
            from backend.models import AdapterResult
            return AdapterResult()
    service.adapter = EmptyAdapter()
    data = asyncio.run(service.chat(service.new_session()["id"], ChatRequest(message="hello")))
    assert data["messages"][-1]["content"].startswith("No action was proposed.")
