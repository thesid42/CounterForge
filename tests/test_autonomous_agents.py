import asyncio
import json
import time
import httpx
import pytest
from fastapi.testclient import TestClient
from backend import workflow
from backend.agent_runtime import run_agent
from backend.agents import AgentRegistration, PERSONAS, register_agent, resolve_target
from backend.alerts import SimulatedAlertDispatcher
from backend.config import settings
from backend.console import explain
from backend.fixtures import CANARY, ATTACKS
from backend.main import create_app
from backend.policy import Policy
from backend.service import LabService, execute_lab_attack_async
from backend.storage import Store


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setattr(settings, "MODEL_MODE", "live")
    monkeypatch.setattr(settings, "TARGET_BASE_URL", "")
    monkeypatch.setattr(settings, "ALLOW_SIMULATION", True)
    monkeypatch.setattr(settings, "OPENROUTER_API_KEY", "test-key")
    monkeypatch.setattr(settings, "ATTACKER_BASE_URL", "https://example.test/v1")
    monkeypatch.setattr(settings, "DEFENDER_BASE_URL", "https://example.test/v1")
    monkeypatch.setattr(settings, "ATTACKER_MODEL", "fake-attacker")
    monkeypatch.setattr(settings, "DEFENDER_MODEL", "fake-defender")
    return LabService(Store(":memory:"), SimulatedAlertDispatcher())


def test_target_persona_and_rules_reach_model_and_gate_before_execution(monkeypatch):
    original = httpx.AsyncClient
    sent = []
    def respond(request):
        body = json.loads(request.content)
        sent.append(body)
        if len(body["messages"]) == 2:
            message = {"content": "", "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "export_incident", "arguments": '{"destination":"test-sink"}'}}]}
        else:
            message = {"content": "Done."}
        return httpx.Response(200, json={"choices": [{"message": message}]})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(respond), **kw))
    target = {"persona": "research", "model": "local-test", "base_url": "http://127.0.0.1:11434/v1", "tools": PERSONAS["research"]["tools"]}
    attack = {**ATTACKS[0], "target_profile": target}
    baseline = asyncio.run(run_agent(attack, Policy(), None))
    defended = asyncio.run(run_agent(attack, Policy(), "RULES-ON-MARKER"))
    assert baseline["verdict"] == "succeeded" and baseline["unauthorized_actions"] == 1
    assert defended["verdict"] == "blocked" and defended["unauthorized_actions"] == 0
    assert defended["model_verdict"] == "succeeded" and defended["defense_enforced"]
    assert "RULES-ON-MARKER" not in sent[0]["messages"][0]["content"]
    assert "RULES-ON-MARKER" in sent[2]["messages"][0]["content"]
    assert "knowledge assistant" in sent[0]["messages"][0]["content"]
    assert {t["function"]["name"] for t in sent[0]["tools"]} == set(target["tools"])
    assert CANARY not in json.dumps(baseline) + json.dumps(defended)


def test_target_error_stays_error_and_raw_disclosure_is_preserved(monkeypatch):
    original = httpx.AsyncClient
    target = {"persona": "incident", "model": "test", "base_url": "http://127.0.0.1:11434/v1", "tools": PERSONAS["incident"]["tools"]}
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(lambda r: httpx.Response(500)), **kw))
    failed = asyncio.run(run_agent({**ATTACKS[0], "target_profile": target}, Policy(), "rules"))
    assert failed["verdict"] == "error" and not failed["defense_enforced"]
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"choices": [{"message": {"content": CANARY}}]})), **kw))
    result = asyncio.run(run_agent({**ATTACKS[0], "target_profile": target}, Policy(), "rules"))
    assert result["model_verdict"] == "succeeded" and result["output_blocked"]
    assert result["response_content"] == "[REDACTED]"
    assert result["output"] == "Protected output withheld."


def fake_roles(monkeypatch):
    observations, executions = [], []
    class Attacker:
        async def craft(self, seed, feedback, round_number):
            observations.append(list(feedback))
            return {**seed, "id": f"{seed['id']}-r{round_number}", "seed_id": seed["id"], "round": round_number,
                    "strategy": f"strategy {round_number}", "payload": f"payload {round_number}", "generated_by": "fake"}
    class Defender:
        async def plan(self, attack, baseline):
            return {"rationale": "Constrain tools", "system_prompt": "RULES-ON", "controls": ["block_untrusted_actions"], "generated_by": "fake"}
    async def execute(attack, policy, defense_prompt=None):
        executions.append((attack["payload"], defense_prompt))
        benign = attack.get("id") == "benign"
        return {"verdict": "blocked" if defense_prompt or benign else "succeeded", "model_verdict": "blocked" if defense_prompt or benign else "succeeded",
                "reason": "observed", "output": "Safe answer" if benign else "target reply", "response_content": "target reply", "trace": [], "tool_calls": [], "defense_enforced": bool(defense_prompt)}
    monkeypatch.setattr(workflow, "AttackerAgent", Attacker)
    monkeypatch.setattr(workflow, "DefenderAgent", Defender)
    monkeypatch.setattr(workflow, "execute_lab_attack_async", execute)
    return observations, executions


@pytest.mark.parametrize("rules_on", [True, False])
def test_autonomous_loop_retests_same_payload_and_evolves_from_replay(service, monkeypatch, rules_on):
    observations, executions = fake_roles(monkeypatch)
    target = resolve_target(service, "local-support")
    service.store.put("run", "older-dvaa", {"id": "older-dvaa", "target": None, "status": "completed"})
    state = workflow.new_campaign(service, "data-extraction", rules_on, target=target, autonomous=True, rounds=2)
    asyncio.run(workflow.run_campaign(service, workflow.make_graph(service), state))
    run = service.store.get("run", state["id"])
    assert run["status"] == "completed", run.get("error")
    assert len(run["results"]) == 2
    assert executions[:4] == [("payload 1", None), ("payload 1", "RULES-ON" if rules_on else None), ("payload 2", None), ("payload 2", "RULES-ON" if rules_on else None)]
    assert observations[1][-1]["phase"] == ("defense-on" if rules_on else "rules-off")
    assert run["validated"] is rules_on
    assert run["comparison"]["replay_breaches"] == (0 if rules_on else 2)
    assert bool(service.get_active_defense()) is rules_on


def test_registration_autostarts_once_and_manual_option_waits(service, monkeypatch):
    fake_roles(monkeypatch)
    with TestClient(create_app(service)) as client:
        payload = {"name": "Support agent", "persona": "support", "model": "local-test", "rounds": 1, "scenario": "data-extraction"}
        first = client.post("/api/agents", json=payload).json()
        assert first["started_run"]["target"]["persona"] == "support"
        duplicate = client.post("/api/agents", json=payload).json()
        assert not duplicate["created"] and duplicate["started_run"] is None
        manual = client.post("/api/agents", json={**payload, "name": "Manual agent", "auto_run": False}).json()
        assert manual["started_run"] is None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            run = client.get("/api/lab/runs/" + first["started_run"]["id"]).json()
            if run["status"] == "completed":
                break
            time.sleep(.05)
        assert run["status"] == "completed", run.get("error")
        assert len(service.store.list("run")) == 1
        bad = client.post("/api/agents", json={**payload, "base_url": "https://example.com/v1"})
        assert bad.status_code == 422


def test_final_defense_must_pass_earlier_payloads_before_saving(service, monkeypatch):
    fake_roles(monkeypatch)
    class Defender:
        async def plan(self, attack, baseline):
            return {"system_prompt": "rules for " + attack["payload"], "rationale": "Constrain tools", "controls": [], "generated_by": "fake"}
    async def execute(attack, policy, defense_prompt=None):
        success = not defense_prompt or (attack["payload"] == "payload 1" and defense_prompt == "rules for payload 2")
        return {"verdict": "succeeded" if success else "blocked", "output": "Useful reply", "trace": [], "tool_calls": []}
    monkeypatch.setattr(workflow, "DefenderAgent", Defender)
    monkeypatch.setattr(workflow, "execute_lab_attack_async", execute)
    state = workflow.new_campaign(service, "data-extraction", target=resolve_target(service, "local-support"), autonomous=True, rounds=2)
    asyncio.run(workflow.run_campaign(service, workflow.make_graph(service), state))
    run = service.store.get("run", state["id"])
    assert run["status"] == "completed"
    assert all(r["defended"]["verdict"] == "blocked" for r in run["results"])
    assert run["validation"]["final_defense_checks"][0]["result"]["verdict"] == "succeeded"
    assert not run["validated"] and not service.get_active_defense()


def test_multiple_registrations_queue_runs_without_overlap(service, monkeypatch):
    fake_roles(monkeypatch)
    with TestClient(create_app(service)) as client:
        payload = {"name": "First agent", "persona": "support", "model": "local-test", "rounds": 1, "scenario": "data-extraction"}
        first = client.post("/api/agents", json=payload).json()["started_run"]
        second = client.post("/api/agents", json={**payload, "name": "Second agent"}).json()["started_run"]
        assert client.post("/api/lab/runs", json={"target_id": first["target"]["id"]}).status_code == 409
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            runs = [service.store.get("run", r["id"]) for r in (first, second)]
            assert sum(r["status"] == "running" for r in runs) <= 1
            if all(r["status"] == "completed" for r in runs):
                break
            time.sleep(.05)
        assert all(r["status"] == "completed" for r in runs)
        assert runs[0]["completed_at"] <= runs[1]["timeline"][1]["timestamp"]


def test_evidence_answer_is_bounded_and_does_not_get_unrelated_run_history(service, monkeypatch):
    original = httpx.AsyncClient
    captured = []
    def respond(request):
        captured.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"message": {"content": "Observed breach. " * 180}}]})
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(respond), **kw))
    answer, source = asyncio.run(explain("What happened?", [], {"selected_run": {"id": "selected"}}))
    assert len(answer.split()) <= 45
    assert captured[0]["max_tokens"] == 220
    assert "35 words" in captured[0]["messages"][0]["content"]
