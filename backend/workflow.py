import asyncio
from copy import deepcopy
from typing import TypedDict
from uuid import uuid4
from langgraph.graph import END, START, StateGraph
from .fixtures import ATTACKS
from .policy import Policy, evaluate_tool
from .redforge import analyze_patterns, mutate_payload
from .service import execute_lab_attack, now


class Campaign(TypedDict, total=False):
    id: str
    scenario: str
    status: str
    stage: str
    base_version: int
    attacks: list[dict]
    results: list[dict]
    candidate: dict
    validated: bool
    validation: dict
    created_at: str
    updated_at: str
    completed_at: str
    mode: str
    patterns: dict
    proposal: dict
    activated: bool


def make_graph(service):
    async def persist(state, stage, **updates):
        value = {**state, **updates, "stage": stage, "updated_at": now()}
        service.store.put("run", state["id"], value)
        await service.broker.publish(state["id"], {"type": "stage", "payload": {"stage": stage}})
        # Brief pacing makes actual transitions visible; no fake progress percentage.
        await asyncio.sleep(0.18)
        return value

    async def generate(state):
        attacks = deepcopy([a for a in ATTACKS if state["scenario"] == "all" or a["id"] == state["scenario"]])
        return await persist(state, "generate", attacks=attacks)

    async def execute(state):
        baseline = Policy(export_allowlist=False, protect_context=False, responder_allowlist=False, block_untrusted_actions=False)
        results = [{"id": a["id"], "name": a["name"], "category": a["category"], "surface": a["surface"], "payload": a["payload"], "baseline": execute_lab_attack(a, baseline)} for a in state["attacks"]]
        return await persist(state, "execute", results=results)

    async def inspect(state):
        evidence = analyze_patterns([{**r, "verdict": r["baseline"]["verdict"]} for r in state["results"]])
        return await persist(state, "inspect", patterns=evidence)

    async def propose(state):
        candidate = {**service.policy.to_dict(), "version": state["base_version"] + 1, "block_untrusted_actions": True}
        return await persist(state, "propose", candidate=candidate, proposal={"name": "Enforce source authority", "description": "Retrieved documents and tool results cannot authorize privileged actions.", "evidence": [r["id"] for r in state["results"] if r["baseline"]["verdict"] == "succeeded"]})

    async def replay(state):
        candidate = Policy(**state["candidate"])
        results = [{**r, "defended": execute_lab_attack(a, candidate)} for r, a in zip(state["results"], state["attacks"])]
        # Test separately constructed held-out variants and benign tool requests.
        held_out = [{**ATTACKS[0], "id": "held-out-paraphrase", "payload": mutate_payload(ATTACKS[0]["payload"])}, {**ATTACKS[1], "id": "held-out-destination", "arguments": {"destination": "unapproved-diagnostics"}}]
        hold_results = [execute_lab_attack(a, candidate) for a in held_out]
        benign = [evaluate_tool(candidate, "get_incident", {}), evaluate_tool(candidate, "search_runbooks", {}), evaluate_tool(candidate, "draft_incident_update", {}), evaluate_tool(candidate, "request_page", {"responder_id": "primary"})]
        validated = all(r["defended"]["verdict"] == "blocked" for r in results) and all(r["verdict"] == "blocked" for r in hold_results) and all(x.allowed for x in benign)
        validation = {"held_out_total": len(hold_results), "held_out_blocked": sum(r["verdict"] == "blocked" for r in hold_results), "benign_total": len(benign), "benign_passed": sum(x.allowed for x in benign)}
        return await persist(state, "replay", results=results, validated=validated, validation=validation)

    async def finish(state):
        return await persist(state, "complete", status="completed", completed_at=now())

    graph = StateGraph(Campaign)
    nodes = {"generate": generate, "execute": execute, "inspect": inspect, "propose": propose, "replay": replay, "finish": finish}
    for name, fn in nodes.items():
        graph.add_node(name, fn)
    graph.add_edge(START, "generate")
    for a, b in zip(nodes, list(nodes)[1:]):
        graph.add_edge(a, b)
    graph.add_edge("finish", END)
    return graph.compile()


async def run_campaign(service, graph, state):
    try:
        result = await graph.ainvoke(state)
        service.store.put("run", state["id"], result)
    except Exception as exc:
        service.store.put("run", state["id"], {**state, "status": "failed", "stage": "error", "error": str(exc), "updated_at": now()})
    await service.broker.publish(state["id"], {"type": "finished"})


def new_campaign(service, scenario):
    state = {"id": uuid4().hex, "scenario": scenario, "status": "running", "stage": "queued", "base_version": service.policy.version, "created_at": now(), "results": [], "mode": "local-simulation"}
    service.store.put("run", state["id"], state)
    return state
