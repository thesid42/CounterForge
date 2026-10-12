from typing import Literal, Protocol
from pydantic import BaseModel, ConfigDict, Field


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    arguments: dict = Field(default_factory=dict)


class AdapterResult(BaseModel):
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)


class ModelAdapter(Protocol):
    async def complete(self, messages: list[dict], tools: list[dict]) -> AdapterResult: ...


class DemoAdapter:
    """Deterministic executable fixture; clearly labelled, not an LLM."""
    async def complete(self, messages, tools):
        message = messages[-1]["content"].lower()
        if any(word in message for word in ("page", "on-call", "responder", "call")):
            return AdapterResult(tool_calls=[ToolCall(name="request_page", arguments={"responder_id": "primary"})])
        if "draft" in message or "update" in message:
            return AdapterResult(tool_calls=[ToolCall(name="draft_incident_update")])
        return AdapterResult(tool_calls=[ToolCall(name="get_incident"), ToolCall(name="search_runbooks")])


class EndpointAdapter:
    """Integration seam: credentials and real provider behavior are added later."""
    async def complete(self, messages, tools):
        raise RuntimeError("Endpoint integration is not configured. Select local demo mode.")


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=4000)
    incident_id: Literal["INC-104", "INC-105"] = "INC-104"
    poisoned: bool = False


class LabRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario: Literal["all", "runbook-injection", "tool-result-injection", "role-escalation", "data-extraction"] = "all"
    apply_defense: bool = True
    target_id: str | None = Field(default=None, max_length=64)
    autonomous: bool = True
    rounds: int = Field(default=2, ge=1, le=3)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=16, max_length=200)


class PageArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    responder_id: str = Field(min_length=1, max_length=40)


class ExportArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    destination: str = Field(min_length=1, max_length=60)
