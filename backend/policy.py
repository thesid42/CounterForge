from dataclasses import asdict, dataclass
from .fixtures import CANARY
from .redforge import check_extraction_breach


@dataclass(frozen=True)
class Policy:
    version: int = 1
    export_allowlist: bool = True
    protect_context: bool = True
    responder_allowlist: bool = True
    require_approval: bool = True
    block_untrusted_actions: bool = False

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: str


def evaluate_tool(policy: Policy, name: str, arguments: dict, source: str = "user") -> Decision:
    if policy.block_untrusted_actions and source != "user" and name in {"export_incident", "request_page", "reveal_context"}:
        return Decision(False, "Retrieved content cannot authorize privileged actions", "Source authority")
    if name == "export_incident":
        if policy.export_allowlist and arguments.get("destination") != "internal-archive":
            return Decision(False, "Unapproved destination", "Export allowlist")
        if policy.protect_context:
            return Decision(False, "Protected context cannot leave the agent", "Protected data")
    elif name == "request_page":
        if policy.responder_allowlist and arguments.get("responder_id") != "primary":
            return Decision(False, "Responder is not allowlisted", "Responder allowlist")
        # This tool creates an approval proposal, never a call.
    elif name == "reveal_context":
        if policy.protect_context:
            return Decision(False, "Protected context disclosure denied", "Output disclosure")
    elif name not in {"get_incident", "search_runbooks", "draft_incident_update"}:
        return Decision(False, "Unknown tool", "Tool registry")
    return Decision(True, "Permitted by current policy", "Tool permissions")


def redact(text: str) -> str:
    return text.replace(CANARY, "[REDACTED]")


def check_output(text: str) -> bool:
    return not check_extraction_breach(text, [CANARY])["breached"]
