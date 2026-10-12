import json
import httpx
from pydantic import BaseModel, ConfigDict
from .models import ToolCall
from .config import settings
from .fixtures import CANARY


class TargetResult(BaseModel):
    model_config = ConfigDict(extra="allow")
    text: str = ""
    tool_calls: list[ToolCall] = []
    dvaa: dict | None = None


class DVAATarget:
    def __init__(self, base_url: str | None = None, model: str | None = None, collector_url: str | None = None):
        self.base_url = (base_url or settings.TARGET_BASE_URL or "").rstrip("/")
        self.model = model or settings.TARGET_MODEL or ""
        self.collector_url = (collector_url or settings.CANARY_COLLECTOR_URL or "").rstrip("/")
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(60.0))
        self.collector_error: str | None = None

    async def run(self, messages: list[dict]) -> TargetResult:
        if not self.base_url:
            raise RuntimeError("TARGET_BASE_URL not configured")
        url = f"{self.base_url}/chat/completions"
        payload = {"model": self.model, "messages": messages}
        response = await self.client.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        choices = data.get("choices") or []
        msg = (choices[0] if choices else {}).get("message") or {}
        content = msg.get("content") or ""
        raw_tool_calls = msg.get("tool_calls") or []
        tool_calls: list[ToolCall] = []
        for tc in raw_tool_calls:
            func = tc.get("function") or {}
            name = func.get("name") or ""
            args = func.get("arguments") or "{}"
            try:
                arguments = json.loads(args) if isinstance(args, str) else args
            except Exception:
                arguments = {}
            tool_calls.append(ToolCall(name=name, arguments=arguments))
        dvaa = data.get("dvaa")
        return TargetResult(text=content, tool_calls=tool_calls, dvaa=dvaa)

    async def collector_hits(self) -> list:
        self.collector_error = None
        if not self.collector_url:
            return []
        url = f"{self.collector_url}/hits"
        try:
            r = await self.client.get(url)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            self.collector_error = str(exc)
            return []

    async def collector_reset(self) -> None:
        """Clear recorded hits so each run's evidence is attributable to that run."""
        if not self.collector_url:
            return
        try:
            await self.client.post(f"{self.collector_url}/reset")
        except Exception as exc:
            self.collector_error = str(exc)

    async def health(self) -> bool:
        if not self.base_url:
            return False
        root = self.base_url.replace("/v1", "").rstrip("/")
        try:
            r = await self.client.get(f"{root}/health")
            return r.status_code < 500
        except Exception:
            return False
