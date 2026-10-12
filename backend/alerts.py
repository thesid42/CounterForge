import os
import re
from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4
from xml.sax.saxutils import escape

import httpx
from dotenv import load_dotenv


load_dotenv()


class AlertConfigurationError(ValueError):
    pass


class AlertDispatchError(RuntimeError):
    pass


class AlertDispatcher(Protocol):
    mode: str

    def dispatch(self, message: str, incident_id: str) -> dict: ...


@dataclass(frozen=True)
class AlertSettings:
    mode: str = "simulated"
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_api_key_sid: str = ""
    twilio_api_key_secret: str = ""
    twilio_from_number: str = ""
    alert_to_number: str = ""
    timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls):
        mode = os.getenv("ALERT_MODE", "simulated").strip().lower()
        if mode not in {"simulated", "twilio_voice"}:
            raise AlertConfigurationError(
                "ALERT_MODE must be 'simulated' or 'twilio_voice'"
            )
        try:
            timeout = float(os.getenv("ALERT_TIMEOUT_SECONDS", "10"))
        except ValueError as exc:
            raise AlertConfigurationError(
                "ALERT_TIMEOUT_SECONDS must be a number"
            ) from exc
        if not 1 <= timeout <= 30:
            raise AlertConfigurationError(
                "ALERT_TIMEOUT_SECONDS must be between 1 and 30"
            )
        settings = cls(
            mode=mode,
            twilio_account_sid=os.getenv("TWILIO_ACCOUNT_SID", "").strip(),
            twilio_auth_token=os.getenv("TWILIO_AUTH_TOKEN", "").strip(),
            twilio_api_key_sid=os.getenv("TWILIO_API_KEY_SID", "").strip(),
            twilio_api_key_secret=os.getenv("TWILIO_API_KEY_SECRET", "").strip(),
            twilio_from_number=os.getenv("TWILIO_FROM_NUMBER", "").strip(),
            alert_to_number=os.getenv("ALERT_TO_NUMBER", "").strip(),
            timeout_seconds=timeout,
        )
        if mode == "twilio_voice":
            settings.validate_twilio()
        return settings

    def validate_twilio(self):
        required = {
            "TWILIO_ACCOUNT_SID": self.twilio_account_sid,
            "TWILIO_FROM_NUMBER": self.twilio_from_number,
            "ALERT_TO_NUMBER": self.alert_to_number,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise AlertConfigurationError(
                "Missing Twilio alert configuration: " + ", ".join(missing)
            )
        if not re.fullmatch(r"AC[0-9a-fA-F]{32}", self.twilio_account_sid):
            raise AlertConfigurationError("TWILIO_ACCOUNT_SID is not a valid Account SID")
        api_key_configured = bool(
            self.twilio_api_key_sid or self.twilio_api_key_secret
        )
        if api_key_configured:
            if not self.twilio_api_key_sid or not self.twilio_api_key_secret:
                raise AlertConfigurationError(
                    "TWILIO_API_KEY_SID and TWILIO_API_KEY_SECRET must be set together"
                )
            if not re.fullmatch(r"SK[0-9a-fA-F]{32}", self.twilio_api_key_sid):
                raise AlertConfigurationError(
                    "TWILIO_API_KEY_SID is not a valid API Key SID"
                )
        elif not self.twilio_auth_token:
            raise AlertConfigurationError(
                "Set TWILIO_API_KEY_SID and TWILIO_API_KEY_SECRET, or TWILIO_AUTH_TOKEN"
            )
        for name, value in (
            ("TWILIO_FROM_NUMBER", self.twilio_from_number),
            ("ALERT_TO_NUMBER", self.alert_to_number),
        ):
            if not re.fullmatch(r"\+[1-9][0-9]{7,14}", value):
                raise AlertConfigurationError(f"{name} must use E.164 format")


class SimulatedAlertDispatcher:
    mode = "simulated"

    def dispatch(self, message: str, incident_id: str):
        return {
            "mode": self.mode,
            "status": "Accepted",
            "provider_status": "simulated",
            "attempts": 1,
            "id": "demo-" + uuid4().hex[:8],
        }


class TwilioVoiceDispatcher:
    mode = "twilio_voice"

    def __init__(self, settings: AlertSettings, client=None):
        settings.validate_twilio()
        self.settings = settings
        self.client = client or httpx.Client(timeout=settings.timeout_seconds)

    def dispatch(self, message: str, incident_id: str):
        # The message is a server-owned, sanitized template. No evidence, model
        # output, phone number, or destination supplied by an agent reaches Twilio.
        said = f'<Say voice="alice">{escape(message)}</Say>'
        # Pause first so the speech isn't clipped after a trial notice/keypress,
        # and repeat once so the responder reliably hears it.
        twiml = f'<Response><Pause length="1"/>{said}<Pause length="1"/>{said}</Response>'
        url = (
            "https://api.twilio.com/2010-04-01/Accounts/"
            f"{self.settings.twilio_account_sid}/Calls.json"
        )
        try:
            username = (
                self.settings.twilio_api_key_sid
                or self.settings.twilio_account_sid
            )
            password = (
                self.settings.twilio_api_key_secret
                or self.settings.twilio_auth_token
            )
            response = self.client.post(
                url,
                auth=(username, password),
                data={
                    "To": self.settings.alert_to_number,
                    "From": self.settings.twilio_from_number,
                    "Twiml": twiml,
                },
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AlertDispatchError(
                "Twilio did not accept the voice notification"
            ) from exc
        call_sid = payload.get("sid")
        if not isinstance(call_sid, str) or not call_sid.startswith("CA"):
            raise AlertDispatchError("Twilio returned an invalid call identifier")
        return {
            "mode": self.mode,
            "status": "Accepted",
            "provider_status": payload.get("status", "queued"),
            "attempts": 1,
            "id": call_sid,
        }


def build_alert_dispatcher(settings=None):
    settings = settings or AlertSettings.from_env()
    if settings.mode == "simulated":
        return SimulatedAlertDispatcher()
    return TwilioVoiceDispatcher(settings)
