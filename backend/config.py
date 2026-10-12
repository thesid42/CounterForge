import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = REPO_ROOT / ".env"


def _load_env(path: Path):
    if not path.exists():
        return {}
    values = {}
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Remove surrounding quotes if present
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            values[key] = value
    return values


env_file = _load_env(ENV_PATH)


class Settings:
    MODEL_MODE: str = os.environ.get("MODEL_MODE", env_file.get("MODEL_MODE", "demo"))
    TARGET_BASE_URL: str = os.environ.get("TARGET_BASE_URL", env_file.get("TARGET_BASE_URL", ""))
    TARGET_MODEL: str = os.environ.get("TARGET_MODEL", env_file.get("TARGET_MODEL", ""))
    CANARY_COLLECTOR_URL: str = os.environ.get("CANARY_COLLECTOR_URL", env_file.get("CANARY_COLLECTOR_URL", ""))
    CANARY_EXFIL_URL: str = os.environ.get("CANARY_EXFIL_URL", env_file.get("CANARY_EXFIL_URL", ""))
    ATTACKER_MODEL: str = os.environ.get("ATTACKER_MODEL", env_file.get("ATTACKER_MODEL", ""))
    ATTACKER_BASE_URL: str = os.environ.get("ATTACKER_BASE_URL", env_file.get("ATTACKER_BASE_URL", ""))
    ATTACKER_API_KEY: str = os.environ.get("ATTACKER_API_KEY", env_file.get("ATTACKER_API_KEY", ""))
    DEFENDER_MODEL: str = os.environ.get("DEFENDER_MODEL", env_file.get("DEFENDER_MODEL", ""))
    DEFENDER_BASE_URL: str = os.environ.get("DEFENDER_BASE_URL", env_file.get("DEFENDER_BASE_URL", ""))
    DEFENDER_API_KEY: str = os.environ.get("DEFENDER_API_KEY", env_file.get("DEFENDER_API_KEY", ""))
    ALERT_MODE: str = os.environ.get("ALERT_MODE", env_file.get("ALERT_MODE", "simulated"))


settings = Settings()
