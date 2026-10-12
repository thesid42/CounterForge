"""Text-only preferences and explicit operator run commands.

Saved evidence and generated analyst replies never enter this parser.
"""
import re
from random import choice
from .run_names import SCENARIO_NAMES


def default_preferences():
    return {"target_id": None,
            "scenario": "all", "apply_defense": False, "rounds": 2,
            "allow_runs": True, "reply_style": "brief"}


def configuration_text(preferences, targets):
    target = next((t for t in targets if t["id"] == preferences["target_id"]), None)
    name = target["name"] if target else "No agent chosen"
    return f"{name} · defense {'on' if preferences['apply_defense'] else 'off'} · {preferences['rounds']} round{'s' if preferences['rounds'] != 1 else ''} · {SCENARIO_NAMES[preferences['scenario']]}. Replies: {preferences['reply_style']}. Chat runs: {'enabled' if preferences['allow_runs'] else 'disabled'}."


def command_text(text):
    lower = text.lower().strip().rstrip(".!?")
    # Common operator typos, scoped to command matching, never saved prose.
    lower = re.sub(r"\bteh\b", "the", lower)
    lower = re.sub(r"\bassitants?\b", "assistants", lower)
    lower = re.sub(r"\bdefen[cs]e of(?=\s+(?:do|start|run|test|launch)\b)", "defense off", lower)
    return lower


def target_choice(text, targets, pick_any=True):
    lower = command_text(text)
    matched = sorted((t for t in targets if re.search(r"(?<!\w)(?:dvaa )?" + re.escape(t["name"].lower().removeprefix("dvaa ")) + r"(?!\w)", lower)), key=lambda t: len(t["name"]), reverse=True)
    aliases = {"incident": r"\bincident(?: assistant| agent| persona| bot)?\b", "support": r"\bsupport(?: assistant| agent| persona| bot)?\b", "research": r"\b(?:knowledge|research)(?: assistant| agent| persona| bot)?\b"}
    personas = [p for p, pattern in aliases.items() if re.search(pattern, lower)]
    if len(personas) > 1:
        raise ValueError("Choose one persona per run: incident, support, or knowledge assistant.")
    if matched:
        return matched[0]["id"]
    if personas:
        return next((t["id"] for t in targets if t["id"] == "local-" + personas[0]), None)
    if re.search(r"\bany(?: (?:available |registered )?(?:agent|assistant|target|bot|one))\b|\b(?:one of (?:them|the assistants|the agents)|pick (?:one|any))\b|(?:^|\s)any$", lower):
        return (choice(targets)["id"] if pick_any else "any") if targets else None
    return None


def target_reply(text, targets):
    names = [r"(?:dvaa )?" + re.escape(t["name"].lower().removeprefix("dvaa ")) for t in targets]
    options = "|".join([*names, r"(?:incident|support|knowledge|research)(?: assistant| agent| bot)?", r"any(?: (?:available |registered )?(?:agent|assistant|target|one))?", r"one of them", r"pick (?:one|any)"])
    return bool(re.fullmatch(r"(?:please )?(?:use |choose |pick )?(?:the )?(?:" + options + r")(?:\s+please|\s*[,;]?\s+(?:with |without |defense |defence |one round|two rounds|three rounds).*)?", command_text(text)))


def batch_target_choices(text, targets):
    lower = command_text(text)
    if re.search(r"\ball (?:the )?(?:dvaa )?(?:agents|bots|targets)\b", lower):
        return [t["id"] for t in targets if t.get("adapter") == "dvaa"]
    picked, spans = [], []
    for t in sorted(targets, key=lambda t: len(t["name"]), reverse=True):
        name = t["name"].lower().removeprefix("dvaa ")
        match = re.search(r"(?<!\w)(?:dvaa )?" + re.escape(name) + r"(?![\w-])", lower)
        if match and not any(match.start() < end and match.end() > begin for begin, end in spans):
            picked.append(t["id"])
            spans.append(match.span())
    for persona, pattern in {"incident": r"\bincident\b", "support": r"\bsupport\b", "research": r"\b(?:knowledge|research)\b"}.items():
        match = re.search(pattern, lower)
        if match and not any(begin <= match.start() < end for begin, end in spans):
            tid = "local-" + persona
            if any(t["id"] == tid for t in targets):
                picked.append(tid)
    return list(dict.fromkeys(picked)) if len(set(picked)) > 1 else []


def parse_command(text, preferences, targets, multiple_targets=False):
    lower = command_text(text)
    prefix = r"^(?:please\s+)?(?:(?:can|could|would|will)\s+you\s+|i (?:want|would like) (?:you )?to\s+)?"
    launch = r"(?:(?:start|launch|run|test|evaluate)\b|(?:do|perform)\s+(?:(?:a|one|another|new)\s+){0,2}(?:security\s+)?(?:run|test)\b)"
    start = bool(re.match(prefix + launch, lower) or re.match(prefix + r"(?:defen[cs]e(?: rules)? (?:on|off))\s*[,;]?\s*(?:and\s+)?" + launch, lower))
    configure = bool(re.match(prefix + r"(?:use|set|configure|switch|change|keep|make|enable|disable|allow|prevent|stop|turn)\b", lower) or re.match(r"^(?:defen[cs]e(?: rules)? (?:on|off)|(?:one|two|three|\d+) rounds?|brief replies|short replies)\b", lower))
    if re.match(r"^(?:show|what (?:are|is)|tell me|list)\b", lower) and re.search(r"\b(settings|configuration|config|personas|targets)\b", lower):
        return "settings", preferences
    if re.match(prefix + r"run\s+(?:history|activity|details|stats|results)\b", lower):
        return None, preferences
    if not start and not configure:
        return None, preferences
    updated = dict(preferences)
    selected_target = None if multiple_targets else target_choice(text, targets)
    if selected_target:
        updated["target_id"] = selected_target
        if selected_target != preferences.get("target_id") or target_choice(text, targets, pick_any=False) == "any":
            updated["apply_defense"] = False
    off = r"\b(?:defen[cs]e(?: rules)? (?:off|disabled)|without (?:the )?defen[cs]e(?: rules)?|(?:disable|turn off) (?:the )?defen[cs]e(?: rules)?)\b"
    on = r"\b(?:defen[cs]e(?: rules)? (?:on|enabled)|with (?:the )?defen[cs]e(?: rules)?|(?:enable|turn on) (?:the )?defen[cs]e(?: rules)?)\b"
    if re.search(off, lower):
        updated["apply_defense"] = False
    elif re.search(on, lower):
        updated["apply_defense"] = True
    round_match = re.search(r"\b(\d+|one|two|three)\s*(?:rounds?|attempts?)\b|\b(?:rounds?|attempts?)\s*(?:to|=|:)?\s*(\d+|one|two|three)\b", lower)
    if round_match:
        value = next(v for v in round_match.groups() if v)
        rounds = {"one": 1, "two": 2, "three": 3}.get(value)
        rounds = rounds if rounds else int(value)
        if rounds not in {1, 2, 3}:
            raise ValueError("Use one, two, or three rounds.")
        updated["rounds"] = rounds
    surfaces = {"all": r"\b(?:all (?:attack )?(?:surfaces|tests)|full security check)\b", "data-extraction": r"\b(?:data[- ]extraction|extraction|context check|protected context)\b", "tool-result-injection": r"\btool[- ]result\b", "runbook-injection": r"\b(?:runbook|poisoned runbook)\b", "role-escalation": r"\b(?:role[- ]escalation|impersonation|authority check)\b"}
    for scenario, pattern in surfaces.items():
        if re.search(pattern, lower):
            updated["scenario"] = scenario
            break
    if re.search(r"\b(?:disable|prevent|stop) (?:runs? from chat|chat runs?)\b", lower):
        updated["allow_runs"] = False
    elif re.search(r"\b(?:enable|allow) (?:runs? from chat|chat runs?)\b", lower):
        updated["allow_runs"] = True
    if re.search(r"\b(?:brief|short|concise)\b", lower):
        updated["reply_style"] = "brief"
    elif re.search(r"\b(?:detailed|details) (?:answers|replies)|\breplies (?:detailed|in detail)\b", lower):
        updated["reply_style"] = "details"
    if configure and updated == preferences:
        # Repeating a recognized setting still confirms it. Unrecognized prose
        # remains an analyst question instead of inventing a configuration.
        if not (selected_target or round_match or re.search(off + "|" + on, lower) or re.search(r"\b(?:brief|short|concise|chat runs?|replies)\b", lower)):
            return None, preferences
    return ("start" if start else "configure"), updated
