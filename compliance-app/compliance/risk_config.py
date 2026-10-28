"""Load and validate the prioritization config files (the only I/O for scoring).

    config/risk_weights.json    every number used by ``compliance.risk``, with a "version"
    config/requirements.json    versioned requirement catalogue and SCA check mapping
    config/approved_ports.json  approved listening ports baseline
    data/kev_snapshot.json      optional local known-exploited CVE list (skipped if missing)
"""

import json
import re
from collections.abc import Mapping
from pathlib import Path

from .risk import EXPOSURE_TAGS, ROLES, SEVERITIES

APP_DIR = Path(__file__).resolve().parent.parent
WEIGHTS_PATH = APP_DIR / "config" / "risk_weights.json"
REQUIREMENTS_PATH = APP_DIR / "config" / "requirements.json"
APPROVED_PORTS_PATH = APP_DIR / "config" / "approved_ports.json"
KEV_PATH = APP_DIR / "data" / "kev_snapshot.json"

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_REQ_ID = re.compile(r"^REQ-[A-Z]{2,4}-\d{2}$")


class ConfigError(ValueError):
    """A config file is missing or invalid; the message names the file and the problem."""


def _read(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as e:
        raise ConfigError(f"{Path(path).name} could not be read.") from e
    except json.JSONDecodeError as e:
        raise ConfigError(f"{Path(path).name} is not valid JSON: {e.msg} (line {e.lineno}).") from e


def _number(value, where):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ConfigError(f"risk_weights.json: {where} must be a number of 0 or more.")
    return value


def _version(data, name):
    version = data.get("version") if isinstance(data, Mapping) else None
    if not isinstance(version, str) or not version.strip():
        raise ConfigError(f"{name}: a non-empty \"version\" is required.")
    return version.strip()


def validate_weights(data):
    """Return the weights mapping if every required number is present and valid."""
    version = _version(data, "risk_weights.json")
    try:
        sev, exp, asset = data["severity"], data["exposure"], data["asset"]
        for key in ("max", "cvss_multiplier", "default"):
            _number(sev[key], f"severity.{key}")
        for level in SEVERITIES:
            _number(sev["requirement"][level], f"severity.requirement.{level}")
        for key in ("max", "defender_off", "firewall_off", "known_exploited", "unapproved_port"):
            _number(exp[key], f"exposure.{key}")
        _number(asset["max"], "asset.max")
        _number(asset["handles_client_data"], "asset.handles_client_data")
        for role in ROLES:
            _number(asset["role"][role], f"asset.role.{role}")
        _number(data["time_open"]["max"], "time_open.max")
        _number(data["time_open"]["points_per_day"], "time_open.points_per_day")
        _number(data["repeat"]["points"], "repeat.points")
        _number(data["repeat"]["min_times_reopened"], "repeat.min_times_reopened")
        _number(data["score_max"], "score_max")
        bands = data["bands"]
    except (KeyError, TypeError) as e:
        raise ConfigError(f"risk_weights.json: missing or malformed entry {e}.") from e
    if not isinstance(bands, list) or not bands:
        raise ConfigError("risk_weights.json: \"bands\" must be a non-empty list.")
    names = [b.get("name") if isinstance(b, Mapping) else None for b in bands]
    if not all(isinstance(n, str) and n for n in names) or len(set(names)) != len(names):
        raise ConfigError("risk_weights.json: every band needs a unique name.")
    for b in bands:
        _number(b.get("min"), f"bands.{b['name']}.min")
    if min(b["min"] for b in bands) != 0:
        raise ConfigError("risk_weights.json: the lowest band must start at 0.")
    return {**data, "version": version}


def load_weights(path=WEIGHTS_PATH):
    return validate_weights(_read(path))


# "mapped": only SCA checks mapped to a requirement become findings (paper: results are matched to "a small,
# documented set of requirements"); "all": every failed SCA check becomes a finding (unmapped ones score low).
SCA_SCOPES = ("mapped", "all")


def in_scope(finding, catalogue):
    """False for an SCA finding with no requirement while the catalogue scope is "mapped"."""
    return not (catalogue.get("sca_scope") == "mapped" and finding.get("source") == "sca"
                and not finding.get("requirement_id"))


def validate_requirements(data):
    """Return {"version", "requirements": {id: entry}, "by_check": {(policy, check_id): id}, "sca_scope"}."""
    version = _version(data, "requirements.json")
    entries = data.get("requirements")
    if not isinstance(entries, list):
        raise ConfigError("requirements.json: \"requirements\" must be a list.")
    requirements, by_check = {}, {}
    for entry in entries:
        rid = entry.get("id") if isinstance(entry, Mapping) else None
        if not isinstance(rid, str) or not _REQ_ID.fullmatch(rid) or rid in requirements:
            raise ConfigError(f"requirements.json: invalid or duplicate requirement id {rid!r}.")
        if entry.get("severity") not in SEVERITIES:
            raise ConfigError(f"requirements.json: {rid} severity must be one of {', '.join(SEVERITIES)}.")
        if entry.get("exposure") not in (None, *EXPOSURE_TAGS):
            raise ConfigError(f"requirements.json: {rid} exposure must be null or one of {', '.join(EXPOSURE_TAGS)}.")
        if not isinstance(entry.get("title"), str) or not entry["title"].strip():
            raise ConfigError(f"requirements.json: {rid} needs a title.")
        for check in entry.get("sca_checks") or []:
            if not (isinstance(check, Mapping) and isinstance(check.get("policy"), str)
                    and isinstance(check.get("id"), str)):
                raise ConfigError(f"requirements.json: {rid} sca_checks entries need text \"policy\" and \"id\".")
            key = (check["policy"], check["id"])
            if key in by_check:
                raise ConfigError(f"requirements.json: check {key} is mapped to more than one requirement.")
            by_check[key] = rid
        requirements[rid] = dict(entry)
    scope = data.get("sca_scope", "all")
    if scope not in SCA_SCOPES:
        raise ConfigError(f"requirements.json: \"sca_scope\" must be one of {', '.join(SCA_SCOPES)}.")
    return {"version": version, "requirements": requirements, "by_check": by_check, "sca_scope": scope}


def load_requirements(path=REQUIREMENTS_PATH):
    return validate_requirements(_read(path))


def load_approved_ports(path=APPROVED_PORTS_PATH):
    data = _read(path)
    ports = data.get("ports") if isinstance(data, Mapping) else None
    if not isinstance(ports, list) or not all(isinstance(p, int) and not isinstance(p, bool)
                                              and 0 < p < 65536 for p in ports):
        raise ConfigError("approved_ports.json: \"ports\" must be a list of port numbers.")
    return frozenset(ports)


def load_kev(path=KEV_PATH):
    """CVE ids from a local snapshot; an empty set if the optional file is missing or unreadable.

    Accepts a plain list of CVE ids, {"cves": [...]}, or the CISA KEV catalogue layout
    {"vulnerabilities": [{"cveID": ...}]}. The file is never downloaded by the app.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return frozenset()
    if isinstance(data, Mapping):
        items = data.get("cves")
        if items is None:
            items = [v.get("cveID") for v in data.get("vulnerabilities") or [] if isinstance(v, Mapping)]
    else:
        items = data
    if not isinstance(items, list):
        return frozenset()
    return frozenset(c for c in items if isinstance(c, str) and _CVE.fullmatch(c))


MONITORED_EVENTS_PATH = APP_DIR / "config" / "monitored_events.json"
FIM_BASELINE_PATH = APP_DIR / "config" / "fim_baseline.json"
APPROVED_SOFTWARE_PATH = APP_DIR / "config" / "approved_software.json"


def validate_monitored_events(data, catalogue):
    _version(data, "monitored_events.json")
    events = data.get("events")
    if not isinstance(events, list):
        raise ConfigError("monitored_events.json: \"events\" must be a list.")
    for cfg in events:
        if not (isinstance(cfg, Mapping) and isinstance(cfg.get("event_id"), str) and cfg["event_id"].isdigit()
                and isinstance(cfg.get("title"), str)):
            raise ConfigError("monitored_events.json: each event needs a numeric text event_id and a title.")
        for rid in [cfg.get("requirement_id"), *cfg.get("verify_with", [])]:
            if rid not in catalogue["requirements"]:
                raise ConfigError(f"monitored_events.json: unknown requirement {rid!r} for event {cfg['event_id']}.")
        if not isinstance(cfg.get("min_count", 1), int) or cfg.get("min_count", 1) < 1:
            raise ConfigError(f"monitored_events.json: min_count of event {cfg['event_id']} must be 1 or more.")
    if not isinstance(data.get("lookback_days", 30), int) or not 1 <= data.get("lookback_days", 30) <= 365:
        raise ConfigError("monitored_events.json: lookback_days must be 1 to 365.")
    return data


def validate_fim_baseline(data, catalogue):
    _version(data, "fim_baseline.json")
    for kind in ("files", "registry"):
        if not isinstance(data.get(kind), list) or not all(isinstance(p, str) and p.strip() for p in data[kind]):
            raise ConfigError(f"fim_baseline.json: \"{kind}\" must be a list of paths.")
        if data.get(f"{kind}_requirement") not in catalogue["requirements"]:
            raise ConfigError(f"fim_baseline.json: \"{kind}_requirement\" must be a requirement id.")
    return data


def load_monitored_events(catalogue, path=MONITORED_EVENTS_PATH):
    return validate_monitored_events(_read(path), catalogue)


def load_fim_baseline(catalogue, path=FIM_BASELINE_PATH):
    return validate_fim_baseline(_read(path), catalogue)


def load_approved_software(path=APPROVED_SOFTWARE_PATH):
    data = _read(path)
    names = data.get("names") if isinstance(data, Mapping) else None
    if not isinstance(names, list) or not all(isinstance(n, str) and n.strip() for n in names):
        raise ConfigError("approved_software.json: \"names\" must be a list of program names.")
    return tuple(n.strip() for n in names)


def match_requirement(catalogue, policy, check_id):
    """Requirement id mapped to this SCA check, or None."""
    if policy is None or check_id is None:
        return None
    return catalogue["by_check"].get((str(policy), str(check_id)))
