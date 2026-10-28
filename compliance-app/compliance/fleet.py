"""Fleet view over SCA results: per-endpoint status, check details and repeated failures.

Builds on ``compliance.scoring`` (classification and pass percentage are not
redefined here). Two separate dimensions are reported for every endpoint:

* compliance ``status`` from its check results:
    noncompliant  at least one failed check
    compliant     at least one passed check, no failed and no unknown checks
    unknown       no passed/failed results, or some results are unknown
                  (missing data is never treated as a pass)
* ``connectivity`` from the Wazuh agent status:
    online   status "active" and last keep-alive within ``STALE_AFTER``
    stale    status "active" but the last keep-alive is older than that
    offline  any other Wazuh status ("disconnected", "pending", "never_connected")
    unknown  no agent status available

Checks are attributed to an endpoint only through the document's own
``agent.id``; documents without one are counted as unattributed, never guessed.
"""

import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from .scoring import FAILED, NOT_APPLICABLE, PASSED, UNKNOWN, compute_compliance_score, list_findings

STALE_AFTER = timedelta(hours=1)
LOCATION_FIELDS = ("department", "building", "floor", "room")
UNASSIGNED = "Unassigned"
CHECK_LABELS = {PASSED: "Compliant", FAILED: "Noncompliant", UNKNOWN: "Unknown",
                NOT_APPLICABLE: "Not applicable"}

# CIS policy descriptions state the expected value in this sentence; nothing is inferred otherwise.
_EXPECTED = re.compile(r"The recommended state for this setting is:?\s*(.+?)(?:\.(?:\s|$)|$)", re.S)


def parse_time(value):
    """Parse a Wazuh/ISO timestamp to an aware UTC datetime, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)  # "+0000" -> "+00:00"
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def classify_endpoint(counts):
    """Endpoint compliance status from ``compute_compliance_score`` counts."""
    if counts["failed"]:
        return "noncompliant"
    if counts["passed"] and not counts["unknown"]:
        return "compliant"
    return "unknown"


def classify_connectivity(agent_status, last_seen, as_of, stale_after=STALE_AFTER):
    if not agent_status:
        return "unknown"
    if agent_status != "active":
        return "offline"
    seen = parse_time(last_seen)
    if seen and as_of - seen > stale_after:
        return "stale"
    return "online"


def group_documents_by_agent(documents):
    """Split SCA documents by their own ``agent.id``. Returns (by_agent, unattributed_count)."""
    by_agent, unattributed = {}, 0
    for doc in documents:
        agent = doc.get("agent") if isinstance(doc, Mapping) else None
        agent_id = agent.get("id") if isinstance(agent, Mapping) else None
        if isinstance(agent_id, str) and agent_id:
            by_agent.setdefault(agent_id, []).append(doc)
        else:
            unattributed += 1
    return by_agent, unattributed


def _text(value):
    return value if isinstance(value, str) and value.strip() else None


def expected_from_description(description):
    match = _EXPECTED.search(description) if isinstance(description, str) else None
    return " ".join(match.group(1).split()) if match else None


def check_details(documents):
    """``list_findings`` rows enriched with the document's policy, rationale, targets and time."""
    rows = []
    for doc, finding in zip(documents, list_findings(documents)):
        check = doc.get("check") if isinstance(doc.get("check"), Mapping) else doc["data"]["check"]
        policy = doc.get("policy") if isinstance(doc.get("policy"), Mapping) else {}
        state = doc.get("state") if isinstance(doc.get("state"), Mapping) else {}
        targets = check.get("targets") if isinstance(check.get("targets"), Mapping) else {}
        description = _text(check.get("description"))
        rows.append({
            **finding,
            "label": CHECK_LABELS[finding["status"]],
            "policy": _text(policy.get("name")),
            "description": description,
            "rationale": _text(check.get("rationale")),
            "expected": expected_from_description(description),
            "targets": {k: [str(v) for v in vals] for k, vals in targets.items() if isinstance(vals, list)},
            "assessed_at": _iso(parse_time(state.get("modified_at"))),
        })
    return rows


def blank_location():
    return {field: None for field in LOCATION_FIELDS}


def build_endpoint(agent_id, agent, documents, location, as_of, last_event=None):
    """One endpoint record. ``agent`` is the Wazuh agent info (may be empty); ``location``
    an asset assignment (may be None)."""
    agent = agent or {}
    counts = compute_compliance_score(documents)
    checks = check_details(documents)
    times = [parse_time(c["assessed_at"]) for c in checks] + [parse_time(last_event)]
    times = [t for t in times if t]
    location = {field: _text((location or {}).get(field)) for field in LOCATION_FIELDS}
    hostname = agent.get("name")
    if not hostname:
        agents = [d.get("agent") for d in documents if isinstance(d.get("agent"), Mapping)]
        names = {a.get("name") for a in agents if isinstance(a.get("name"), str) and a.get("name")}
        hostname = names.pop() if len(names) == 1 else None
    return {
        "key": agent_id,
        "agent_id": agent_id,
        "hostname": hostname,
        "agent_status": agent.get("status"),
        "connectivity": classify_connectivity(agent.get("status"), agent.get("last_keepalive"), as_of),
        "last_seen": _iso(parse_time(agent.get("last_keepalive"))),
        "last_assessment": _iso(max(times)) if times else None,
        "os": agent.get("os"),
        "ip": agent.get("ip"),
        "location": location,
        "department": location["department"] or UNASSIGNED,
        "assigned": location["department"] is not None,
        "status": classify_endpoint(counts),
        "counts": counts,
        "policies": sorted({c["policy"] for c in checks if c["policy"]}),
        "checks": checks,
    }


def summarize_fleet(endpoints):
    """Endpoint (PC) counts and check counts over the whole fleet."""
    all_statuses = [e["status"] for e in endpoints]
    checks = [{"check": {"result": c["result"]}} for e in endpoints for c in e["checks"]]
    departments = {}
    for e in endpoints:
        dept = departments.setdefault(e["department"], {"name": e["department"], "pcs": 0, "compliant": 0,
                                                        "noncompliant": 0, "unknown": 0, "_results": []})
        dept["pcs"] += 1
        dept[e["status"]] += 1
        dept["_results"] += [{"check": {"result": c["result"]}} for c in e["checks"]]
    for dept in departments.values():
        dept["pass_percentage"] = compute_compliance_score(dept.pop("_results"))["pass_percentage"]
    return {
        "pcs": {
            "total": len(endpoints),
            "compliant": all_statuses.count("compliant"),
            "noncompliant": all_statuses.count("noncompliant"),
            "unknown": all_statuses.count("unknown"),
            "offline_or_stale": sum(e["connectivity"] in ("offline", "stale") for e in endpoints),
            "unassigned": sum(not e["assigned"] for e in endpoints),
        },
        "checks": compute_compliance_score(checks),
        "departments": sorted(departments.values(), key=lambda d: (d["name"] == UNASSIGNED, d["name"].lower())),
    }


def prioritize_failures(endpoints):
    """Failed checks grouped across endpoints, most widespread first.

    Ordering uses only observed facts: affected endpoints, then affected
    departments, then mapped frameworks. Wazuh SCA provides no severity, so
    none is invented.
    """
    groups = {}
    for e in endpoints:
        for c in e["checks"]:
            ident = str(c["id"]) if c["id"] is not None else f"name:{c['name']}"
            g = groups.setdefault((c["policy"], ident), {
                "id": c["id"], "name": c["name"], "policy": c["policy"], "remediation": c["remediation"],
                "rationale": c["rationale"], "expected": c["expected"], "frameworks": {}, "reported_on": 0,
                "endpoints": [],
            })
            if c["status"] in (PASSED, FAILED):
                g["reported_on"] += 1
            if c["status"] == FAILED:
                g["endpoints"].append({"key": e["key"], "hostname": e["hostname"], "department": e["department"]})
                for fw, controls in c["compliance"].items():
                    g["frameworks"].setdefault(fw, set()).update(controls)
    result = []
    for g in groups.values():
        if not g["endpoints"]:
            continue
        departments = sorted({x["department"] for x in g["endpoints"]}, key=lambda d: (d == UNASSIGNED, d.lower()))
        g["frameworks"] = {fw: sorted(ctrls) for fw, ctrls in sorted(g["frameworks"].items())}
        g["departments"] = departments
        g["affected"] = len(g["endpoints"])
        g["why"] = _why(g)
        result.append(g)
    result.sort(key=lambda g: (-g["affected"], -len(g["departments"]), -len(g["frameworks"]),
                               (g["name"] or "").lower()))
    return result


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def _why(group):
    pct = round(group["affected"] / group["reported_on"] * 100) if group["reported_on"] else None
    reasons = [f"Fails on {_plural(group['affected'], 'endpoint')} of {group['reported_on']} that reported "
               f"a passed/failed result for this check" + (f" ({pct}%)." if pct is not None else ".")]
    reasons.append(f"Affects {_plural(len(group['departments']), 'department')}: {', '.join(group['departments'])}.")
    if group["frameworks"]:
        reasons.append(f"Mapped to {_plural(len(group['frameworks']), 'compliance framework')}: "
                       f"{', '.join(group['frameworks'])}.")
    else:
        reasons.append("No compliance framework mapping is provided for this check.")
    return reasons
