"""Per-endpoint compliance against the requirement catalogue (pure functions, no I/O).

This is the second measure next to the Wazuh SCA benchmark score: for every selected
requirement it says whether *this PC* meets it, and why.

Status of one requirement on one PC, decided in this order:
    non_compliant   an open finding for it (open, in review, or fixed but not yet verified)
    exception       otherwise, an approved exception
    compliant       a passing assessment: SCA check passed, collector/inventory check passed,
                    or a finding for it was cleared/verified by a later assessment
    unknown         an assessment ran but could not decide (unknown result, stale report)
    not_applicable  the check does not apply on this PC
    compliant       weaker evidence: a monitored source was read for this PC and found
                    nothing (no monitored event, no protected-file change, no unapproved
                    software/port in the inventory)
    no_data         nothing about this requirement was read for this PC

Missing data is never counted as compliant. The compliance rate is
compliant / (compliant + non_compliant); exceptions, n/a, unknown and no-data are shown
separately, like the paper's four assessment states plus the exception workflow.
"""

OPEN = ("open", "in_review", "fixed_pending")
STATUSES = ("compliant", "non_compliant", "exception", "not_applicable", "unknown", "no_data")
STATUS_LABELS = {"compliant": "Compliant", "non_compliant": "Non-compliant", "exception": "Approved exception",
                 "not_applicable": "Not applicable", "unknown": "Unknown", "no_data": "No data"}


def requirement_sources(config):
    """{requirement id: {"sca", "event", "fim", "bitlocker", "software", "ports"}} from the config files."""
    catalogue = config["catalogue"]
    sources = {rid: set() for rid in catalogue["requirements"]}
    for rid, req in catalogue["requirements"].items():
        if req.get("sca_checks"):
            sources[rid].add("sca")
    for cfg in (config.get("monitored_events") or {}).get("events", []):
        sources.setdefault(cfg["requirement_id"], set()).add("event")
    fim = config.get("fim_baseline") or {}
    for key in ("files_requirement", "registry_requirement"):
        if fim.get(key):
            sources.setdefault(fim[key], set()).add("fim")
    for rid in ("REQ-BL-02", "REQ-BL-03"):
        if rid in sources:
            sources[rid].add("bitlocker")
    if "REQ-SW-01" in sources:
        sources["REQ-SW-01"].add("software")
    if "REQ-NP-01" in sources:
        sources["REQ-NP-01"].add("ports")
    return sources


def evaluate_endpoint(config, results, findings, coverage, event_ids_by_req=None, lookback_days=30):
    """Requirement status for one endpoint.

    ``results``: this sync's assessment results for the endpoint (``compliance.sources`` shape).
    ``findings``: stored findings of the endpoint (in scope). ``coverage``: {"event", "fim",
    "software", "ports", "bitlocker"} -> True when that source was read for this PC (and, for
    software/ports, the approved list is configured so the rule is active).
    Returns {"requirements": [...], "summary": {...}}.
    """
    catalogue = config["catalogue"]
    sources = requirement_sources(config)
    event_ids_by_req = event_ids_by_req or {}
    rows = []
    for rid, req in catalogue["requirements"].items():
        mine = [r for r in results if r.get("requirement_id") == rid]
        found = [f for f in findings if f.get("requirement_id") == rid]
        open_rows = [f for f in found if f["state"] == "non_compliant" and f["status"] in OPEN]
        exceptions = [f for f in found if f["status"] == "exception"]
        evidence, status = [], None
        if open_rows:
            status = "non_compliant"
            evidence = [f"Open finding: {f['title']}" for f in open_rows]
        elif exceptions:
            status = "exception"
            evidence = [f"Approved exception: {f['title']}" for f in exceptions]
        else:
            passed = [r for r in mine if r["status"] == "passed"]
            closed = [f for f in found if f["status"] in ("cleared", "verified") and f["state"] == "compliant"]
            if passed or closed:
                status = "compliant"
                evidence = [f"Passed: {r['title']}" for r in passed]
                evidence += [f"{'Verified fix' if f['status'] == 'verified' else 'Cleared by assessment'}: {f['title']}"
                             for f in closed if f["title"] not in {r["title"] for r in passed}]
            elif [r for r in mine if r["status"] == "unknown"] or [f for f in found if f["state"] == "unknown"]:
                status = "unknown"
                evidence = [f"Could not be assessed: {r['title']}" for r in mine if r["status"] == "unknown"] \
                    or ["The last assessment could not decide."]
            elif [r for r in mine if r["status"] == "not_applicable"]:
                status = "not_applicable"
                evidence = [f"Not applicable: {r['title']}" for r in mine if r["status"] == "not_applicable"]
            else:
                weak = []
                if "event" in sources.get(rid, ()) and coverage.get("event"):
                    ids = ", ".join(event_ids_by_req.get(rid, [])) or "monitored"
                    weak.append(f"No event {ids} in the last {lookback_days} days")
                if "fim" in sources.get(rid, ()) and coverage.get("fim"):
                    weak.append(f"No change to the protected paths in the last {lookback_days} days")
                if "software" in sources.get(rid, ()) and coverage.get("software"):
                    weak.append("No unapproved software in the latest inventory")
                if "ports" in sources.get(rid, ()) and coverage.get("ports"):
                    weak.append("No unapproved listening port in the latest inventory")
                if weak:
                    status, evidence = "compliant", weak
                else:
                    status, evidence = "no_data", [_no_data_reason(sources.get(rid, set()), coverage)]
        rows.append({"id": rid, "title": req["title"], "area": req.get("area"), "severity": req["severity"],
                     "sources": sorted(sources.get(rid, ())), "status": status, "label": STATUS_LABELS[status],
                     "evidence": evidence})
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    decided = counts["compliant"] + counts["non_compliant"]
    return {"requirements": rows, "summary": {
        **counts, "total": len(rows),
        "compliance_rate": round(counts["compliant"] / decided * 100, 2) if decided else None,
        "catalogue_version": catalogue["version"]}}


def _no_data_reason(sources, coverage):
    if not sources:
        return "No data source is mapped to this requirement."
    reasons = []
    if "sca" in sources:
        reasons.append("its SCA check was not reported by this PC")
    if "event" in sources and not coverage.get("event"):
        reasons.append("Windows events were not read")
    if "fim" in sources and not coverage.get("fim"):
        reasons.append("file integrity alerts were not read")
    if "bitlocker" in sources and not coverage.get("bitlocker"):
        reasons.append("no BitLocker collector report")
    if "software" in sources and not coverage.get("software"):
        reasons.append("software inventory not read or the approved-software list is empty")
    if "ports" in sources and not coverage.get("ports"):
        reasons.append("port inventory not read or the approved-ports list is empty")
    return "Not assessed on this PC: " + ("; ".join(reasons) if reasons else "no result yet") + "."
