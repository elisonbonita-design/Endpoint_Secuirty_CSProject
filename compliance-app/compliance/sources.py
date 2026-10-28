"""Turn observations from every data source into finding results (pure functions, no I/O).

A *result* is one assessment of one check on one endpoint:

    {"endpoint_id", "endpoint_label", "source", "check_key", "title", "status",
     "observed_at", "requirement_id", "remediation", "cvss", "cve_id"}

``status`` is passed | failed | not_applicable | unknown and is applied to the stored
finding by ``compliance.finding_sync.transition``.

Sources and how a finding is verified (paper, Table 3):
    sca            state: a later scan shows the check passed
    bitlocker      state: a later collector report shows protection on / fully encrypted
    vulnerability  state: a later scan no longer lists the CVE
    inventory      state: a later inventory no longer shows the package / listening port
    event          alert: opens a finding; never closes it by itself. A finding marked
                   fixed_pending is verified only by a later assessment: a passing SCA
                   check of a linked requirement, else a newer SCA scan of the endpoint
                   with no new matching alert since the fix was recorded
    fim            alert: opens a finding; verified when a later FIM check of the same
                   path is recorded after the fix (the restore / reversal)

"Absence means fixed" is only applied to endpoints listed as *covered*, i.e. the data
source was read successfully for them; a failed or missing query never verifies anything.
"""

from datetime import datetime, timedelta, timezone

from .risk_config import match_requirement

OPEN_STATUSES = ("open", "in_review", "exception", "fixed_pending")
CLOSED_STATUSES = ("cleared", "verified")


def _parse(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        text = value.strip().replace("Z", "+00:00")
        if len(text) > 5 and text[-5] in "+-" and text[-3] != ":":
            text = text[:-2] + ":" + text[-2:]  # "+0000" -> "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    return None


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def result(endpoint, source, check_key, title, status, observed_at=None, requirement_id=None,
           remediation=None, cvss=None, cve_id=None):
    return {"endpoint_id": endpoint["key"], "endpoint_label": endpoint.get("hostname"), "source": source,
            "check_key": check_key, "title": title, "status": status, "observed_at": observed_at,
            "requirement_id": requirement_id, "remediation": remediation, "cvss": cvss, "cve_id": cve_id}


def _req_remediation(catalogue, requirement_id):
    req = catalogue["requirements"].get(requirement_id) if requirement_id else None
    return req.get("remediation") if req else None


# ---- SCA ----

def sca_check_key(policy, check_id, name):
    ident = str(check_id) if check_id is not None else f"name:{name}"
    return f"{policy or ''}::{ident}"


def sca_results(endpoints, catalogue):
    """One result per SCA check; with scope "mapped", checks without a requirement are left out."""
    mapped_only = catalogue.get("sca_scope") == "mapped"
    out = []
    for e in endpoints:
        for c in e.get("checks", []):
            rid = match_requirement(catalogue, c.get("policy"), c.get("id"))
            if mapped_only and rid is None:
                continue
            out.append(result(e, "sca", sca_check_key(c.get("policy"), c.get("id"), c.get("name")),
                              c.get("name") or "(unnamed check)", c.get("status"), c.get("assessed_at"), rid,
                              _req_remediation(catalogue, rid) or c.get("remediation")))
    return out


def _sca_evidence(endpoint, catalogue):
    """(latest SCA assessment time, {requirement_id: [(status, time)]}) for one endpoint."""
    latest, by_req = None, {}
    for c in endpoint.get("checks", []):
        at = _parse(c.get("assessed_at"))
        if at and (latest is None or at > latest):
            latest = at
        rid = match_requirement(catalogue, c.get("policy"), c.get("id"))
        if rid:
            by_req.setdefault(rid, []).append((c.get("status"), at))
    return latest, by_req


def _alert_result(existing, last_alert):
    """Should an alert at ``last_alert`` (re)open the finding? A closed finding reopens only for a newer alert."""
    if existing is None:
        return True
    if existing["status"] in CLOSED_STATUSES:
        return last_alert > (_parse(existing["status_changed_at"]) or last_alert)
    return existing["status"] != "exception"


# ---- Windows security events (Wazuh alerts) ----

def event_results(endpoints, events_by_agent, covered, existing, monitored, catalogue):
    """``events_by_agent``: {agent_id: {event_id: {"last": iso, "count": n}}}.
    ``existing``: {(endpoint_id, source, check_key): finding row}. ``monitored``: config/monitored_events.json."""
    out = []
    for e in endpoints:
        if e["key"] not in covered:
            continue
        seen = events_by_agent.get(e["key"], {})
        last_scan, sca_by_req = _sca_evidence(e, catalogue)
        for cfg in monitored["events"]:
            key = f"event:{cfg['event_id']}"
            row = existing.get((e["key"], "event", key))
            info = seen.get(cfg["event_id"])
            last = _parse(info["last"]) if info else None
            hit = last is not None and info["count"] >= cfg.get("min_count", 1)
            title = f"{cfg['title']} (event {cfg['event_id']})"
            rid = cfg["requirement_id"]
            pending = row is not None and row["status"] == "fixed_pending"
            mark = _parse(row["status_changed_at"]) if pending else None
            if hit and _alert_result(row, last) and not (pending and mark and last <= mark):
                out.append(result(e, "event", key, title, "failed", _iso(last), rid, _req_remediation(catalogue, rid)))
                continue
            if not pending or mark is None or (last and last > mark):
                continue  # not awaiting verification, or the event happened again after the fix
            evidence = [at for r in cfg.get("verify_with", []) for status, at in sca_by_req.get(r, [])
                        if status == "passed" and at and at > mark]
            linked = any(sca_by_req.get(r) for r in cfg.get("verify_with", []))
            if evidence:
                out.append(result(e, "event", key, title, "passed", _iso(max(evidence)), rid))
            elif not linked and last_scan and last_scan > mark:
                out.append(result(e, "event", key, title, "passed", _iso(last_scan), rid))
    return out


# ---- File integrity monitoring (Wazuh syscheck alerts) ----

def _norm_path(path):
    return path.replace("/", "\\").rstrip("\\").lower()


def fim_kind(path, baseline):
    p = _norm_path(path)
    for kind in ("files", "registry"):
        for prefix in baseline.get(kind, []):
            q = _norm_path(prefix)
            if p == q or p.startswith(q + "\\"):
                return kind
    return None


def fim_results(endpoints, fim_by_agent, covered, existing, baseline, catalogue):
    """``fim_by_agent``: {agent_id: [{"path", "event": added|modified|deleted, "at": iso}]}."""
    out = []
    requirement = {"files": baseline.get("files_requirement"), "registry": baseline.get("registry_requirement")}
    for e in endpoints:
        if e["key"] not in covered:
            continue
        by_path = {}
        for alert in fim_by_agent.get(e["key"], []):
            kind = fim_kind(alert.get("path") or "", baseline)
            at = _parse(alert.get("at"))
            if kind and at:
                by_path.setdefault(_norm_path(alert["path"]), []).append((at, alert.get("event"), alert["path"], kind))
        keys = set(by_path) | {k[2][4:] for k in existing if k[0] == e["key"] and k[1] == "fim"}
        for path in sorted(keys):
            key = f"fim:{path}"
            row = existing.get((e["key"], "fim", key))
            alerts = sorted(by_path.get(path, []), reverse=True)
            if row is not None and row["status"] == "fixed_pending":
                mark = _parse(row["status_changed_at"])
                later = [a for a in alerts if mark and a[0] > mark]
                if later:
                    out.append(result(e, "fim", key, row["title"], "passed", _iso(later[0][0]), row["requirement_id"]))
                continue
            if not alerts:
                continue
            at, event, original, kind = alerts[0]
            if _alert_result(row, at):
                rid = requirement[kind]
                label = "registry key" if kind == "registry" else "file"
                out.append(result(e, "fim", key, f"Protected {label} {event or 'changed'}: {original}", "failed",
                                  _iso(at), rid, _req_remediation(catalogue, rid)))
    return out


# ---- State sources: vulnerabilities, installed software, listening ports ----

def _state_results(endpoints, current_by_agent, covered, existing, source, prefix, now):
    """``current_by_agent``: {agent_id: {check_key: result kwargs}}. Missing keys on covered endpoints pass."""
    out = []
    for e in endpoints:
        if e["key"] not in covered:
            continue
        current = current_by_agent.get(e["key"], {})
        for key, kwargs in current.items():
            out.append(result(e, source, key, status="failed", **kwargs))
        for (eid, src, key), row in existing.items():
            if eid == e["key"] and src == source and key.startswith(prefix) and key not in current \
                    and row["state"] != "compliant":
                out.append(result(e, source, key, row["title"], "passed", _iso(now), row["requirement_id"]))
    return out


def vulnerability_results(endpoints, vulns_by_agent, covered, existing, now):
    """``vulns_by_agent``: {agent_id: [{"cve", "package", "version", "cvss"}]}. No requirement: CVSS gives severity."""
    current = {}
    for agent, items in vulns_by_agent.items():
        for v in items:
            if not v.get("cve"):
                continue
            key = f"cve:{v['cve']}:{(v.get('package') or '').lower()}"
            current.setdefault(agent, {})[key] = {
                "title": f"{v['cve']} in {v.get('package') or 'unknown package'} {v.get('version') or ''}".strip(),
                "observed_at": _iso(now), "cvss": v.get("cvss"), "cve_id": v["cve"],
                "remediation": f"Update or remove {v.get('package') or 'the package'}, then wait for the next "
                               "vulnerability scan to confirm the CVE is gone."}
    return _state_results(endpoints, current, covered, existing, "vulnerability", "cve:", now)


def software_approved(name, approved):
    lowered = name.lower()
    return any(lowered == a.lower() or (a.endswith("*") and lowered.startswith(a[:-1].lower())) for a in approved)


def inventory_results(endpoints, packages_by_agent, ports_by_agent, covered_packages, covered_ports, existing,
                      approved_software, approved_ports, catalogue, now):
    """Unapproved packages (only if an approved list exists) and listening ports not in the approved baseline."""
    out = []
    if approved_software:
        current = {}
        for agent, names in packages_by_agent.items():
            for name in names:
                if name and not software_approved(name, approved_software):
                    current.setdefault(agent, {})[f"pkg:{name.lower()}"] = {
                        "title": f"Unapproved software installed: {name}", "observed_at": _iso(now),
                        "requirement_id": "REQ-SW-01", "remediation": _req_remediation(catalogue, "REQ-SW-01")}
        out += _state_results(endpoints, current, covered_packages, existing, "inventory", "pkg:", now)
    if approved_ports:
        current = {}
        for agent, ports in ports_by_agent.items():
            for p in ports:
                if p.get("port") and p["port"] not in approved_ports:
                    proto = (p.get("transport") or "tcp").lower()
                    proc = f" ({p['process']})" if p.get("process") else ""
                    current.setdefault(agent, {})[f"port:{proto}:{p['port']}"] = {
                        "title": f"Unapproved listening port {p['port']}/{proto}{proc}", "observed_at": _iso(now),
                        "requirement_id": "REQ-NP-01", "remediation": _req_remediation(catalogue, "REQ-NP-01")}
        out += _state_results(endpoints, current, covered_ports, existing, "inventory", "port:", now)
    return out


# ---- BitLocker (PowerShell collector) ----

BITLOCKER_FAILED_STATUSES = ("FullyDecrypted", "EncryptionInProgress", "DecryptionInProgress",
                             "EncryptionPaused", "DecryptionPaused")


def evaluate_bitlocker(volumes, now, max_age_hours):
    """(protection status, method status, observed_at) for the operating-system volume of one report."""
    os_volumes = [v for v in volumes if (v.get("volume_type") or "").lower() == "operatingsystem"]
    if not os_volumes:
        return "unknown", "unknown", None
    v = os_volumes[0]
    collected = _parse(v.get("collected_at"))
    if collected is None or (max_age_hours is not None and now - collected > timedelta(hours=max_age_hours)):
        return "unknown", "unknown", _iso(collected)
    protection, status, pct = v.get("protection_status"), v.get("volume_status"), v.get("encryption_percentage")
    if protection == "On" and status == "FullyEncrypted" and pct == 100:
        prot = "passed"
    elif protection == "Off" or status in BITLOCKER_FAILED_STATUSES or (isinstance(pct, (int, float)) and pct < 100):
        prot = "failed"
    else:
        prot = "unknown"
    method = v.get("encryption_method")
    meth = "unknown" if not method else ("passed" if method == "XtsAes256" else "failed")
    return prot, meth, _iso(collected)


def bitlocker_results(endpoints, reports_by_host, catalogue, now, max_age_hours=24):
    """``reports_by_host``: {hostname lower: [volume rows of the newest report]}."""
    out = []
    for e in endpoints:
        volumes = reports_by_host.get((e.get("hostname") or "").lower())
        if volumes is None:
            continue
        prot, meth, at = evaluate_bitlocker(volumes, now, max_age_hours)
        out.append(result(e, "bitlocker", "bitlocker:os:protection",
                          "OS drive BitLocker protection on and fully encrypted (collector)", prot, at, "REQ-BL-02",
                          _req_remediation(catalogue, "REQ-BL-02")))
        out.append(result(e, "bitlocker", "bitlocker:os:method", "OS drive uses XTS-AES 256 encryption (collector)",
                          meth, at, "REQ-BL-03", _req_remediation(catalogue, "REQ-BL-03")))
    return out
