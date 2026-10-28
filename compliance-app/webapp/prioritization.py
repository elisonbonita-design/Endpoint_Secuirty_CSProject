"""Glue between stored findings, asset fields, config and the pure scoring in ``compliance.risk``.

Scores are recomputed when the fleet is loaded (which also syncs findings), when asset
fields change, and every few minutes by a background thread so "time open" keeps
ageing. Each recompute reads, computes in Python, then writes in one short transaction.
"""

import logging
import os
import threading

from compliance import requirement_status, sources
from compliance.risk import (SEAT_LETTERS, band_key, is_scorable, needs_data, score_finding, seat_band,
                             sort_key)
from compliance.risk_config import (in_scope, load_approved_ports, load_approved_software, load_fim_baseline,
                                    load_kev, load_monitored_events, load_requirements, load_weights)

log = logging.getLogger(__name__)
RECOMPUTE_INTERVAL_SECONDS = 300


def load_risk_config():
    """All prioritization config; raises ``ConfigError`` with a clear message if a file is invalid."""
    catalogue = load_requirements()
    return {"weights": load_weights(), "catalogue": catalogue, "approved_ports": load_approved_ports(),
            "kev": load_kev(), "monitored_events": load_monitored_events(catalogue),
            "fim_baseline": load_fim_baseline(catalogue), "approved_software": load_approved_software()}


def location_text(location):
    loc = location or {}
    parts = [loc.get("building"), loc.get("floor") and f"Floor {loc['floor']}",
             loc.get("room") and f"Room {loc['room']}"]
    parts = [p for p in parts if p]
    return " · ".join(parts) if parts else None


class RiskService:
    def __init__(self, store, assets, config, now):
        """``assets``: callable returning the AssetStore; ``now``: callable returning aware UTC time."""
        self.store = store
        self._assets = assets
        self.config = config
        self._now = now
        self._lock = threading.Lock()
        self._last = {}
        self.last_scan = {}  # data source -> counts of what the latest sync changed
        self._requirements = {}

    @property
    def weights(self):
        return self.config["weights"]

    def sync(self, data_source, endpoints, observations=None):
        """Store the latest results of ``endpoints`` (fleet records with SCA checks) and of the other
        sources in ``observations``, then rescore that data source.

        ``observations`` keys (each optional; a missing key means "not read", never "all fixed"):
            events / fim / vulnerabilities / packages / ports: {"by_agent": {...}, "covered": set of agent ids}
            bitlocker: {hostname lower: [volume rows]}
        """
        observations = observations or {}
        catalogue = self.config["catalogue"]
        with self._lock:
            self.last_scan.pop(data_source, None)  # never report an older scan if this one fails
            now = self._now()
            existing = {(r["endpoint_id"], r["source"], r["check_key"]): r for r in self.store.all(data_source)}
            results = sources.sca_results(endpoints, catalogue)
            if "events" in observations and self.config.get("monitored_events"):
                obs = observations["events"]
                results += sources.event_results(endpoints, obs["by_agent"], obs["covered"], existing,
                                                 self.config["monitored_events"], catalogue)
            if "fim" in observations and self.config.get("fim_baseline"):
                obs = observations["fim"]
                results += sources.fim_results(endpoints, obs["by_agent"], obs["covered"], existing,
                                               self.config["fim_baseline"], catalogue)
            if "vulnerabilities" in observations:
                obs = observations["vulnerabilities"]
                results += sources.vulnerability_results(endpoints, obs["by_agent"], obs["covered"], existing, now)
            packages = observations.get("packages", {"by_agent": {}, "covered": set()})
            ports = observations.get("ports", {"by_agent": {}, "covered": set()})
            # The sample data carries its own small baselines so the demo can show these rules.
            approved = observations.get("approved") or {}
            results += sources.inventory_results(
                endpoints, packages["by_agent"], ports["by_agent"], packages["covered"], ports["covered"], existing,
                tuple(approved.get("software") or self.config.get("approved_software", ())),
                frozenset(approved.get("ports") or self.config["approved_ports"]), catalogue, now)
            if "bitlocker" in observations:
                results += sources.bitlocker_results(endpoints, observations["bitlocker"], catalogue, now,
                                                     observations.get("bitlocker_max_age_hours", 24))
            tally = {"created": 0, "reopened": 0, "cleared": 0, "verified": 0}
            self.store.apply(data_source, results, catalogue, now, tally=tally)
            self.last_scan[data_source] = tally
            scores = self._recompute(data_source)
            software_rule = bool(approved.get("software") or self.config.get("approved_software"))
            ports_rule = bool(approved.get("ports") or self.config["approved_ports"])
            self._requirement_view(data_source, endpoints, results, observations, software_rule, ports_rule)
            return scores

    def _requirement_view(self, data_source, endpoints, results, observations, software_rule, ports_rule):
        """Per-endpoint compliance against the requirement catalogue, kept for the endpoint views."""
        findings = self._last.get(data_source, ([], {}))[0]
        monitored = self.config.get("monitored_events") or {}
        event_ids = {}
        for cfg in monitored.get("events", []):
            event_ids.setdefault(cfg["requirement_id"], []).append(cfg["event_id"])

        def covered(name, key):
            return name in observations and key in observations[name]["covered"]

        view = {}
        for e in endpoints:
            key = e["key"]
            mine = [r for r in results if r["endpoint_id"] == key]
            coverage = {
                "event": covered("events", key) and bool(monitored),
                "fim": covered("fim", key) and bool(self.config.get("fim_baseline")),
                "software": covered("packages", key) and software_rule,
                "ports": covered("ports", key) and ports_rule,
                "bitlocker": any(r["source"] == "bitlocker" for r in mine),
            }
            view[key] = requirement_status.evaluate_endpoint(
                self.config, mine, [f for f in findings if f["endpoint_id"] == key], coverage, event_ids,
                monitored.get("lookback_days", 30))
        self._requirements[data_source] = view

    def requirements(self, data_source, endpoint_id):
        """The requirement view of one endpoint from the latest sync, or None before the first sync."""
        return self._requirements.get(data_source, {}).get(endpoint_id)

    def recompute(self, data_source=None):
        with self._lock:
            return self._recompute(data_source)

    def _recompute(self, data_source):
        now = self._now()
        # Out-of-scope rows (unmapped SCA checks while the catalogue scope is "mapped") stay stored but are
        # never scored or shown, so the views only contain the selected requirements.
        catalogue = self.config["catalogue"]
        findings = [f for f in self.store.all(data_source) if in_scope(f, catalogue)]
        find = self._assets().lookup_table()
        by_endpoint = {}
        for f in findings:
            by_endpoint.setdefault((f["data_source"], f["endpoint_id"]), []).append(f)
        requirements = self.config["catalogue"]["requirements"]
        scores = {}
        for f in findings:
            asset = find(f["endpoint_id"], f["endpoint_label"]) or {}
            result = score_finding(
                f, requirements=requirements, endpoint_findings=by_endpoint[(f["data_source"], f["endpoint_id"])],
                asset={"handles_client_data": bool(asset.get("handles_client_data")), "role": asset.get("role")},
                weights=self.weights, now=now, kev_ids=self.config["kev"],
                approved_ports=self.config["approved_ports"])
            if result:
                scores[f["id"]] = result
        self.store.record_scores(list(scores.values()), now)
        per_source = {}
        for f in findings:
            per_source.setdefault(f["data_source"], []).append(f)
        for source in ([data_source] if data_source else set(per_source) | set(self._last)):
            rows = per_source.get(source, [])
            self._last[source] = (rows, {f["id"]: scores[f["id"]] for f in rows if f["id"] in scores})
        return scores

    def _state(self, data_source):
        if data_source not in self._last:
            self.recompute(data_source)
        return self._last[data_source]

    def view(self, finding, score, location=None):
        req = self.config["catalogue"]["requirements"].get(finding["requirement_id"] or "")
        return {
            "id": finding["id"], "endpoint_id": finding["endpoint_id"], "endpoint_label": finding["endpoint_label"],
            "location": location, "seat": location_text(location), "finding_title": finding["title"],
            "title": finding["title"], "source": finding["source"], "requirement_id": finding["requirement_id"],
            "requirement_title": req.get("title") if req else None, "catalogue_version": finding["catalogue_version"],
            "severity": finding["severity"], "state": finding["state"], "status": finding["status"],
            "opened_at": finding["opened_at"], "times_reopened": finding["times_reopened"],
            "remediation": finding["remediation"], "cve_id": finding["cve_id"], "cvss": finding["cvss"],
            "verified_at": finding["verified_at"], "status_changed_at": finding["status_changed_at"],
            "score": score["score"] if score else None, "band": score["band"] if score else None,
            "band_key": band_key(score["band"]) if score else None, "reason": score["reason"] if score else None,
            "days_open": score["days_open"] if score else None,
            "weights_version": score["weights_version"] if score else None,
        }

    def prioritized(self, data_source, locations=None, endpoint_id=None):
        """(scored views sorted by priority, "Needs data" views) for one data source."""
        findings, scores = self._state(data_source)
        locations = locations or {}
        selected = [f for f in findings if endpoint_id is None or f["endpoint_id"] == endpoint_id]
        scored = [self.view(f, scores[f["id"]], locations.get(f["endpoint_id"]))
                  for f in selected if f["id"] in scores and is_scorable(f)]
        scored.sort(key=sort_key)
        unknown = [self.view(f, None, locations.get(f["endpoint_id"])) for f in selected if needs_data(f)]
        return scored, unknown

    def finding(self, data_source, finding_id, locations=None):
        findings, scores = self._state(data_source)
        match = next((f for f in findings if f["id"] == finding_id), None)
        if match is None:
            return None
        return self.view(match, scores.get(finding_id), (locations or {}).get(match["endpoint_id"]))

    def seats(self, data_source, endpoints):
        """{endpoint key: {"band", "letter", "top_score"}} for the floor plan and fleet views."""
        findings, scores = self._state(data_source)
        bands = {}
        for f in findings:
            if f["id"] in scores and is_scorable(f):
                bands.setdefault(f["endpoint_id"], []).append(scores[f["id"]])
        result = {}
        for e in endpoints:
            items = bands.get(e["key"], [])
            key = seat_band([s["band"] for s in items], e["counts"], self.weights)
            result[e["key"]] = {"band": key, "letter": SEAT_LETTERS[key],
                                "top_score": max((s["score"] for s in items), default=None),
                                "scored": len(items)}
        return result


_refresher = {"started": False}
_refresher_lock = threading.Lock()


def start_background_recompute(service, interval=RECOMPUTE_INTERVAL_SECONDS, debug=False, environ=None):
    """Start the periodic recompute thread once per process. Returns True if it started.

    Not started: a second time in this process, in the Flask debug reloader's parent
    process (only the child serving requests runs it), or when
    COMPLIANCE_DISABLE_BACKGROUND=1. ``create_app`` never calls this, so tests never start it.
    """
    env = os.environ if environ is None else environ
    if service is None or env.get("COMPLIANCE_DISABLE_BACKGROUND") == "1":
        return False
    if debug and env.get("WERKZEUG_RUN_MAIN") != "true":
        return False
    with _refresher_lock:
        if _refresher["started"]:
            return False
        _refresher["started"] = True
    stop = threading.Event()

    def loop():
        while not stop.wait(interval):
            try:
                service.recompute()
            except Exception:  # keep the thread alive; the next run may succeed
                log.exception("Background risk recompute failed")

    thread = threading.Thread(target=loop, name="risk-recompute", daemon=True)
    thread.start()
    _refresher["thread"], _refresher["stop"] = thread, stop
    return True
