"""Local web dashboard for SCA compliance results.

Single report: Wazuh SCA JSON from the bundled sample, an uploaded file or one
Wazuh agent. Fleet views: every endpoint from the bundled sample fleet or from
the Wazuh Indexer (read-only), with asset assignments stored in SQLite.
Prioritization: findings are stored and given a rule-based risk score; an optional
local AI (Ollama) may only explain them.
"""

import json
import logging
import os
import re
import secrets
import sqlite3
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge

from compliance import compute_compliance_score, compute_framework_scores, list_findings
from compliance.fleet import (build_endpoint, group_documents_by_agent, parse_time, prioritize_failures,
                              summarize_fleet)
from compliance.wazuh_alerts import (AGENT_ID_PATTERN, ALERTS_INDEX, MAX_AGENTS, MAX_CHECKS, MONITORING_INDEX,
                                     agents_query, latest_checks_query, monitoring_response_to_agents,
                                     sca_activity_query, sca_activity_response, search_response_to_documents)

from compliance.ai_explain import (AI_LABEL, explain_payload, explain_prompt, fallback_explanation,
                                   parse_explanation, parse_summary, summary_payload, summary_prompt)
from compliance.risk_config import ConfigError

from compliance import wazuh_sources

from .ai_providers import AIError, provider_from_env
from .assets_db import MAX_IMAGE_BYTES, AssetError, AssetStore
from .auth import AuthError, UserStore, load_secret_key
from .findings_db import FindingStore
from .indexer import IndexerError, client_from_env
from .prioritization import RiskService, load_risk_config
from .routes_workflow import register_workflow_routes

log = logging.getLogger(__name__)

APP_DIR = Path(__file__).resolve().parent.parent
SAMPLE_PATH = APP_DIR / "samples" / "sca_results_sample.json"
FLEET_SAMPLE_PATH = APP_DIR / "samples" / "fleet_sample.json"
ASSET_DB_PATH = APP_DIR / "instance" / "assets.db"
SECRET_KEY_PATH = APP_DIR / "instance" / "secret_key"
OBSERVATIONS_SAMPLE_PATH = APP_DIR / "samples" / "observations_sample.json"
ENDPOINT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
FLEET_SOURCES = ("sample", "wazuh")
PRIORITY_BASIS = ("Ranked by the number of affected endpoints, then affected departments, then mapped "
                  "compliance frameworks. Wazuh SCA results carry no severity, so no risk score is assigned.")
MAX_UPLOAD_BYTES = 2 * 1024 * 1024


class ReportError(ValueError):
    """Input that cannot be turned into a report; message is safe to show users."""


class ApiError(Exception):
    """Request failure with an HTTP status; message is safe to show users."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def build_report(data):
    if isinstance(data, dict):
        data = [data]
    try:
        return {
            "overall": compute_compliance_score(data),
            "frameworks": compute_framework_scores(data),
            "findings": list_findings(data),
        }
    except (TypeError, ValueError) as e:
        raise ReportError(f"Unsupported SCA data: {e}") from e


ALL_POLICIES = "__all__"


def select_policy(documents, requested):
    """Filter Wazuh documents to one SCA policy.

    ``requested`` is a policy name, ``ALL_POLICIES``, or empty for the default: the
    largest CIS policy if the agent has one (so the official benchmark score stays the
    headline), otherwise all policies. Returns (documents, selected name or None for
    all, [{"name", "checks"}] for every policy found on the agent).
    """
    counts = {}
    for doc in documents:
        name = doc["policy"].get("name")
        if isinstance(name, str) and name:
            counts[name] = counts.get(name, 0) + 1
    policies = [{"name": n, "checks": c} for n, c in sorted(counts.items(), key=lambda kv: kv[0].lower())]

    if requested in (None, ""):
        cis = [p for p in policies if p["name"].upper().startswith("CIS ")]
        requested = max(cis, key=lambda p: p["checks"])["name"] if cis else ALL_POLICIES
    if not isinstance(requested, str) or len(requested) > 200:
        raise ApiError("The policy name is not valid.")
    if requested == ALL_POLICIES:
        return documents, None, policies
    if requested not in counts:
        raise ApiError("That policy has no results for this agent. Choose one from the list.")
    return [d for d in documents if d["policy"].get("name") == requested], requested, policies


def parse_json_bytes(raw):
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError as e:
        raise ReportError("The file is not UTF-8 encoded text.") from e
    except json.JSONDecodeError as e:
        raise ReportError(f"Invalid JSON: {e.msg} (line {e.lineno}, column {e.colno}).") from e


_FROM_ENV = object()
TEST_USER = {"id": 0, "username": "test", "role": "admin", "active": 1}
PUBLIC_ENDPOINTS = ("login_page", "login_submit", "static", "collector_bitlocker")
SESSION_LIFETIME = timedelta(hours=8)
AI_FALLBACK_NOTE = "Local AI is off or unavailable; showing the rule-based reason and remediation instead."


def _utcnow():
    return datetime.now(timezone.utc)


def create_app(sample_path=SAMPLE_PATH, indexer_client=_FROM_ENV, ai_provider=_FROM_ENV,
               fleet_sample_path=FLEET_SAMPLE_PATH, asset_db_path=ASSET_DB_PATH, now=_utcnow,
               risk_config=_FROM_ENV, login_required=True, secret_key=None, collector_token=_FROM_ENV,
               observations_sample_path=OBSERVATIONS_SAMPLE_PATH):
    """``indexer_client`` and ``ai_provider`` default to ones built from environment variables;
    either may be None (not configured / AI disabled). ``risk_config`` defaults to the files in
    config/ (see ``load_risk_config``). The database is created on first use; ``now`` returns
    the current UTC time (staleness and "time open" are judged against it).

    ``login_required=False`` is for automated tests only: every request then acts as an
    administrator named "test". ``secret_key`` defaults to instance/secret_key (created once).
    ``collector_token`` (env COLLECTOR_TOKEN, 32+ characters) enables the BitLocker collector.

    No background thread is started here; ``python -m webapp`` starts it (see ``__main__``).
    """
    app = Flask(__name__)
    asset_store, risk_store, user_store = [], [], []
    if indexer_client is _FROM_ENV:
        indexer_client = client_from_env()
    if ai_provider is _FROM_ENV:
        ai_provider = provider_from_env()
    if collector_token is _FROM_ENV:
        collector_token = os.environ.get("COLLECTOR_TOKEN", "").strip() or None
    if collector_token is not None and len(collector_token) < 32:
        log.error("BitLocker collector disabled: COLLECTOR_TOKEN must have at least 32 characters.")
        collector_token = None
    risk_error = None
    if risk_config is _FROM_ENV:
        try:
            risk_config = load_risk_config()
        except ConfigError as e:
            log.error("Prioritization disabled: %s", e)
            risk_config, risk_error = None, f"Prioritization is unavailable: {e}"
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    if login_required:
        app.secret_key = secret_key or load_secret_key(SECRET_KEY_PATH)
    else:
        app.secret_key = secret_key or secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                      SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
                      PERMANENT_SESSION_LIFETIME=SESSION_LIFETIME)

    def users():
        if not user_store:
            user_store.append(UserStore(asset_db_path))
        return user_store[0]

    def current_user():
        """The signed-in, still active account, re-read from the database on every request."""
        if not login_required:
            return TEST_USER
        if "user" not in g:
            uid = session.get("uid")
            user = users().get(uid) if isinstance(uid, int) else None
            g.user = user if user and user["active"] else None
        return g.user

    def require_role(*roles):
        user = current_user()
        if user is None:
            raise ApiError("Sign in first.", 401)
        if user["role"] not in roles:
            raise ApiError("Your role does not allow this action.", 403)
        return user

    @app.before_request
    def login_gate():
        if request.endpoint in PUBLIC_ENDPOINTS or current_user() is not None:
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "Sign in first."}), 401
        return redirect(url_for("login_page"))

    @app.get("/login")
    def login_page():
        if current_user() is not None:
            return redirect(url_for("index"))
        return render_template("login.html", error=None, first_run=users().count() == 0)

    @app.post("/login")
    def login_submit():
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            return render_template("login.html", error="Sign-in must come from this site.", first_run=False), 403
        try:
            user = users().authenticate(request.form.get("username", ""), request.form.get("password", ""), now())
        except AuthError as e:
            return render_template("login.html", error=str(e), first_run=False), 429
        if user is None:
            return render_template("login.html", error="Wrong username or password.", first_run=False), 401
        session.clear()
        session.permanent = True
        session["uid"] = user["id"]
        log.info("Sign-in: %s", user["username"])
        return redirect(url_for("index"))

    @app.post("/logout")
    def logout():
        require_app_request()
        session.clear()
        return jsonify({"signed_out": True})

    @app.get("/api/me")
    def me():
        user = current_user()
        return jsonify({"username": user["username"], "role": user["role"], "login_required": login_required})

    def error(message, status=400):
        return jsonify({"error": message}), status

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        # same-origin: nothing leaks to other sites, while our own form posts keep a real Origin header
        # (with no-referrer browsers send "Origin: null", which the sign-in check would have to trust).
        response.headers["Referrer-Policy"] = "same-origin"
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_e):
        return error(f"File is too large. The limit is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.", 413)

    @app.errorhandler(ReportError)
    def report_error(e):
        return error(str(e))

    @app.errorhandler(ApiError)
    def api_error(e):
        return error(str(e), e.status)

    def load_sample_documents():
        try:
            raw = Path(sample_path).read_bytes()
        except OSError:
            raise ApiError("The bundled sample file could not be read.", 500) from None
        return parse_json_bytes(raw)

    def load_wazuh_documents(agent_id):
        if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
            raise ApiError("Enter a numeric Wazuh agent ID, for example 001.")
        if indexer_client is None:
            raise ApiError("Wazuh Indexer access is not configured on the server.", 503)
        try:
            response = indexer_client.search(ALERTS_INDEX, latest_checks_query(agent_id))
        except IndexerError as e:
            raise ApiError(str(e), 502) from e
        try:
            documents = search_response_to_documents(response)
        except (TypeError, ValueError) as e:
            raise ReportError(f"Unsupported SCA data from the Wazuh Indexer: {e}") from e
        if not documents:
            raise ApiError(f"No SCA results found in the Wazuh Indexer for agent {agent_id}.", 404)
        return documents

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/sample")
    def sample():
        report = build_report(load_sample_documents())
        report["source"] = "Bundled sample"
        return jsonify(report)

    @app.get("/api/wazuh/sca")
    def wazuh_sca():
        agent_id = request.args.get("agent_id", "")
        documents = load_wazuh_documents(agent_id)
        selected, policy, policies = select_policy(documents, request.args.get("policy"))
        report = build_report(selected)
        agent_name = documents[0]["agent"].get("name")
        shown = [policy] if policy else [p["name"] for p in policies]
        report["source"] = " · ".join(filter(None, [
            f"Wazuh agent {agent_id}" + (f" ({agent_name})" if agent_name else ""),
            ", ".join(shown),
        ]))
        report["policy"] = policy
        report["policies"] = policies
        report["truncated"] = len(documents) >= MAX_CHECKS
        return jsonify(report)

    @app.post("/api/upload")
    def upload():
        upload_file = request.files.get("file")
        if upload_file is None or not upload_file.filename:
            return error("No file was uploaded. Choose a JSON file first.")
        report = build_report(parse_json_bytes(upload_file.read()))
        report["source"] = upload_file.filename
        return jsonify(report)

    # ---- Fleet views (sample fleet or live Wazuh) ----

    def assets():
        if not asset_store:
            asset_store.append(AssetStore(asset_db_path))
        return asset_store[0]

    def risk_service():
        """The prioritization service, or None if its config could not be loaded."""
        if risk_config is None:
            return None
        if not risk_store:
            risk_store.append(RiskService(FindingStore(asset_db_path), assets, risk_config, now))
        return risk_store[0]

    app.extensions["risk_service"] = risk_service

    def require_risk():
        service = risk_service()
        if service is None:
            raise ApiError(risk_error or "Prioritization is unavailable.", 503)
        return service

    def indexer_search(index, body):
        try:
            return indexer_client.search(index, body)
        except IndexerError as e:
            raise ApiError(str(e), 502) from e

    def load_sample_fleet(find):
        try:
            data = parse_json_bytes(Path(fleet_sample_path).read_bytes())
        except OSError:
            raise ApiError("The bundled sample fleet file could not be read.", 500) from None
        if not (isinstance(data, Mapping) and all(isinstance(data.get(k), list)
                                                   for k in ("agents", "assets", "documents"))):
            raise ReportError("The sample fleet file has an unexpected structure.")
        agents = {a["id"]: a for a in data["agents"] if isinstance(a, Mapping) and isinstance(a.get("id"), str)}
        sample_assets = {a.get("agent_id"): a for a in data["assets"] if isinstance(a, Mapping)}
        by_agent, unattributed = group_documents_by_agent(data["documents"])
        as_of = parse_time(data.get("as_of")) or now()
        endpoints = []
        for agent_id in sorted(set(agents) | set(by_agent)):
            agent = agents.get(agent_id, {})
            # A saved assignment overrides the bundled sample one.
            location = find(agent_id, agent.get("name")) or sample_assets.get(agent_id)
            endpoints.append(build_endpoint(agent_id, agent, by_agent.get(agent_id, []), location, as_of))
        warnings = [f"{unattributed} sample check(s) had no agent ID and were excluded."] if unattributed else []
        meta = {"mode": "sample", "is_sample": True, "label": data.get("label") or "Sample data",
                "as_of": as_of.strftime("%Y-%m-%dT%H:%M:%SZ")}
        return meta, endpoints, warnings

    def load_wazuh_fleet(find):
        if indexer_client is None:
            raise ApiError("Wazuh Indexer access is not configured on the server.", 503)
        try:
            agents = monitoring_response_to_agents(indexer_search(MONITORING_INDEX, agents_query()))
            activity = sca_activity_response(indexer_search(ALERTS_INDEX, sca_activity_query()))
        except (TypeError, ValueError) as e:
            if isinstance(e, ApiError):
                raise
            raise ReportError(f"Unsupported data from the Wazuh Indexer: {e}") from e
        as_of = now()
        warnings, endpoints = [], []
        ids = sorted(set(agents) | set(activity))
        invalid = [i for i in ids if not AGENT_ID_PATTERN.fullmatch(i)]
        if invalid:
            warnings.append(f"{len(invalid)} agent ID(s) in an unexpected format were skipped.")
        if len(agents) >= MAX_AGENTS or len(activity) >= MAX_AGENTS:
            warnings.append(f"Only the first {MAX_AGENTS} agents are shown.")
        for agent_id in (i for i in ids if AGENT_ID_PATTERN.fullmatch(i)):
            documents = []
            if agent_id in activity:
                try:
                    documents = search_response_to_documents(
                        indexer_search(ALERTS_INDEX, latest_checks_query(agent_id)))
                except (TypeError, ValueError) as e:
                    raise ReportError(f"Unsupported SCA data from the Wazuh Indexer: {e}") from e
                if len(documents) >= MAX_CHECKS:
                    warnings.append(f"Agent {agent_id}: only the newest {MAX_CHECKS} checks are shown.")
            # Only checks whose own agent.id matches are attributed to this endpoint.
            documents = [d for d in documents if d["agent"].get("id") == agent_id]
            agent = agents.get(agent_id) or {"name": activity.get(agent_id, {}).get("name")}
            endpoints.append(build_endpoint(agent_id, agent, documents, find(agent_id, agent.get("name")),
                                            as_of, last_event=activity.get(agent_id, {}).get("last_event")))
        meta = {"mode": "wazuh", "is_sample": False, "label": "Live data from the Wazuh Indexer",
                "as_of": as_of.strftime("%Y-%m-%dT%H:%M:%SZ")}
        return meta, endpoints, warnings

    def sample_observations(endpoints):
        """Synthetic events, FIM, vulnerabilities, ports and BitLocker reports for the sample fleet."""
        try:
            data = parse_json_bytes(Path(observations_sample_path).read_bytes())
        except (OSError, ReportError):
            return {}
        everyone = {e["key"] for e in endpoints}
        obs = {name: {"by_agent": data.get(name, {}), "covered": everyone}
               for name in ("events", "fim", "vulnerabilities", "packages", "ports")}
        obs["bitlocker"] = {h.lower(): v for h, v in data.get("bitlocker", {}).items()}
        obs["bitlocker_max_age_hours"] = None  # sample reports are old by design
        obs["approved"] = data.get("approved", {})
        return obs

    def wazuh_observations(endpoints, warnings):
        """Read the other Wazuh sources. A source that fails is skipped with a warning, never treated as clean."""
        obs, everyone = {}, {e["key"] for e in endpoints}
        online = {e["key"] for e in endpoints if e["connectivity"] == "online"}
        config = risk_config or {}
        reads = []
        if config.get("monitored_events"):
            events = config["monitored_events"]
            reads.append(("events", "Windows security events", ALERTS_INDEX,
                          wazuh_sources.events_query([c["event_id"] for c in events["events"]],
                                                     events.get("lookback_days", 30)),
                          wazuh_sources.events_response, everyone))
        if config.get("fim_baseline"):
            reads.append(("fim", "File integrity monitoring", ALERTS_INDEX,
                          wazuh_sources.fim_query(config["fim_baseline"].get("lookback_days", 30)),
                          wazuh_sources.fim_response, everyone))
        reads += [
            ("vulnerabilities", "Vulnerability detection", wazuh_sources.VULNERABILITIES_INDEX,
             wazuh_sources.vulnerabilities_query(), wazuh_sources.vulnerabilities_response, online),
            ("packages", "Software inventory", wazuh_sources.PACKAGES_INDEX, wazuh_sources.packages_query(),
             wazuh_sources.packages_response, online),
            ("ports", "Open-port inventory", wazuh_sources.PORTS_INDEX, wazuh_sources.ports_query(),
             wazuh_sources.ports_response, online),
        ]
        for name, label, index, query, parse, covered in reads:
            try:
                obs[name] = {"by_agent": parse(indexer_client.search(index, query)), "covered": covered}
            except (IndexerError, TypeError, ValueError) as e:
                warnings.append(f"{label} not available ({e}); those findings were not updated.")
            except Exception:  # an optional source must never break the fleet views
                log.exception("Reading %s failed", label)
                warnings.append(f"{label} could not be read; those findings were not updated.")
        try:
            obs["bitlocker"] = FindingStore(asset_db_path).latest_bitlocker_reports()
        except sqlite3.Error:
            log.exception("Could not read BitLocker reports")
        return obs

    def load_fleet():
        source = request.args.get("source", "sample")
        if source not in FLEET_SOURCES:
            raise ApiError("Unknown data source. Use 'sample' or 'wazuh'.")
        find = assets().lookup_table()
        try:
            meta, endpoints, warnings = (load_sample_fleet if source == "sample" else load_wazuh_fleet)(find)
        except (ApiError, ReportError):
            raise
        except (TypeError, ValueError) as e:
            raise ReportError(f"Unsupported SCA data: {e}") from e
        positions = assets().positions()
        for e in endpoints:
            # A saved marker applies only while the PC is still assigned to that building and floor.
            p = positions.get(e["key"])
            loc = e["location"]
            e["position"] = ({"x": p["x"], "y": p["y"]} if p and (p["building"], p["floor"])
                             == (loc["building"], loc["floor"]) else None)
        service = risk_service()
        seats = {}
        if service is not None:
            observations = (sample_observations(endpoints) if meta["mode"] == "sample"
                            else wazuh_observations(endpoints, warnings))
            try:
                service.sync(meta["mode"], endpoints, observations)
                seats = service.seats(meta["mode"], endpoints)
            except sqlite3.Error:
                log.exception("Could not update stored findings")
                warnings.append("Risk priorities could not be updated; the stored findings may be out of date.")
        for e in endpoints:
            e["risk"] = seats.get(e["key"])
            req = service.requirements(meta["mode"], e["key"]) if service is not None else None
            e["requirements"] = req["requirements"] if req else None
            e["requirement_summary"] = req["summary"] if req else None
        return meta, endpoints, warnings

    def without_checks(endpoint):
        # The fleet list carries counts only; checks and the requirement list come with /api/fleet/endpoint.
        return {k: v for k, v in endpoint.items() if k not in ("checks", "requirements")}

    @app.get("/api/fleet")
    def fleet():
        meta, endpoints, warnings = load_fleet()
        service = risk_service()
        # What this read changed in the stored findings (shown after "Scan now"); None without the store.
        scan = service.last_scan.get(meta["mode"]) if service is not None else None
        return jsonify({"source": meta, "summary": summarize_fleet(endpoints),
                        "endpoints": [without_checks(e) for e in endpoints], "warnings": warnings,
                        "scan": dict(scan, as_of=meta["as_of"]) if scan is not None else None})

    @app.get("/api/fleet/endpoint")
    def fleet_endpoint():
        endpoint_id = request.args.get("id", "")
        if not ENDPOINT_ID_PATTERN.fullmatch(endpoint_id):
            raise ApiError("The endpoint ID is not valid.")
        meta, endpoints, warnings = load_fleet()
        match = next((e for e in endpoints if e["key"] == endpoint_id), None)
        if match is None:
            raise ApiError(f"No endpoint {endpoint_id} in this data source.", 404)
        return jsonify({"source": meta, "endpoint": match, "warnings": warnings})

    @app.get("/api/fleet/findings")
    def fleet_findings():
        meta, endpoints, warnings = load_fleet()
        return jsonify({"source": meta, "findings": prioritize_failures(endpoints), "basis": PRIORITY_BASIS,
                        "endpoints_total": len(endpoints), "warnings": warnings})

    # ---- Risk prioritization (rule-based) and optional local AI explanations ----

    def risk_context():
        """Load (and sync) the fleet; return (service, meta, {endpoint key: location}, warnings)."""
        service = require_risk()
        meta, endpoints, warnings = load_fleet()
        return service, meta, {e["key"]: e["location"] for e in endpoints}, warnings

    @app.get("/api/risk")
    def risk_findings():
        service, meta, locations, warnings = risk_context()
        endpoint_id = request.args.get("endpoint")
        if endpoint_id is not None and not ENDPOINT_ID_PATTERN.fullmatch(endpoint_id):
            raise ApiError("The endpoint ID is not valid.")
        scored, unknown = service.prioritized(meta["mode"], locations, endpoint_id)
        band = request.args.get("band")
        if band:
            scored = [s for s in scored if s["band_key"] == band.lower()]
        return jsonify({
            "source": meta, "warnings": warnings, "findings": scored, "needs_data": unknown,
            "needs_data_count": len(unknown), "weights_version": service.weights["version"],
            "catalogue_version": service.config["catalogue"]["version"],
            "bands": [b["name"] for b in sorted(service.weights["bands"], key=lambda b: -b["min"])],
            "ai_enabled": ai_provider is not None,
        })

    def risk_json():
        require_app_request()
        body = request.get_json(silent=True) if request.is_json else None
        if not isinstance(body, Mapping):
            raise ApiError("Send the request as a JSON object.")
        return body

    @app.post("/api/risk/explain")
    def risk_explain():
        body = risk_json()
        finding_id = body.get("finding_id")
        if isinstance(finding_id, bool) or not isinstance(finding_id, int):
            raise ApiError("finding_id must be a number.")
        service, meta, locations, _ = risk_context()
        view = service.finding(meta["mode"], finding_id, locations)
        if view is None:
            raise ApiError("That finding does not exist in this data source.", 404)
        fallback = fallback_explanation(view)
        result = {"finding_id": finding_id, "reason": view["reason"], "remediation": view["remediation"]}
        if ai_provider is None:
            return jsonify({**result, **fallback, "ai": False, "note": AI_FALLBACK_NOTE})
        try:
            parsed = parse_explanation(ai_provider.generate(explain_prompt(explain_payload(view))))
        except AIError as e:
            return jsonify({**result, **fallback, "ai": False, "note": f"{e} {AI_FALLBACK_NOTE}"})
        if parsed is None:
            return jsonify({**result, **fallback, "ai": False,
                            "note": f"The local AI answer could not be read. {AI_FALLBACK_NOTE}"})
        return jsonify({**result, **parsed, "ai": True, "label": AI_LABEL, "model": ai_provider.model})

    @app.post("/api/risk/summary")
    def risk_summary():
        risk_json()
        service, meta, locations, _ = risk_context()
        scored, unknown = service.prioritized(meta["mode"], locations)
        names = [b["name"] for b in sorted(service.weights["bands"], key=lambda b: -b["min"])]
        counts = summary_payload(scored, len(unknown), names)
        if ai_provider is None:
            return jsonify({"ai": False, "counts": counts, "summary": None, "note": AI_FALLBACK_NOTE})
        try:
            summary = parse_summary(ai_provider.generate(summary_prompt(counts)))
        except AIError as e:
            return jsonify({"ai": False, "counts": counts, "summary": None, "note": f"{e} {AI_FALLBACK_NOTE}"})
        if summary is None:
            return jsonify({"ai": False, "counts": counts, "summary": None,
                            "note": f"The local AI answer could not be read. {AI_FALLBACK_NOTE}"})
        return jsonify({"ai": True, "counts": counts, "summary": summary, "label": AI_LABEL,
                        "model": ai_provider.model})

    # ---- Asset assignments ----

    def require_app_request():
        # Browsers cannot send this header cross-site without a CORS preflight, which this app never allows.
        if request.headers.get("X-Requested-With") != "compliance-dashboard":
            raise ApiError("This request must come from the dashboard.", 403)

    def asset_json():
        require_app_request()
        require_role("admin")
        body = request.get_json(silent=True) if request.is_json else None
        if not isinstance(body, Mapping):
            raise ApiError("Send the assignment as a JSON object.")
        return body

    @app.errorhandler(AssetError)
    def asset_error(e):
        return error(str(e))

    def rescore():
        """Asset importance changed: recompute every stored score now (not only on the next poll)."""
        service = risk_service()
        if service is not None:
            try:
                service.recompute()
            except sqlite3.Error:
                log.exception("Could not recompute risk scores after an asset change")

    @app.get("/api/assets")
    def list_assets():
        return jsonify({"assignments": assets().all()})

    @app.put("/api/assets")
    def save_asset():
        body = asset_json()
        assets().upsert(body.get("key_type"), body.get("key_value"), body)
        rescore()
        return jsonify({"assignments": assets().all()})

    @app.delete("/api/assets")
    def delete_asset():
        body = asset_json()
        if not assets().delete(body.get("key_type"), body.get("key_value")):
            raise ApiError("That assignment does not exist.", 404)
        rescore()
        return jsonify({"assignments": assets().all()})

    @app.post("/api/assets/import")
    def import_assets():
        require_app_request()
        require_role("admin")
        upload_file = request.files.get("file")
        if upload_file is None or not upload_file.filename:
            return error("No file was uploaded. Choose a CSV file first.")
        try:
            text = upload_file.read().decode("utf-8-sig")
        except UnicodeDecodeError:
            return error("The CSV file is not UTF-8 encoded text.")
        count = assets().import_csv(text)
        rescore()
        return jsonify({"imported": count, "assignments": assets().all()})

    # ---- Floor plans and marker positions ----

    @app.get("/api/floorplans")
    def list_floor_plans():
        return jsonify({"floor_plans": assets().floor_plans(), "max_bytes": MAX_IMAGE_BYTES})

    @app.post("/api/floorplans")
    def upload_floor_plan():
        require_app_request()
        require_role("admin")
        upload_file = request.files.get("file")
        if upload_file is None or not upload_file.filename:
            return error("No image was uploaded. Choose a PNG, JPEG or WebP file.")
        assets().save_floor_plan(request.form.get("building"), request.form.get("floor"),
                                 upload_file.filename, upload_file.read(MAX_IMAGE_BYTES + 1))
        return jsonify({"floor_plans": assets().floor_plans()})

    @app.delete("/api/floorplans")
    def delete_floor_plan():
        body = asset_json()
        if not assets().delete_floor_plan(body.get("building"), body.get("floor")):
            raise ApiError("No floor plan for that building and floor.", 404)
        return jsonify({"floor_plans": assets().floor_plans()})

    @app.get("/api/floorplans/image")
    def floor_plan_image():
        found = assets().floor_plan_image(request.args.get("building"), request.args.get("floor"))
        if found is None:
            raise ApiError("No floor plan for that building and floor.", 404)
        content_type, data = found
        response = app.response_class(data, mimetype=content_type)
        response.headers["Content-Disposition"] = "inline"
        response.headers["Cache-Control"] = "no-cache"
        return response

    @app.put("/api/positions")
    def save_position():
        body = asset_json()
        endpoint_id = body.get("agent_id")
        if not isinstance(endpoint_id, str) or not ENDPOINT_ID_PATTERN.fullmatch(endpoint_id):
            raise ApiError("The endpoint ID is not valid.")
        # The marker is tied to an endpoint that exists in the chosen source and to its assigned floor.
        _, endpoints, _ = load_fleet()
        endpoint = next((e for e in endpoints if e["key"] == endpoint_id), None)
        if endpoint is None:
            raise ApiError(f"No endpoint {endpoint_id} in this data source.", 404)
        loc = endpoint["location"]
        if not loc["building"] or not loc["floor"]:
            raise ApiError("Assign a building and floor to this PC on the Assets tab before placing it.")
        assets().set_position(endpoint_id, loc["building"], loc["floor"], body.get("x"), body.get("y"))
        return jsonify({"agent_id": endpoint_id, "building": loc["building"], "floor": loc["floor"],
                        "position": {"x": float(body["x"]), "y": float(body["y"])}})

    @app.delete("/api/positions")
    def delete_position():
        body = asset_json()
        if not assets().delete_position(body.get("agent_id")):
            raise ApiError("That PC has no saved position.", 404)
        return jsonify({"agent_id": body.get("agent_id")})

    register_workflow_routes(app, {
        "risk_service": require_risk, "load_fleet": load_fleet, "require_app_request": require_app_request,
        "require_role": require_role, "current_user": current_user, "users": users, "now": now,
        "findings": lambda: FindingStore(asset_db_path), "collector_token": collector_token, "error": ApiError,
    })
    return app
