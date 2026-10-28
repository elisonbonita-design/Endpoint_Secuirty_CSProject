"""Finding workflow, accounts, compliance report and the BitLocker collector endpoint.

Kept apart from app.py; ``register_workflow_routes`` receives the helpers it needs from
``create_app``.
"""

import csv
import hmac
import io
import logging
from collections import Counter
from collections.abc import Mapping

from flask import jsonify, render_template, request

from compliance.risk import band_key
from compliance.risk_config import in_scope

from .auth import AuthError
from .collector import ReportRejected, parse_report
from .findings_db import MANUAL_TRANSITIONS, WorkflowError
from .prioritization import location_text

log = logging.getLogger(__name__)
STATUS_ORDER = ("open", "in_review", "fixed_pending", "exception", "cleared", "verified")
SOURCE_LABELS = {"sca": "Configuration (SCA)", "event": "Security event", "inventory": "Inventory",
                 "vulnerability": "Vulnerability", "fim": "File integrity", "bitlocker": "BitLocker"}
CSV_FIELDS = ("id", "endpoint_label", "endpoint_id", "seat", "source", "requirement_id", "title", "state", "status",
              "severity", "cvss", "cve_id", "score", "band", "days_open", "opened_at", "verified_at",
              "times_reopened", "catalogue_version", "weights_version")


def _csv_cell(value):
    """Plain text for spreadsheets: values starting with = + - @ are prefixed so they never run as formulas."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def allowed_transitions(status, role):
    allowed = list(MANUAL_TRANSITIONS.get(status, ()))
    if role != "admin":
        allowed = [s for s in allowed if s != "exception" and status != "exception"]
    return allowed


def register_workflow_routes(app, ctx):
    risk_service, load_fleet, require_role = ctx["risk_service"], ctx["load_fleet"], ctx["require_role"]
    require_app_request, current_user, now = ctx["require_app_request"], ctx["current_user"], ctx["now"]
    findings, users, ApiError = ctx["findings"], ctx["users"], ctx["error"]

    @app.errorhandler(WorkflowError)
    def workflow_error(e):
        return jsonify({"error": str(e)}), e.status

    @app.errorhandler(AuthError)
    def auth_error(e):
        return jsonify({"error": str(e)}), 400

    def json_body():
        require_app_request()
        body = request.get_json(silent=True) if request.is_json else None
        if not isinstance(body, Mapping):
            raise ApiError("Send the request as a JSON object.")
        return body

    def finding_context(finding_id):
        service = risk_service()
        meta, endpoints, _ = load_fleet()
        locations = {e["key"]: e["location"] for e in endpoints}
        row = findings().get(finding_id)
        if row is None or row["data_source"] != meta["mode"]:
            raise ApiError("That finding does not exist in this data source.", 404)
        return service, meta, row, service.finding(meta["mode"], finding_id, locations)

    # ---- Findings: detail, history and the review workflow ----

    @app.get("/api/findings/<int:finding_id>")
    def finding_detail(finding_id):
        _, _, row, view = finding_context(finding_id)
        user = current_user()
        return jsonify({"finding": view, "history": findings().history(finding_id),
                        "scores": findings().score_history(finding_id),
                        "allowed": allowed_transitions(row["status"], user["role"])})

    @app.post("/api/findings/<int:finding_id>/status")
    def finding_status(finding_id):
        body = json_body()
        user = require_role("admin", "reviewer")
        service, meta, _, _ = finding_context(finding_id)
        findings().change_status(finding_id, body.get("status"), user["username"], user["role"], body.get("note"),
                                 now())
        service.recompute(meta["mode"])  # an exception or a status change can change the score
        log.info("Finding %s set to %s by %s", finding_id, body.get("status"), user["username"])
        return finding_detail(finding_id)

    @app.post("/api/findings/<int:finding_id>/notes")
    def finding_note(finding_id):
        body = json_body()
        user = require_role("admin", "reviewer")
        finding_context(finding_id)
        findings().add_note(finding_id, user["username"], body.get("note"), now())
        return finding_detail(finding_id)

    # ---- Accounts (admin) ----

    @app.get("/api/users")
    def list_users():
        require_role("admin")
        return jsonify({"users": users().all()})

    @app.post("/api/users")
    def create_user():
        body = json_body()
        require_role("admin")
        users().create(body.get("username"), body.get("password"), body.get("role"), now())
        return jsonify({"users": users().all()})

    @app.patch("/api/users/<int:user_id>")
    def update_user(user_id):
        body = json_body()
        actor = require_role("admin")
        users().update(user_id, role=body.get("role"), active=body.get("active"), password=body.get("password"),
                       actor_id=actor["id"])
        return jsonify({"users": users().all()})

    # ---- Compliance report ----

    def report_data():
        service = risk_service()
        meta, endpoints, warnings = load_fleet()
        locations = {e["key"]: e["location"] for e in endpoints}
        scored, unknown = service.prioritized(meta["mode"], locations)
        # Closed or excepted findings stay in the report with their history (evidence of verification).
        catalogue = service.config["catalogue"]
        closed = [service.finding(meta["mode"], r["id"], locations) for r in findings().all(meta["mode"])
                  if r["status"] in ("exception", "cleared", "verified") and in_scope(r, catalogue)]
        all_items = scored + unknown + closed
        return {
            "meta": meta, "warnings": warnings, "scored": scored, "unknown": unknown, "closed": closed,
            "histories": findings().histories([f["id"] for f in all_items]),
            "by_band": Counter(s["band"] for s in scored),
            "by_status": Counter(f["status"] for f in all_items),
            "by_source": Counter(f["source"] for f in all_items),
            "bands": [b["name"] for b in sorted(service.weights["bands"], key=lambda b: -b["min"])],
            "endpoints": [{"key": e["key"], "hostname": e["hostname"], "seat": location_text(e["location"]),
                           "risk": e.get("risk"), "status": e["status"], "connectivity": e["connectivity"],
                           "requirements": e.get("requirement_summary"),
                           "benchmark": e["counts"].get("pass_percentage")}
                          for e in endpoints],
            "weights_version": service.weights["version"],
            "catalogue_version": service.config["catalogue"]["version"],
        }

    @app.get("/report")
    def report_page():
        data = report_data()
        return render_template("report.html", d=data, user=current_user(), generated_at=now(),
                               status_order=STATUS_ORDER, source_labels=SOURCE_LABELS, band_key=band_key)

    @app.get("/api/reports/findings.csv")
    def report_csv():
        data = report_data()
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(CSV_FIELDS)
        for item in data["scored"] + data["unknown"] + data["closed"]:
            writer.writerow([_csv_cell(item.get(f)) for f in CSV_FIELDS])
        response = app.response_class(out.getvalue(), mimetype="text/csv")
        response.headers["Content-Disposition"] = f'attachment; filename="findings-{data["meta"]["mode"]}.csv"'
        return response

    @app.get("/api/requirements")
    def requirements():
        catalogue = risk_service().config["catalogue"]
        return jsonify({"version": catalogue["version"], "requirements": [
            {k: r.get(k) for k in ("id", "area", "title", "severity", "exposure", "remediation")} |
            {"mapped_checks": len(r.get("sca_checks") or [])} for r in catalogue["requirements"].values()]})

    # ---- BitLocker collector (Bearer token, no browser session) ----

    @app.post("/api/collector/bitlocker")
    def collector_bitlocker():
        token = ctx["collector_token"]
        if not token:
            return jsonify({"error": "The BitLocker collector is not enabled on this server."}), 503
        auth = request.headers.get("Authorization", "")
        sent = auth[7:] if auth.startswith("Bearer ") else ""
        if not hmac.compare_digest(sent.encode("utf-8"), token.encode("utf-8")):
            log.warning("BitLocker report rejected: bad token from %s", request.remote_addr)
            return jsonify({"error": "Not authorized."}), 401
        try:
            hostname, collected_at, volumes = parse_report(request.get_json(silent=True), now())
        except ReportRejected as e:
            return jsonify({"error": str(e)}), 400
        findings().save_bitlocker_report(hostname, collected_at, volumes, now())
        return jsonify({"stored": len(volumes), "hostname": hostname})
