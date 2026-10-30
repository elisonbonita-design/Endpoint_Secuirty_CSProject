"""Approved software (REQ-SW-01): view the list and each endpoint's installed programs; admins change the list.

Kept apart from app.py; ``register_software_routes`` receives the helpers it needs from
``create_app``. A change takes effect at the next read of the fleet (the page re-reads at once).
"""

import logging
from collections.abc import Mapping

from flask import jsonify, request

from compliance.sources import software_approved

from .software_db import SoftwareError

log = logging.getLogger(__name__)


def register_software_routes(app, ctx):
    software, installed_programs, require_role = ctx["software"], ctx["installed_programs"], ctx["require_role"]
    require_app_request, current_user, now, ApiError = (ctx["require_app_request"], ctx["current_user"], ctx["now"],
                                                        ctx["error"])

    @app.errorhandler(SoftwareError)
    def software_error(e):
        return jsonify({"error": str(e)}), 400

    def body():
        require_app_request()
        data = request.get_json(silent=True) if request.is_json else None
        if not isinstance(data, Mapping):
            raise ApiError("Send the request as a JSON object.")
        return data

    def listing():
        entries = software().entries()
        return {"entries": entries, "history": software().history(), "rule_on": bool(entries)}

    @app.get("/api/software")
    def software_list():
        return jsonify(listing())

    @app.post("/api/software")
    def software_add():
        data = body()
        user = require_role("admin")
        name = software().add(data.get("name"), data.get("note"), user["username"], now())
        log.info("Approved software added by %s: %s", user["username"], name)
        return jsonify(listing())

    @app.delete("/api/software/<int:entry_id>")
    def software_remove(entry_id):
        data = body()
        user = require_role("admin")
        name = software().remove(entry_id, data.get("note"), user["username"], now())
        log.info("Approved software removed by %s: %s", user["username"], name)
        return jsonify(listing())

    @app.get("/api/software/installed")
    def software_installed():
        endpoint_id = request.args.get("id", "")
        programs, approved, own_list = installed_programs(endpoint_id)
        rows = []
        for name in programs:
            match = next((a for a in approved if software_approved(name, (a,))), None)
            rows.append({"name": name, "approved": match is not None, "matched_by": match})
        return jsonify({"endpoint_id": endpoint_id, "programs": rows, "rule_on": bool(approved),
                        "sample_list": own_list})

    @app.post("/api/software/approve-installed")
    def software_approve_installed():
        """Record an endpoint's current programs as approved: the known-good baseline."""
        data = body()
        user = require_role("admin")
        programs, approved, own_list = installed_programs(data.get("endpoint_id", ""))
        if own_list:
            raise ApiError("The sample data has its own fixed list; switch to Live Wazuh to change approvals.")
        missing = [p for p in programs if not software_approved(p, approved)]
        added = software().add_many(missing, data.get("note") or f"Baseline from endpoint {data.get('endpoint_id')}",
                                    user["username"], now())
        log.info("Approved software baseline by %s: %d program(s)", user["username"], len(added))
        return jsonify(dict(listing(), added=added))
