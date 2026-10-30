"""Approved listening ports (REQ-NP-01): view the list and each endpoint's ports; admins change the list.

Kept apart from app.py; ``register_port_routes`` receives the helpers it needs from ``create_app``.
What the page shows comes from ``sources.port_checks``, the same function the rule uses.
"""

import logging
from collections.abc import Mapping

from flask import jsonify, request

from compliance.sources import port_checks

from .ports_db import PortError

log = logging.getLogger(__name__)


def register_port_routes(app, ctx):
    ports, listening_ports, require_role = ctx["ports"], ctx["listening_ports"], ctx["require_role"]
    require_app_request, now, ApiError = ctx["require_app_request"], ctx["now"], ctx["error"]

    @app.errorhandler(PortError)
    def port_error(e):
        return jsonify({"error": str(e)}), 400

    def body():
        require_app_request()
        data = request.get_json(silent=True) if request.is_json else None
        if not isinstance(data, Mapping):
            raise ApiError("Send the request as a JSON object.")
        return data

    def listing():
        entries = ports().entries()
        return {"entries": entries, "history": ports().history(), "rule_on": bool(entries)}

    @app.get("/api/ports")
    def ports_list():
        return jsonify(listing())

    @app.post("/api/ports")
    def ports_add():
        data = body()
        user = require_role("admin")
        kind, value = ports().add(data.get("kind"), data.get("value"), data.get("note"), user["username"], now())
        log.info("Approved %s added by %s: %s", kind, user["username"], value)
        return jsonify(listing())

    @app.delete("/api/ports/<int:entry_id>")
    def ports_remove(entry_id):
        data = body()
        user = require_role("admin")
        kind, value = ports().remove(entry_id, data.get("note"), user["username"], now())
        log.info("Approved %s removed by %s: %s", kind, user["username"], value)
        return jsonify(listing())

    @app.get("/api/ports/listening")
    def ports_listening():
        endpoint_id = request.args.get("id", "")
        found, (numbers, programs), sample_list = listening_ports(endpoint_id)
        checks, skipped = port_checks(found, numbers, programs)
        return jsonify({"endpoint_id": endpoint_id, "checks": checks, "skipped": skipped,
                        "rule_on": bool(numbers or programs), "sample_list": sample_list})

    @app.post("/api/ports/approve-listening")
    def ports_approve_listening():
        """Record an endpoint's current listening ports as approved: the known-good baseline."""
        data = body()
        user = require_role("admin")
        found, (numbers, programs), sample_list = listening_ports(data.get("endpoint_id", ""))
        if sample_list:
            raise ApiError("The sample data has its own fixed list; switch to Live Wazuh to change approvals.")
        missing = [(c["kind"], c["value"]) for c in port_checks(found, numbers, programs)[0] if not c["approved"]]
        added = ports().add_many(missing, data.get("note") or f"Baseline from endpoint {data.get('endpoint_id')}",
                                 user["username"], now())
        log.info("Approved ports baseline by %s: %d entr(ies)", user["username"], len(added))
        return jsonify(dict(listing(), added=[{"kind": k, "value": v} for k, v in added]))
