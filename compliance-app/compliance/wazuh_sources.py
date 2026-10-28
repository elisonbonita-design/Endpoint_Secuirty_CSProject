"""Read-only Wazuh Indexer queries for the non-SCA sources, and parsers for their responses.

Field names and how sure we are of them:
    alerts (wazuh-alerts-4.x-*)     agent.id, timestamp, data.win.system.eventID, rule.groups "syscheck",
                                    syscheck.path, syscheck.event: standard Wazuh 4.x alert fields, but not
                                    yet seen in this lab (no Windows events or FIM alerts captured so far)
    wazuh-states-vulnerabilities-*  agent.id, package.name/version, vulnerability.id, vulnerability.score.base
    wazuh-states-inventory-packages-* / -ports-*
                                    package.name; source.port, network.transport, interface.state,
                                    process.name (from wazuh-src docs/ref/modules/syscollector/events.md)
State indices are read for both agent.id (4.x) and wazuh.agent.id (5.x documentation). If an index
is missing in the lab the query fails, the dashboard shows a warning and that source is skipped.
"""

from collections.abc import Mapping

ALERTS_INDEX = "wazuh-alerts-4.x-*"
VULNERABILITIES_INDEX = "wazuh-states-vulnerabilities-*"
PACKAGES_INDEX = "wazuh-states-inventory-packages-*"
PORTS_INDEX = "wazuh-states-inventory-ports-*"
MAX_AGENTS = 500
MAX_DOCS = 10000  # OpenSearch default max_result_window


def _since(days):
    return {"range": {"timestamp": {"gte": f"now-{int(days)}d"}}}


def events_query(event_ids, lookback_days):
    """Newest time and count of each monitored Windows event ID per agent."""
    return {
        "size": 0,
        "query": {"bool": {"filter": [{"terms": {"data.win.system.eventID": list(event_ids)}},
                                      _since(lookback_days)]}},
        "aggs": {"agents": {"terms": {"field": "agent.id", "size": MAX_AGENTS}, "aggs": {
            "events": {"terms": {"field": "data.win.system.eventID", "size": 50},
                       "aggs": {"last": {"max": {"field": "timestamp"}}}}}}},
    }


def _buckets(node, name):
    value = node.get(name) if isinstance(node, Mapping) else None
    buckets = value.get("buckets") if isinstance(value, Mapping) else None
    if not isinstance(buckets, list):
        raise ValueError("unexpected Indexer aggregation response")
    return [b for b in buckets if isinstance(b, Mapping) and isinstance(b.get("key"), (str, int))]


def events_response(response):
    """{agent_id: {event_id: {"last": iso, "count": n}}}."""
    out = {}
    for agent in _buckets(response.get("aggregations") if isinstance(response, Mapping) else None, "agents"):
        for event in _buckets(agent, "events"):
            last = event.get("last") if isinstance(event.get("last"), Mapping) else {}
            if isinstance(last.get("value_as_string"), str):
                out.setdefault(str(agent["key"]), {})[str(event["key"])] = {
                    "last": last["value_as_string"], "count": int(event.get("doc_count") or 0)}
    return out


def fim_query(lookback_days, per_path=3):
    """Newest syscheck alerts per agent and path."""
    return {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {"rule.groups": "syscheck"}}, _since(lookback_days)]}},
        "aggs": {"agents": {"terms": {"field": "agent.id", "size": MAX_AGENTS}, "aggs": {
            "paths": {"terms": {"field": "syscheck.path", "size": 1000}, "aggs": {
                "latest": {"top_hits": {"size": per_path, "sort": [{"timestamp": {"order": "desc"}}],
                                        "_source": ["timestamp", "syscheck.path", "syscheck.event"]}}}}}}},
    }


def fim_response(response):
    """{agent_id: [{"path", "event", "at"}]}."""
    out = {}
    for agent in _buckets(response.get("aggregations") if isinstance(response, Mapping) else None, "agents"):
        for path in _buckets(agent, "paths"):
            hits = (((path.get("latest") or {}).get("hits") or {}).get("hits")) or []
            for hit in hits:
                src = hit.get("_source") if isinstance(hit, Mapping) else None
                syscheck = src.get("syscheck") if isinstance(src, Mapping) else None
                if isinstance(syscheck, Mapping) and isinstance(src.get("timestamp"), str):
                    out.setdefault(str(agent["key"]), []).append(
                        {"path": syscheck.get("path") or str(path["key"]), "event": syscheck.get("event"),
                         "at": src["timestamp"]})
    return out


def _state_query(fields):
    return {"size": MAX_DOCS, "query": {"match_all": {}},
            "_source": ["agent.id", "wazuh.agent.id", *fields]}


def vulnerabilities_query():
    return _state_query(["package.name", "package.version", "vulnerability.id", "vulnerability.score.base"])


def packages_query():
    return _state_query(["package.name"])


def ports_query():
    return _state_query(["source.port", "network.transport", "interface.state", "process.name"])


def _hits(response):
    try:
        hits = response["hits"]["hits"]
    except (KeyError, TypeError) as e:
        raise ValueError("unexpected Indexer search response") from e
    if not isinstance(hits, list):
        raise ValueError("unexpected Indexer search response")
    return [h["_source"] for h in hits if isinstance(h, Mapping) and isinstance(h.get("_source"), Mapping)]


def _get(doc, path):
    for part in path.split("."):
        doc = doc.get(part) if isinstance(doc, Mapping) else None
    return doc


def _agent(doc):
    agent = _get(doc, "agent.id") or _get(doc, "wazuh.agent.id")
    return str(agent) if isinstance(agent, (str, int)) else None


def vulnerabilities_response(response):
    out = {}
    for doc in _hits(response):
        agent, cve = _agent(doc), _get(doc, "vulnerability.id")
        if agent and isinstance(cve, str):
            score = _get(doc, "vulnerability.score.base")
            out.setdefault(agent, []).append({
                "cve": cve, "package": _get(doc, "package.name"), "version": _get(doc, "package.version"),
                "cvss": float(score) if isinstance(score, (int, float)) and 0 <= score <= 10 else None})
    return out


def packages_response(response):
    out = {}
    for doc in _hits(response):
        agent, name = _agent(doc), _get(doc, "package.name")
        if agent and isinstance(name, str) and name.strip():
            out.setdefault(agent, set()).add(name.strip())
    return {agent: sorted(names) for agent, names in out.items()}


def ports_response(response):
    """Listening TCP ports, and UDP ports (UDP has no listening state)."""
    out = {}
    for doc in _hits(response):
        agent, port = _agent(doc), _get(doc, "source.port")
        # Windows lists IPv4 and IPv6 sockets separately (tcp / tcp6); one port is one finding.
        transport = (_get(doc, "network.transport") or "tcp").lower().rstrip("6")
        state = (_get(doc, "interface.state") or "").lower()
        if not agent or not isinstance(port, int) or not (state == "listening" or transport.startswith("udp")):
            continue
        out.setdefault(agent, {})[(transport, port)] = {"port": port, "transport": transport,
                                                       "process": _get(doc, "process.name")}
    return {agent: list(ports.values()) for agent, ports in out.items()}
