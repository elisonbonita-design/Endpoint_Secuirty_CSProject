"""Map Wazuh 4.x SCA alerts into the document shape used by ``compliance.scoring``.

Verified against a live Wazuh 4.14.8 lab: SCA results are indexed as alerts in
``wazuh-alerts-4.x-*`` (rule.groups "sca"), one alert per check with
``data.sca.type == "check"``:

    data.sca.policy            policy name
    data.sca.check.id/title/result/reason/remediation/rationale/description
    data.sca.check.compliance  {framework: "ctrl1,ctrl2"}  (comma-separated string)

Later scans only alert on checks whose result changed, so the current state of
each check is its most recent alert (see ``latest_checks_query``).

Also verified there: the agent inventory is snapshotted into ``wazuh-monitoring-*``
(one document per agent per run: ``id``, ``name``, ``status`` such as "active",
"disconnected", "pending" or "never_connected", ``lastKeepAlive``, ``ip``, ``os.name``).
SCA check alerts carry the examined target (``command``, ``registry``, ``file`` ...)
but no actual or expected value.
"""

import re
from collections.abc import Mapping

ALERTS_INDEX = "wazuh-alerts-4.x-*"
MONITORING_INDEX = "wazuh-monitoring-*"
MAX_AGENTS = 500
AGENT_ID_PATTERN = re.compile(r"^\d{3,8}$")
MAX_CHECKS = 5000

_CHECK_FIELDS = ("id", "title", "result", "reason", "remediation", "rationale", "description",
                 "compliance", "references")
# Rule targets Wazuh reports for a check: what was examined, not the value found.
TARGET_FIELDS = ("command", "registry", "file", "directory", "process")


def latest_checks_query(agent_id, size=MAX_CHECKS):
    """OpenSearch query returning the newest SCA check alert per check id for one agent."""
    if not isinstance(agent_id, str) or not AGENT_ID_PATTERN.fullmatch(agent_id):
        raise ValueError("agent_id must be 3-8 digits, e.g. '001'")
    return {
        "size": size,
        "query": {"bool": {"filter": [
            {"term": {"agent.id": agent_id}},
            {"term": {"rule.groups": "sca"}},
            {"term": {"data.sca.type": "check"}},
        ]}},
        "collapse": {"field": "data.sca.check.id"},
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["timestamp", "agent.id", "agent.name", "data.sca.policy", "data.sca.scan_id"]
                   + [f"data.sca.check.{field}" for field in _CHECK_FIELDS + TARGET_FIELDS],
    }


def agents_query(size=MAX_AGENTS):
    """Newest ``wazuh-monitoring`` snapshot per agent id."""
    return {
        "size": size,
        "collapse": {"field": "id"},
        "sort": [{"timestamp": {"order": "desc"}}],
        "_source": ["id", "name", "status", "lastKeepAlive", "timestamp", "ip", "os.name"],
    }


def sca_activity_query(size=MAX_AGENTS):
    """Agents with SCA alerts and the time of each agent's newest SCA alert (check or summary)."""
    return {
        "size": 0,
        "query": {"bool": {"filter": [{"term": {"rule.groups": "sca"}}]}},
        "aggs": {"agents": {
            "terms": {"field": "agent.id", "size": size},
            "aggs": {"last_event": {"max": {"field": "timestamp"}},
                     "name": {"terms": {"field": "agent.name", "size": 1}}},
        }},
    }


def _hits(response):
    try:
        hits = response["hits"]["hits"]
    except (KeyError, TypeError) as e:
        raise ValueError("unexpected Indexer search response") from e
    if not isinstance(hits, list):
        raise ValueError("unexpected Indexer search response")
    return hits


def _str_or_none(value):
    return value if isinstance(value, str) and value else None


def monitoring_response_to_agents(response):
    """``{agent_id: {"id", "name", "status", "last_keepalive", "ip", "os"}}`` from ``agents_query``."""
    agents = {}
    for hit in _hits(response):
        source = hit.get("_source") if isinstance(hit, Mapping) else None
        if not isinstance(source, Mapping) or not isinstance(source.get("id"), str):
            continue
        os_info = source.get("os") if isinstance(source.get("os"), Mapping) else {}
        agents.setdefault(source["id"], {
            "id": source["id"],
            "name": _str_or_none(source.get("name")),
            "status": _str_or_none(source.get("status")),
            "last_keepalive": _str_or_none(source.get("lastKeepAlive")),
            "ip": _str_or_none(source.get("ip")),
            "os": _str_or_none(os_info.get("name")),
        })
    return agents


def sca_activity_response(response):
    """``{agent_id: {"last_event": ISO time or None, "name": agent name or None}}``."""
    try:
        buckets = response["aggregations"]["agents"]["buckets"]
    except (KeyError, TypeError) as e:
        raise ValueError("unexpected Indexer aggregation response") from e
    activity = {}
    for bucket in buckets if isinstance(buckets, list) else []:
        if not isinstance(bucket, Mapping) or not isinstance(bucket.get("key"), str):
            continue
        last = bucket.get("last_event") if isinstance(bucket.get("last_event"), Mapping) else {}
        names = (bucket.get("name") or {}).get("buckets") if isinstance(bucket.get("name"), Mapping) else None
        name = names[0].get("key") if isinstance(names, list) and names and isinstance(names[0], Mapping) else None
        activity[bucket["key"]] = {"last_event": _str_or_none(last.get("value_as_string")),
                                   "name": _str_or_none(name)}
    return activity


def _flatten_compliance(compliance, prefix=""):
    """Yield (framework, value) pairs, rejoining keys Wazuh split on dots.

    Wazuh 4.x indexes "pci_dss_v4.0": "x" as {"pci_dss_v4": {"0": "x"}}.
    """
    for key, value in compliance.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping):
            yield from _flatten_compliance(value, name)
        else:
            yield name, value


def _split_controls(value):
    if isinstance(value, list):
        items = value
    elif isinstance(value, (str, int, float)):
        items = str(value).split(",")
    else:
        return []
    return [str(item).strip() for item in items if str(item).strip()]


def _split_targets(value):
    items = value if isinstance(value, list) else [value]
    return [item for item in items if isinstance(item, str) and item.strip()]


def alert_to_document(source):
    """Convert one alert ``_source`` into ``{"check": ..., "policy": ..., "agent": ..., "state": ...}``."""
    if not isinstance(source, Mapping):
        raise TypeError("alert _source must be a mapping")
    data = source.get("data")
    sca = data.get("sca") if isinstance(data, Mapping) else None
    check = sca.get("check") if isinstance(sca, Mapping) else None
    if not isinstance(check, Mapping):
        raise ValueError("alert has no data.sca.check object")

    compliance = check.get("compliance")
    agent = source.get("agent") if isinstance(source.get("agent"), Mapping) else {}
    return {
        "check": {
            "id": check.get("id"),
            "name": check.get("title"),
            "result": check.get("result"),
            "reason": check.get("reason"),
            "remediation": check.get("remediation"),
            "rationale": check.get("rationale"),
            "description": check.get("description"),
            "targets": {field: _split_targets(check.get(field)) for field in TARGET_FIELDS
                        if _split_targets(check.get(field))},
            "compliance": {
                name: controls
                for name, controls in ((n, _split_controls(v)) for n, v in _flatten_compliance(compliance))
                if controls
            } if isinstance(compliance, Mapping) else {},
        },
        "policy": {"name": sca.get("policy")},
        "agent": {"id": agent.get("id"), "name": agent.get("name")},
        "state": {"modified_at": source.get("timestamp")},
    }


def search_response_to_documents(response):
    """Convert an OpenSearch ``_search`` response into a list of SCA documents."""
    hits = _hits(response)
    return [alert_to_document(hit.get("_source") if isinstance(hit, Mapping) else None) for hit in hits]
