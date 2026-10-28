"""Rule-based risk prioritization of findings (pure functions, no I/O).

Score = Severity + Exposure + Asset importance + Time open + Repeat, clamped to
0..score_max. Every number comes from the weights mapping (config/risk_weights.json,
loaded and validated by ``compliance.risk_config``); nothing here reads files, the
clock or the network. ``now`` is always passed in.

Only findings in state ``non_compliant`` with status open, in_review or
fixed_pending are scored. Unknown-state findings are "Needs data" and are never
scored, so missing data is never treated as a confirmed failure. The optional
local AI never calls into this module's results to change them: priority is
decided here only.
"""

import math
from collections.abc import Mapping
from datetime import datetime, timezone

SCORED_STATUSES = ("open", "in_review", "fixed_pending")
CLOSED_STATUSES = ("cleared", "verified")
SEVERITIES = ("critical", "high", "medium", "low")
ROLES = ("agent", "team_lead", "it_admin", "shared_kiosk")
EXPOSURE_TAGS = ("defender_off", "firewall_off", "unapproved_port")

_EXPOSURE_LABELS = {
    "defender_off": "Defender real-time protection off on this endpoint",
    "firewall_off": "Windows Firewall off on this endpoint",
    "unapproved_port": "unapproved listening port on this endpoint",
}
_ROLE_LABELS = {"team_lead": "team lead role", "it_admin": "IT admin role", "shared_kiosk": "shared kiosk"}
# Seat colours on the floor plan: band keys plus "clear" (results, nothing scored) and "unknown".
SEAT_LETTERS = {"critical": "C", "high": "H", "medium": "M", "low": "L", "clear": "✓", "unknown": "?"}


def _parse_time(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def band_key(name):
    return name.lower()


def band_for(score, weights):
    """Band name (e.g. "Critical") for a score; bands are checked from the highest minimum down."""
    for band in sorted(weights["bands"], key=lambda b: -b["min"]):
        if score >= band["min"]:
            return band["name"]
    return weights["bands"][-1]["name"]


def band_rank(name, weights):
    """0 for the most urgent band, larger for less urgent ones."""
    ordered = [b["name"] for b in sorted(weights["bands"], key=lambda b: -b["min"])]
    return ordered.index(name)


def days_open(opened_at, now):
    """Full days since ``opened_at`` (never negative); 0 when the time is unknown."""
    opened = _parse_time(opened_at)
    if opened is None:
        return 0
    return max(0, math.floor((now - opened).total_seconds() / 86400))


def is_scorable(finding):
    return finding.get("state") == "non_compliant" and finding.get("status") in SCORED_STATUSES


def needs_data(finding):
    return finding.get("state") == "unknown" and finding.get("status") in SCORED_STATUSES


def _half_up(value):
    return int(math.floor(value + 0.5))


def _severity(finding, weights):
    w = weights["severity"]
    severity = finding.get("severity")
    if finding.get("requirement_id") and severity in w["requirement"]:
        return min(w["max"], w["requirement"][severity]), f"{severity} requirement"
    cvss = finding.get("cvss")
    if finding.get("source") == "vulnerability" and isinstance(cvss, (int, float)) and not isinstance(cvss, bool):
        return min(w["max"], max(0, _half_up(cvss * w["cvss_multiplier"]))), f"CVSS {cvss:g}"
    return min(w["max"], w["default"]), "no severity rating"


def _exposure_tag(finding, requirements):
    req = requirements.get(finding.get("requirement_id")) if finding.get("requirement_id") else None
    tag = req.get("exposure") if isinstance(req, Mapping) else None
    return tag if tag in EXPOSURE_TAGS else None


def _exposure(finding, endpoint_findings, requirements, weights, kev_ids, listening_ports, approved_ports):
    """[(points, label)] before the cap. The finding's own condition never counts for itself."""
    w = weights["exposure"]
    own = _exposure_tag(finding, requirements)
    present = set()
    for other in endpoint_findings:
        if other is finding or (other.get("id") is not None and other.get("id") == finding.get("id")):
            continue
        if is_scorable(other):
            tag = _exposure_tag(other, requirements)
            if tag:
                present.add(tag)
    # An unapproved listening port is known either from an open port finding or from listening_ports.
    if any(port not in approved_ports for port in listening_ports):
        present.add("unapproved_port")
    factors = [(w[tag], _EXPOSURE_LABELS[tag]) for tag in ("defender_off", "firewall_off")
               if tag in present and tag != own]
    cve = finding.get("cve_id")
    if cve and cve in kev_ids:
        factors.append((w["known_exploited"], f"{cve} is in the known-exploited list"))
    if "unapproved_port" in present and own != "unapproved_port":
        factors.append((w["unapproved_port"], _EXPOSURE_LABELS["unapproved_port"]))
    return [f for f in factors if f[0] > 0]


def _asset(asset, weights):
    w = weights["asset"]
    asset = asset or {}
    factors = []
    if asset.get("handles_client_data"):
        factors.append((w["handles_client_data"], "handles client data"))
    role = asset.get("role") if asset.get("role") in ROLES else "agent"
    if w["role"].get(role, 0) > 0:
        factors.append((w["role"][role], _ROLE_LABELS.get(role, role)))
    return [f for f in factors if f[0] > 0]


def _capped(factors, cap, name):
    """Sum a group of factors; if over the cap, report them as one capped factor so the reason still adds up."""
    raw = sum(p for p, _ in factors)
    if raw <= cap:
        return raw, factors
    joined = ", ".join(label for _, label in factors)
    return cap, [(cap, f"{joined} ({name} capped at {cap})")]


def score_finding(finding, *, requirements, endpoint_findings, asset, weights, now,
                  kev_ids=frozenset(), listening_ports=(), approved_ports=frozenset()):
    """Score one finding, or return None if it is not scorable.

    ``finding``: mapping with id, title, source, state, status, requirement_id, severity,
    cvss, cve_id, opened_at (datetime or ISO text) and times_reopened.
    ``endpoint_findings``: every finding on the same endpoint (may include this one).
    ``requirements``: {requirement_id: {"exposure": "defender_off" | "firewall_off" | None, ...}}.
    ``asset``: {"handles_client_data": bool, "role": one of ROLES} (may be empty).
    """
    if not is_scorable(finding):
        return None
    severity_pts, severity_label = _severity(finding, weights)
    exposure_pts, exposure_factors = _capped(
        _exposure(finding, endpoint_findings, requirements, weights, kev_ids, listening_ports, approved_ports),
        weights["exposure"]["max"], "exposure")
    asset_pts, asset_factors = _capped(_asset(asset, weights), weights["asset"]["max"], "asset importance")
    days = days_open(finding.get("opened_at"), now)
    time_pts = min(weights["time_open"]["max"], days * weights["time_open"]["points_per_day"])
    repeat = weights["repeat"]
    repeat_pts = repeat["points"] if (finding.get("times_reopened") or 0) >= repeat["min_times_reopened"] else 0

    score = max(0, min(weights["score_max"], severity_pts + exposure_pts + asset_pts + time_pts + repeat_pts))
    band = band_for(score, weights)

    factors = [(severity_pts, severity_label), *exposure_factors, *asset_factors,
               (time_pts, f"open {days} day{'' if days == 1 else 's'}"), (repeat_pts, "happened before")]
    # Largest first; equal points keep the fixed order above, so the text is deterministic.
    factors = sorted((f for f in factors if f[0] > 0), key=lambda f: -f[0])
    detail = " + ".join(f"{label} ({points})" for points, label in factors) or "no risk factors"
    title = finding.get("title") or "(untitled finding)"
    return {
        "finding_id": finding.get("id"),
        "score": score,
        "band": band,
        "reason": f"{band} ({score}): {title} – {detail}",
        "weights_version": weights["version"],
        "days_open": days,
        "parts": {"severity": severity_pts, "exposure": exposure_pts, "asset": asset_pts,
                  "time_open": time_pts, "repeat": repeat_pts},
    }


def sort_key(item):
    """Score descending, then oldest ``opened_at`` first. ``item`` has score and opened_at."""
    opened = _parse_time(item.get("opened_at"))
    return (-item["score"], opened.timestamp() if opened else float("inf"))


def seat_band(scored_bands, counts, weights):
    """Floor-plan colour key for one endpoint.

    The most urgent band among its scored findings; "clear" when it has passed/failed
    results but nothing is scored (green, like Low); "unknown" (gray) when it has only
    unknown / not-applicable results or none at all.
    """
    if scored_bands:
        return band_key(min(scored_bands, key=lambda b: band_rank(b, weights)))
    if counts.get("passed") or counts.get("failed"):
        return "clear"
    return "unknown"
