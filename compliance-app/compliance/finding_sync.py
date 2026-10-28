"""Pure status transitions applied when a new assessment result arrives for a finding.

States (what the latest result says): compliant | non_compliant | not_applicable | unknown.
Statuses (where the finding is in its life):
    open, in_review, exception, fixed_pending   set by people (only open is set by sync)
    cleared    the check passed again before anyone marked it fixed (e.g. Group Policy restored it)
    verified   it was marked fixed_pending and a LATER assessment passed

Rules:
    failed  -> state non_compliant; a cleared/verified finding reopens (status open,
               times_reopened + 1, opened_at reset to the new failure, verified_at cleared)
    passed  -> state compliant; open/in_review -> cleared; fixed_pending -> verified only if
               the passing assessment is newer than the moment it was marked fixed_pending
    not_applicable / unknown -> state only; the status is left alone
A missing finding is created only for failed (open) and unknown (open, "Needs data") results.
"""

from datetime import datetime, timezone

RESULT_TO_STATE = {"passed": "compliant", "failed": "non_compliant",
                   "not_applicable": "not_applicable", "unknown": "unknown"}
STATUSES = ("open", "in_review", "exception", "fixed_pending", "cleared", "verified")


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def transition(existing, result, observed_at, now):
    """Fields to write for one finding, or None when nothing needs storing.

    ``existing``: current row (state, status, times_reopened, verified_at, status_changed_at)
    or None. ``result``: passed | failed | not_applicable | unknown. ``observed_at``: time of
    the assessment (may be None), never later than ``now``. Returned keys are a subset of
    state, status, times_reopened, opened_at, verified_at, status_changed_at.
    """
    if result not in RESULT_TO_STATE:
        raise ValueError(f"unknown result {result!r}")
    observed = _parse(observed_at)
    observed = min(observed, now) if observed else now
    state = RESULT_TO_STATE[result]

    if existing is None:
        if result not in ("failed", "unknown"):
            return None
        return {"state": state, "status": "open", "times_reopened": 0, "opened_at": _iso(observed),
                "verified_at": None, "status_changed_at": _iso(now)}

    status = existing["status"]
    changes = {"state": state}
    if result == "failed" and status in ("cleared", "verified"):
        changes.update(status="open", times_reopened=(existing.get("times_reopened") or 0) + 1,
                       opened_at=_iso(observed), verified_at=None, status_changed_at=_iso(now))
    elif result == "passed" and status in ("open", "in_review"):
        changes.update(status="cleared", status_changed_at=_iso(now))
    elif result == "passed" and status == "fixed_pending":
        marked = _parse(existing.get("status_changed_at"))
        if marked is None or observed > marked:
            changes.update(status="verified", verified_at=_iso(observed), status_changed_at=_iso(now))
    return changes
