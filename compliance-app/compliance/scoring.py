"""Compliance scoring over Wazuh SCA stateful check documents.

Input shape follows wazuh-src/docs/ref/modules/sca/output-samples.md:
each item is a stateful document with a ``check`` object (or a stateless
event with ``data.check``) whose ``result`` is one of
"passed", "failed", "not applicable", "not run" (case varies) or null.
``check.compliance`` maps framework name to control ids, e.g.
{"pci_dss": ["2.2.4"], "nist_800_53": ["CM.1"]}.

Results are classified as passed, failed, not_applicable (Wazuh reports these
as "invalid" in its scan summary) or unknown (not run, null or unrecognized).
"""

from collections.abc import Iterable, Mapping

PASSED = "passed"
FAILED = "failed"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"


def _classify_result(result):
    """Return 'passed', 'failed', 'not_applicable' or 'unknown' for a raw SCA result value."""
    if result is None:
        return UNKNOWN
    if not isinstance(result, str):
        raise TypeError(f"check.result must be a string or null, got {type(result).__name__}")
    value = " ".join(result.strip().lower().replace("_", " ").split())
    if value in (PASSED, FAILED):
        return value
    if value == "not applicable":
        return NOT_APPLICABLE
    # "not run" and any unrecognized status are unknown.
    return UNKNOWN


def _iter_checks(documents):
    """Validate the input and yield each document's ``check`` mapping."""
    if isinstance(documents, (str, bytes, Mapping)) or not isinstance(documents, Iterable):
        raise TypeError("documents must be a list of SCA check documents")

    for index, doc in enumerate(documents):
        if not isinstance(doc, Mapping):
            raise TypeError(f"document {index} must be a mapping")
        check = doc.get("check")
        if check is None and isinstance(doc.get("data"), Mapping):
            # Stateless event shape: {"collector", "module", "data": {"check": ...}}
            check = doc["data"].get("check")
        if not isinstance(check, Mapping):
            raise ValueError(f"document {index} is missing a 'check' object")
        yield check


def _frameworks(check):
    """Framework names a check is mapped to; missing or malformed metadata maps to none."""
    compliance = check.get("compliance")
    if not isinstance(compliance, Mapping):
        return []
    return [name for name, controls in compliance.items() if isinstance(name, str) and controls]


def _summarize(results):
    passed = results.count(PASSED)
    failed = results.count(FAILED)
    known = passed + failed
    return {
        "passed": passed,
        "failed": failed,
        "not_applicable": results.count(NOT_APPLICABLE),
        "unknown": results.count(UNKNOWN),
        "total": len(results),
        "pass_percentage": round(passed / known * 100, 2) if known else None,
    }


def compute_compliance_score(documents):
    """Count passed/failed/not-applicable/unknown checks and compute the pass percentage.

    pass_percentage = passed / (passed + failed) * 100, rounded to 2 decimals,
    or None when no check has a passed or failed result.
    """
    return _summarize([_classify_result(check.get("result")) for check in _iter_checks(documents)])


def compute_framework_scores(documents):
    """Score per compliance framework, keyed by framework name (sorted).

    A check mapped to several frameworks counts once in each of them; checks
    without compliance metadata appear in no framework.
    """
    by_framework = {}
    for check in _iter_checks(documents):
        result = _classify_result(check.get("result"))
        for name in set(_frameworks(check)):
            by_framework.setdefault(name, []).append(result)
    return {name: _summarize(by_framework[name]) for name in sorted(by_framework)}


def _text(value):
    return value if isinstance(value, str) else None


def list_findings(documents):
    """Per-check details for display: name, result, reason, remediation, compliance.

    ``status`` is the classified result ('passed', 'failed', 'not_applicable' or
    'unknown'); ``result`` keeps the raw SCA value. Compliance is reduced to
    {framework: [control ids]} for frameworks the check is mapped to.
    """
    findings = []
    for check in _iter_checks(documents):
        result = check.get("result")
        compliance = check.get("compliance") if isinstance(check.get("compliance"), Mapping) else {}
        findings.append({
            "id": check.get("id") if isinstance(check.get("id"), (str, int)) else None,
            "name": _text(check.get("name")),
            "status": _classify_result(result),
            "result": _text(result),
            "reason": _text(check.get("reason")),
            "remediation": _text(check.get("remediation")),
            "compliance": {
                name: [str(c) for c in compliance[name]] if isinstance(compliance[name], list)
                else [str(compliance[name])]
                for name in _frameworks(check)
            },
        })
    return findings
