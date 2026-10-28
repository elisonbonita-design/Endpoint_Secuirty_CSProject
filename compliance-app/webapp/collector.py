"""Validation of BitLocker status reports sent by collector/Send-BitLockerStatus.ps1.

Only these status fields are accepted (the same names Get-BitLockerVolume uses, in
snake_case). Anything that looks like a recovery key, recovery password or key
protector makes the whole report fail and nothing is stored.
"""

import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

VOLUME_FIELDS = {
    "mount_point": None,
    "volume_type": ("OperatingSystem", "Data"),
    "volume_status": ("FullyDecrypted", "FullyEncrypted", "EncryptionInProgress", "DecryptionInProgress",
                      "EncryptionPaused", "DecryptionPaused"),
    "protection_status": ("On", "Off", "Unknown"),
    "encryption_percentage": None,
    "encryption_method": ("None", "Aes128", "Aes256", "Aes128Diffuser", "Aes256Diffuser", "Hardware",
                          "XtsAes128", "XtsAes256"),
    "lock_status": ("Locked", "Unlocked"),
}
REPORT_FIELDS = ("hostname", "collected_at", "volumes")
FORBIDDEN = re.compile(r"key|protector|recovery|password|secret", re.I)
HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
MOUNT_POINT = re.compile(r"^(?:[A-Za-z]:\\?|\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}\\)$")
MAX_VOLUMES = 26


class ReportRejected(ValueError):
    """The message is safe to return to the collector."""


def _walk_keys(value):
    if isinstance(value, Mapping):
        for k, v in value.items():
            yield str(k)
            yield from _walk_keys(v)
    elif isinstance(value, list):
        for v in value:
            yield from _walk_keys(v)


def parse_report(body, now):
    """Return (hostname, collected_at ISO, [volume dicts]) or raise ``ReportRejected``."""
    if not isinstance(body, Mapping):
        raise ReportRejected("Send the report as a JSON object.")
    if any(FORBIDDEN.search(k) for k in _walk_keys(body)):
        raise ReportRejected("Recovery keys, passwords and key protectors must never be sent. Nothing was stored.")
    extra = set(body) - set(REPORT_FIELDS)
    if extra:
        raise ReportRejected(f"Unexpected field(s): {', '.join(sorted(extra))}.")
    hostname = body.get("hostname")
    if not isinstance(hostname, str) or not HOSTNAME.fullmatch(hostname):
        raise ReportRejected("hostname is not valid.")
    try:
        collected = datetime.fromisoformat(str(body.get("collected_at")).replace("Z", "+00:00"))
    except ValueError:
        raise ReportRejected("collected_at must be an ISO 8601 time.") from None
    if collected.tzinfo is None:
        raise ReportRejected("collected_at must include a time zone.")
    if collected - now > timedelta(minutes=5):
        raise ReportRejected("collected_at is in the future.")
    volumes = body.get("volumes")
    if not isinstance(volumes, list) or not 1 <= len(volumes) <= MAX_VOLUMES:
        raise ReportRejected(f"volumes must be a list of 1 to {MAX_VOLUMES} volumes.")
    cleaned = []
    for v in volumes:
        if not isinstance(v, Mapping) or set(v) - set(VOLUME_FIELDS):
            raise ReportRejected(f"Each volume may only contain: {', '.join(VOLUME_FIELDS)}.")
        if not isinstance(v.get("mount_point"), str) or not MOUNT_POINT.fullmatch(v["mount_point"]):
            raise ReportRejected("mount_point is not valid.")
        item = {"mount_point": v["mount_point"]}
        for field, allowed in VOLUME_FIELDS.items():
            if field == "mount_point" or v.get(field) is None:
                continue
            value = v[field]
            if field == "encryption_percentage":
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 100:
                    raise ReportRejected("encryption_percentage must be 0 to 100.")
                value = float(value)
            elif value not in allowed:
                raise ReportRejected(f"{field} must be one of: {', '.join(allowed)}.")
            item[field] = value
        cleaned.append(item)
    return hostname, collected.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), cleaned
