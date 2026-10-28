"""Outbound network allowlist: the app may only talk to this machine and the isolated lab subnet.

Allowed hosts: 127.0.0.1, localhost, and IP addresses inside 10.20.0.0/24. Other host
names are refused without being resolved (DNS could point anywhere).
"""

import ipaddress
from urllib.parse import urlsplit

LAB_NETWORK = ipaddress.ip_network("10.20.0.0/24")
LOOPBACK_NAMES = ("localhost",)
LOOPBACK_ADDRESS = ipaddress.ip_address("127.0.0.1")


class NetworkPolicyError(ValueError):
    """A URL points outside the allowed lab network; the message is safe to show."""


def host_allowed(host):
    if not isinstance(host, str) or not host:
        return False
    host = host.strip().lower().rstrip(".")
    if host in LOOPBACK_NAMES:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address == LOOPBACK_ADDRESS or address in LAB_NETWORK


def check_url(url, schemes, setting):
    """Return the parsed URL if it is allowed, else raise ``NetworkPolicyError`` naming ``setting``."""
    try:
        parts = urlsplit(url.strip()) if isinstance(url, str) else None
        port = parts.port if parts else None  # noqa: F841 - raises ValueError on a bad port
    except ValueError:
        parts = None
    if parts is None or parts.scheme not in schemes or not parts.hostname:
        raise NetworkPolicyError(f"{setting} must be a {' or '.join(s + '://' for s in schemes)} URL.")
    if parts.username or parts.password:
        raise NetworkPolicyError(f"{setting} must not contain a user name or password.")
    if not host_allowed(parts.hostname):
        raise NetworkPolicyError(f"{setting} host '{parts.hostname}' is not allowed. Use 127.0.0.1, localhost "
                                 f"or an address in {LAB_NETWORK} (the offline lab network).")
    return parts
