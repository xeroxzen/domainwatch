"""Build a hostname inventory from certificate transparency and flag what needs attention."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from domainwatch.ct import Cert
from domainwatch.dnscheck import Lookup, Resolution, resolve_host, run_all

MAX_NAMES = 2_000
EXPIRY_WARNING = timedelta(days=21)

Code = Literal["DANGLING_CNAME", "CERT_EXPIRED_LIVE", "CERT_EXPIRING"]
SEVERITY: dict[Code, str] = {"DANGLING_CNAME": "high", "CERT_EXPIRED_LIVE": "medium", "CERT_EXPIRING": "low"}
MEANING: dict[Code, str] = {
    "DANGLING_CNAME": "Points to a name that no longer exists. If the target can be claimed at its provider, "
    "someone else could serve content on this hostname. Remove the record or reclaim the target.",
    "CERT_EXPIRED_LIVE": "Still in DNS, but every public certificate for it has expired. "
    "Often a forgotten system. Confirm an owner, then renew or decommission it.",
    "CERT_EXPIRING": "Its newest public certificate expires within 21 days and no renewal is logged yet.",
}


@dataclass(frozen=True)
class Host:
    name: str
    expires: datetime
    resolution: Resolution
    finding: Code | None


@dataclass(frozen=True)
class Surface:
    domain: str
    source: str
    hosts: tuple[Host, ...]
    wildcards: tuple[str, ...]
    skipped: int


def latest_expiry(domain: str, certs: Iterable[Cert]) -> tuple[dict[str, datetime], dict[str, datetime]]:
    """Map each in-scope hostname, and each wildcard base, to its newest certificate expiry."""
    names: dict[str, datetime] = {}
    wildcards: dict[str, datetime] = {}
    for cert in certs:
        for raw in cert.names:
            name = raw.strip().rstrip(".").lower()
            target = wildcards if name.startswith("*.") else names
            name = name.removeprefix("*.")
            if name != domain and not name.endswith("." + domain):
                continue
            if cert.not_after > target.get(name, datetime.min.replace(tzinfo=cert.not_after.tzinfo)):
                target[name] = cert.not_after
    return names, wildcards


def classify(resolution: Resolution, expires: datetime, now: datetime) -> Code | None:
    if resolution.status == "nxdomain" and resolution.cname:
        return "DANGLING_CNAME"
    if resolution.status != "resolves":
        return None
    if expires < now:
        return "CERT_EXPIRED_LIVE"
    if expires - now < EXPIRY_WARNING:
        return "CERT_EXPIRING"
    return None


def _effective_expiry(name: str, own: datetime, wildcards: dict[str, datetime]) -> datetime:
    parent = name.split(".", 1)[1] if "." in name else ""
    covering = wildcards.get(parent)
    return max(own, covering) if covering else own


def build(domain: str, certs: list[Cert], source: str, lookup: Lookup, now: datetime) -> Surface:
    names, wildcards = latest_expiry(domain, certs)
    ordered = sorted(names)
    skipped = max(0, len(ordered) - MAX_NAMES)
    ordered = ordered[:MAX_NAMES]
    resolutions = run_all(lambda n: resolve_host(lookup, n), ordered)
    hosts = []
    for name, resolution in zip(ordered, resolutions, strict=True):
        expires = _effective_expiry(name, names[name], wildcards)
        hosts.append(Host(name, expires, resolution, classify(resolution, expires, now)))
    return Surface(domain, source, tuple(hosts), tuple(sorted(wildcards)), skipped)
