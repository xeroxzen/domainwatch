"""domainwatch: what can an attacker see of your domain?

Passive only. Reads public certificate transparency logs and makes ordinary DNS lookups; it never
connects to the domain's servers.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from datetime import datetime, timezone

from domainwatch.ct import CTError, certificates
from domainwatch.dnscheck import DnsLookup
from domainwatch.lookalike import Lookalike, find, split_domain
from domainwatch.surface import MEANING, SEVERITY, Surface, build

SHOWN = 25

RISK_TEXT = {
    "mail": "has mail servers: can send and receive email under this name",
    "web": "has a website address",
    "parked": "registered, no mail or website yet",
}


def _render_surface(s: Surface) -> str:
    flagged = [h for h in s.hosts if h.finding]
    live = sum(1 for h in s.hosts if h.resolution.status == "resolves")
    lines = [
        f"{s.domain}: {len(s.hosts)} hostnames in public certificates ({s.source}), {live} resolve today, "
        f"{len(flagged)} need attention.",
    ]
    if s.wildcards:
        lines.append(
            f"  Wildcard certificates cover: {', '.join(s.wildcards)} (names under these can't be listed)."
        )
    if s.skipped:
        lines.append(
            f"  {s.skipped} further hostnames were not checked (limit reached); use a narrower domain."
        )
    rank = ["high", "medium", "low"]
    for code, h in sorted(
        ((h.finding, h) for h in flagged if h.finding), key=lambda p: (rank.index(SEVERITY[p[0]]), p[1].name)
    ):
        target = f" -> {h.resolution.cname}" if h.resolution.cname else ""
        lines.append(f"  [{SEVERITY[code]}] {code}: {h.name}{target} (cert expires {h.expires:%Y-%m-%d})")
        lines.append(f"      {MEANING[code]}")
    return "\n".join(lines)


def _surface_json(s: Surface) -> str:
    hosts = [
        {
            "name": h.name,
            "status": h.resolution.status,
            "cname": h.resolution.cname,
            "addresses": list(h.resolution.addresses),
            "cert_expires": h.expires.isoformat(),
            "finding": h.finding,
        }
        for h in s.hosts
    ]
    return json.dumps(
        {
            "domain": s.domain,
            "source": s.source,
            "wildcards": list(s.wildcards),
            "skipped": s.skipped,
            "hosts": hosts,
        }
    )


def _render_lookalikes(domain: str, found: list[Lookalike], unchecked: list[str]) -> str:
    lines = [f"{domain}: {len(found)} registered lookalike domains."]
    for item in found[:SHOWN]:
        lines.append(f"  [{item.risk}] {item.domain} ({item.kind}): {RISK_TEXT[item.risk]}")
    if len(found) > SHOWN:
        lines.append(f"  ... and {len(found) - SHOWN} more (use --json for all)")
    if found:
        lines.append("  Some may be registered by you or a partner. Check ownership before acting.")
    if unchecked:
        lines.append(
            f"  {len(unchecked)} candidates could not be checked (DNS errors); run again to retry them."
        )
    return "\n".join(lines)


def _lookalikes_json(domain: str, found: list[Lookalike], unchecked: list[str]) -> str:
    rows = [
        {
            "domain": x.domain,
            "kind": x.kind,
            "risk": x.risk,
            "mx": list(x.registration.mx),
            "addresses": list(x.registration.addresses),
            "nameservers": list(x.registration.nameservers),
        }
        for x in found
    ]
    return json.dumps({"domain": domain, "lookalikes": rows, "unchecked": unchecked})


def _surface(domain: str, as_json: bool) -> int:
    try:
        certs, source = certificates(domain)
    except CTError as exc:
        print(f"{domain}: certificate logs unavailable: {exc}", file=sys.stderr)
        return 2
    result = build(domain, certs, source, DnsLookup(), datetime.now(timezone.utc))
    print(_surface_json(result) if as_json else _render_surface(result))
    return 1 if any(h.finding for h in result.hosts) else 0


def _lookalikes(domain: str, as_json: bool) -> int:
    found, unchecked = find(domain, DnsLookup())
    print(
        _lookalikes_json(domain, found, unchecked)
        if as_json
        else _render_lookalikes(domain, found, unchecked)
    )
    if unchecked:
        return 2
    return 1 if any(x.risk != "parked" for x in found) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="domainwatch", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("command", choices=["surface", "lookalikes"])
    parser.add_argument("domain")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)
    domain = args.domain.lower().strip().rstrip(".")
    try:
        split_domain(domain)
    except ValueError as exc:
        print(f"domainwatch: {exc}", file=sys.stderr)
        return 2
    command: Callable[[str, bool], int] = _surface if args.command == "surface" else _lookalikes
    return command(domain, args.json)
