"""Ordinary public DNS lookups. Queries go to the configured recursive resolver, never to the hosts."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Literal, Protocol, TypeVar

import dns.exception
import dns.resolver

TIMEOUT_SECONDS = 3.0
MAX_WORKERS = 16

Status = Literal["resolves", "nxdomain", "no-address", "error"]
T = TypeVar("T")
R = TypeVar("R")


@dataclass(frozen=True)
class Resolution:
    name: str
    status: Status
    cname: str = ""
    addresses: tuple[str, ...] = ()


@dataclass(frozen=True)
class Registration:
    domain: str
    registered: bool
    nameservers: tuple[str, ...] = ()
    mx: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    errors: tuple[str, ...] = field(default=())


class Lookup(Protocol):
    def records(self, name: str, rdtype: str) -> tuple[str, ...]:
        """Return record values, () when the name exists without that type. Raise NXDOMAIN or DNSException."""


class DnsLookup:
    def __init__(self) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.lifetime = TIMEOUT_SECONDS

    def records(self, name: str, rdtype: str) -> tuple[str, ...]:
        try:
            answer = self._resolver.resolve(name, rdtype, search=False)
        except dns.resolver.NoAnswer:
            return ()
        return tuple(str(r).rstrip(".").lower() for r in answer)


def resolve_host(lookup: Lookup, name: str) -> Resolution:
    try:
        cname = lookup.records(name, "CNAME")
        addresses = lookup.records(name, "A") + lookup.records(name, "AAAA")
    except dns.resolver.NXDOMAIN:
        return Resolution(name, "nxdomain", cname=_cname_of(lookup, name))
    except dns.exception.DNSException:
        return Resolution(name, "error")
    target = cname[0] if cname else ""
    return Resolution(name, "resolves" if addresses else "no-address", target, addresses)


def _cname_of(lookup: Lookup, name: str) -> str:
    """A dangling CNAME makes the name itself answer NXDOMAIN for A; ask for the CNAME alone."""
    try:
        found = lookup.records(name, "CNAME")
    except dns.exception.DNSException:
        return ""
    return found[0] if found else ""


def check_registration(lookup: Lookup, domain: str) -> Registration:
    try:
        nameservers = lookup.records(domain, "NS")
    except dns.resolver.NXDOMAIN:
        return Registration(domain, registered=False)
    except dns.exception.DNSException as exc:
        return Registration(domain, registered=False, errors=(f"NS: {type(exc).__name__}",))
    mx, mx_err = _safe(lookup, domain, "MX")
    addresses, a_err = _safe(lookup, domain, "A")
    errors = tuple(e for e in (mx_err, a_err) if e)
    return Registration(domain, True, nameservers, mx, addresses, errors)


def _safe(lookup: Lookup, name: str, rdtype: str) -> tuple[tuple[str, ...], str]:
    try:
        return lookup.records(name, rdtype), ""
    except dns.exception.DNSException as exc:
        return (), f"{rdtype}: {type(exc).__name__}"


def run_all(func: Callable[[T], R], items: Iterable[T]) -> list[R]:
    """Run lookups concurrently with a fixed worker cap, preserving input order."""
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        return list(pool.map(func, items))
