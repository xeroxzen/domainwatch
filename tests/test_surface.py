from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fakes import FakeLookup

from domainwatch.ct import Cert
from domainwatch.surface import build, latest_expiry

NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


def _cert(*names: str, days: int) -> Cert:
    return Cert(names, NOW + timedelta(days=days))


DNS = FakeLookup(
    {
        ("www.example.com", "A"): ("192.0.2.1",),
        ("old.example.com", "A"): ("192.0.2.2",),
        ("soon.eu.example.com", "A"): ("192.0.2.3",),
        ("shop.example.com", "CNAME"): ("gone-store.example.net",),
        ("app.example.com", "CNAME"): ("app.example.net",),
        ("app.example.net", "A"): ("192.0.2.4",),
        ("covered.example.com", "A"): ("192.0.2.5",),
    }
)


def test_latest_expiry_keeps_newest_and_drops_other_domains() -> None:
    names, wildcards = latest_expiry(
        "example.com",
        [
            _cert("www.example.com", days=-10),
            _cert("WWW.example.com.", "evil.com", days=50),
            _cert("*.example.com", days=5),
        ],
    )
    assert names == {"www.example.com": NOW + timedelta(days=50)}
    assert wildcards == {"example.com": NOW + timedelta(days=5)}


def test_findings() -> None:
    certs = [
        _cert("www.example.com", "app.example.com", days=60),
        _cert("old.example.com", days=-30),
        _cert("soon.eu.example.com", days=7),
        _cert("shop.example.com", days=-200),
        _cert("retired.example.com", days=-400),
        _cert("covered.example.com", days=-5),
        _cert("*.example.com", days=80),
    ]
    surface = build("example.com", certs, "test", DNS, NOW)
    findings = {h.name: h.finding for h in surface.hosts}
    assert findings == {
        "app.example.com": None,
        "covered.example.com": None,
        "old.example.com": None,
        "retired.example.com": None,
        "shop.example.com": "DANGLING_CNAME",
        "soon.eu.example.com": "CERT_EXPIRING",
        "www.example.com": None,
    }


def test_expired_live_without_wildcard() -> None:
    surface = build("example.com", [_cert("old.example.com", days=-30)], "test", DNS, NOW)
    assert [h.finding for h in surface.hosts] == ["CERT_EXPIRED_LIVE"]


def test_unreachable_resolver_is_not_a_finding() -> None:
    broken = FakeLookup({}, broken=frozenset({"www.example.com"}))
    surface = build("example.com", [_cert("www.example.com", days=-30)], "test", broken, NOW)
    assert surface.hosts[0].resolution.status == "error"
    assert surface.hosts[0].finding is None
