"""Certificate transparency lookups: every hostname a public CA has issued a certificate for.

Cert Spotter is tried first because it is fast and paginated; crt.sh is the fallback. Both are public
logs, so nothing here touches the domain owner's systems.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

TIMEOUT_SECONDS = 45
MAX_RESPONSE_BYTES = 25 * 1024 * 1024
MAX_PAGES = 20
USER_AGENT = "domainwatch/0.1 (+https://github.com/xeroxzen/domainwatch)"

_CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
_CRTSH = "https://crt.sh/"


class CTError(RuntimeError):
    """No certificate transparency source could be read."""


@dataclass(frozen=True)
class Cert:
    names: tuple[str, ...]
    not_after: datetime


def certificates(domain: str) -> tuple[list[Cert], str]:
    """Return certificates naming the domain or its subdomains, and which log answered."""
    errors = []
    for name, fetch in (("certspotter", _from_certspotter), ("crt.sh", _from_crtsh)):
        try:
            return fetch(domain), name
        except (OSError, ValueError, CTError) as exc:
            errors.append(f"{name}: {exc}")
    raise CTError("; ".join(errors))


def _get_json(url: str) -> Any:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - fixed https hosts
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed https hosts
        body = response.read(MAX_RESPONSE_BYTES + 1)
    if len(body) > MAX_RESPONSE_BYTES:
        raise CTError(f"response larger than {MAX_RESPONSE_BYTES} bytes")
    return json.loads(body)


def _from_certspotter(domain: str) -> list[Cert]:
    certs: list[Cert] = []
    after = ""
    for _ in range(MAX_PAGES):
        query = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        if after:
            query["after"] = after
        page = _get_json(f"{_CERTSPOTTER}?{urllib.parse.urlencode(query)}")
        if not isinstance(page, list):
            raise CTError("unexpected Cert Spotter response")
        if not page:
            return certs
        certs.extend(_certspotter_cert(item) for item in page)
        after = str(page[-1]["id"])
    raise CTError(f"more than {MAX_PAGES} pages of certificates; result would be incomplete")


def _certspotter_cert(item: dict[str, Any]) -> Cert:
    return Cert(tuple(str(n) for n in item["dns_names"]), _parse_time(str(item["not_after"])))


def _from_crtsh(domain: str) -> list[Cert]:
    rows = _get_json(f"{_CRTSH}?{urllib.parse.urlencode({'q': f'%.{domain}', 'output': 'json'})}")
    if not isinstance(rows, list):
        raise CTError("unexpected crt.sh response")
    return [Cert(tuple(str(r["name_value"]).split("\n")), _parse_time(str(r["not_after"]))) for r in rows]


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
