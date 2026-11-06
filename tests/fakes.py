"""An in-memory DNS for tests. Names absent from the table answer NXDOMAIN."""

from __future__ import annotations

import dns.exception
import dns.resolver


class FakeLookup:
    def __init__(
        self, table: dict[tuple[str, str], tuple[str, ...]], broken: frozenset[str] = frozenset()
    ) -> None:
        self.table = table
        self.broken = broken
        self.names = {name for name, _ in table}

    def records(self, name: str, rdtype: str) -> tuple[str, ...]:
        if name in self.broken:
            raise dns.exception.Timeout
        if name not in self.names:
            raise dns.resolver.NXDOMAIN
        cname = self.table.get((name, "CNAME"), ())
        if rdtype in ("A", "AAAA") and cname:
            return self.records(cname[0], rdtype)
        return self.table.get((name, rdtype), ())
