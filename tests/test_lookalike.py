from __future__ import annotations

import pytest
from fakes import FakeLookup

from domainwatch.lookalike import candidates, find, split_domain


@pytest.mark.parametrize(
    ("domain", "expected"),
    [("example.com", ("example", "com")), ("bank.co.zw", ("bank", "co.zw")), ("a.b.co.za", ("a.b", "co.za"))],
)
def test_split_domain(domain: str, expected: tuple[str, str]) -> None:
    assert split_domain(domain) == expected


def test_split_rejects_bare_label() -> None:
    with pytest.raises(ValueError, match="not a registrable"):
        split_domain("localhost")


def test_candidates_cover_each_kind_and_exclude_the_original() -> None:
    found = dict(candidates("bank.co.zw"))
    assert found["bnk.co.zw"] == "omission"
    assert found["baank.co.zw"] == "repetition"
    assert found["bnak.co.zw"] == "transposition"
    assert found["vank.co.zw"] == "keyboard typo"
    assert found["6ank.co.zw"] == "homoglyph"
    assert found["b-ank.co.zw"] == "hyphenation"
    assert found["bank-login.co.zw"] == "added word"
    assert found["bank.com"] == "other suffix"
    assert "bank.co.zw" not in found
    assert not any(d.startswith("-") or ".-" in d or "-." in d for d in found)


def test_find_ranks_mail_first_and_reports_unchecked() -> None:
    dns = FakeLookup(
        {
            ("bank.com", "NS"): ("ns1.example.net",),
            ("bank.com", "A"): ("192.0.2.9",),
            ("bank-login.co.zw", "NS"): ("ns1.example.net",),
            ("bank-login.co.zw", "MX"): ("mx.example.net",),
            ("bnk.co.zw", "NS"): ("ns1.example.net",),
        },
        broken=frozenset({"bank.net"}),
    )
    found, unchecked = find("bank.co.zw", dns)
    assert [(x.domain, x.risk) for x in found] == [
        ("bank-login.co.zw", "mail"),
        ("bank.com", "web"),
        ("bnk.co.zw", "parked"),
    ]
    assert unchecked == ["bank.net"]
