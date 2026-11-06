"""Generate lookalike domains and check which are registered.

Covers the variants phishing campaigns use most: typos, swapped and doubled letters, look-alike
characters, hyphens, attached words such as "-login", and the same name under other suffixes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from domainwatch.dnscheck import Lookup, Registration, check_registration, run_all

MAX_CANDIDATES = 3_000

SUFFIXES = ("com", "net", "org", "co", "info", "online", "africa", "co.zw", "org.zw", "co.za", "com.zw")
WORDS = ("login", "secure", "online", "bank", "mail", "support", "portal", "verify", "pay", "app")
HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "o": ("0",),
    "0": ("o",),
    "l": ("1", "i"),
    "i": ("1", "l"),
    "1": ("l", "i"),
    "e": ("3",),
    "a": ("4",),
    "s": ("5",),
    "m": ("rn",),
    "w": ("vv",),
    "b": ("6",),
    "g": ("9", "q"),
}
KEYBOARD = {
    "q": "wa",
    "w": "qes",
    "e": "wrd",
    "r": "etf",
    "t": "ryg",
    "y": "tuh",
    "u": "yij",
    "i": "uok",
    "o": "ipl",
    "p": "o",
    "a": "qsz",
    "s": "awdz",
    "d": "sefx",
    "f": "drgc",
    "g": "fthv",
    "h": "gyjb",
    "j": "hukn",
    "k": "jilm",
    "l": "ko",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "njk",
}

Risk = Literal["mail", "web", "parked"]


@dataclass(frozen=True)
class Lookalike:
    domain: str
    kind: str
    registration: Registration

    @property
    def risk(self) -> Risk:
        if self.registration.mx:
            return "mail"
        return "web" if self.registration.addresses else "parked"


def split_domain(domain: str) -> tuple[str, str]:
    """Split into the name and its suffix, treating two-part country suffixes like co.zw as one."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        raise ValueError(f"{domain!r} is not a registrable domain")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SUFFIXES:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def _label_variants(label: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for i in range(len(label)):
        out.setdefault(label[:i] + label[i + 1 :], "omission")
        out.setdefault(label[:i] + label[i] + label[i:], "repetition")
        if i + 1 < len(label):
            out.setdefault(label[:i] + label[i + 1] + label[i] + label[i + 2 :], "transposition")
        for ch in KEYBOARD.get(label[i], ""):
            out.setdefault(label[:i] + ch + label[i + 1 :], "keyboard typo")
        for glyph in HOMOGLYPHS.get(label[i], ()):
            out.setdefault(label[:i] + glyph + label[i + 1 :], "homoglyph")
        if i > 0:
            out.setdefault(label[:i] + "-" + label[i:], "hyphenation")
    for word in WORDS:
        out.setdefault(f"{label}-{word}", "added word")
        out.setdefault(f"{label}{word}", "added word")
    return out


def candidates(domain: str) -> list[tuple[str, str]]:
    label, suffix = split_domain(domain)
    found: dict[str, str] = {}
    for variant, kind in _label_variants(label).items():
        if variant and variant != label and not variant.startswith("-") and not variant.endswith("-"):
            found.setdefault(f"{variant}.{suffix}", kind)
    for other in SUFFIXES:
        if other != suffix:
            found.setdefault(f"{label}.{other}", "other suffix")
    found.pop(domain.lower(), None)
    if len(found) > MAX_CANDIDATES:
        raise ValueError(f"{len(found)} candidates exceed the limit of {MAX_CANDIDATES}")
    return sorted(found.items())


def find(domain: str, lookup: Lookup) -> tuple[list[Lookalike], list[str]]:
    """Return registered lookalikes, most dangerous first, and the candidates that could not be checked."""
    pairs = candidates(domain)
    results = run_all(lambda pair: check_registration(lookup, pair[0]), pairs)
    found = [Lookalike(d, kind, reg) for (d, kind), reg in zip(pairs, results, strict=True) if reg.registered]
    unchecked = [reg.domain for reg in results if not reg.registered and reg.errors]
    order = {"mail": 0, "web": 1, "parked": 2}
    return sorted(found, key=lambda x: (order[x.risk], x.domain)), unchecked
