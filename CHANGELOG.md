# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Finding codes, risk levels, exit codes and JSON field names are part of the public interface: renaming or removing one is a breaking change.

## [0.1.0] - 2026-11-06

### Added

- `surface`: hostname inventory from certificate transparency (Cert Spotter, falling back to crt.sh), with `DANGLING_CNAME`, `CERT_EXPIRED_LIVE` and `CERT_EXPIRING` findings. Wildcard certificates count as cover.
- `lookalikes`: omission, repetition, transposition, keyboard-typo, homoglyph, hyphenation, added-word and other-suffix variants, ranked `mail`, `web` or `parked` by their DNS records.
- Text and JSON output, and exit codes for scheduled runs.
- Passive only: no connections to the domains being checked.

[0.1.0]: https://github.com/xeroxzen/domainwatch/releases/tag/v0.1.0
