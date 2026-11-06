# domainwatch

**What can an attacker see of your domain?**

Before anyone attacks an organisation, they look it up. Every TLS certificate a public CA issues is written to a public certificate transparency log, so the names of your test servers, VPN portals and forgotten marketing sites are already listed for anyone who asks. Registering `yourbank-login.com` costs a few dollars and needs no permission from you. domainwatch shows you both views, from the outside, the same way an attacker would see them.

```console
$ domainwatch surface example.com
example.com: 41 hostnames in public certificates (certspotter), 33 resolve today, 3 need attention.
  Wildcard certificates cover: example.com (names under these can't be listed).
  [high] DANGLING_CNAME: shop.example.com -> example-store.shops.example.net (cert expires 2025-03-02)
      Points to a name that no longer exists. If the target can be claimed at its provider, someone else could serve content on this hostname. Remove the record or reclaim the target.
  [medium] CERT_EXPIRED_LIVE: vpn-old.example.com (cert expires 2024-08-19)
      Still in DNS, but every public certificate for it has expired. Often a forgotten system. Confirm an owner, then renew or decommission it.
  [low] CERT_EXPIRING: portal.example.com (cert expires 2026-11-20)
      Its newest public certificate expires within 21 days and no renewal is logged yet.

$ domainwatch lookalikes example.co.zw
example.co.zw: 3 registered lookalike domains.
  [mail] example-login.co.zw (added word): has mail servers: can send and receive email under this name
  [web] examp1e.co.zw (homoglyph): has a website address
  [parked] example.com (other suffix): registered, no mail or website yet
  Some may be registered by you or a partner. Check ownership before acting.
```

## Passive by design

domainwatch never connects to the domain's servers. It reads public certificate transparency logs ([Cert Spotter](https://sslmate.com/certspotter/), with [crt.sh](https://crt.sh) as a fallback) and makes ordinary DNS queries through your configured resolver. That makes it safe to run on any domain, but only act on what it finds for domains you own or are authorised to assess.

## Install

```bash
uv tool install git+https://github.com/xeroxzen/domainwatch
```

Requires Python 3.10 or later.

## Get started

1. Run `domainwatch surface yourdomain.com`. Read the hostname count first: most organisations find names they had forgotten.
2. Fix every `high` finding the same day. A dangling CNAME can let someone else publish a site, or receive cookies, under your name.
3. Run `domainwatch lookalikes yourdomain.com`. Start with the `mail` entries: a lookalike that can send email is the one most likely to be used for invoice fraud or credential phishing.
4. For each lookalike you don't own, decide whether to report it to the registrar, register defensive variants yourself, or add it to your mail filter's block list.
5. Run both weekly, or from a scheduled job using the exit codes below.

## What surface reports

Each hostname found in certificate logs is resolved and compared with its newest certificate. A wildcard certificate one level up counts as cover.

| Code | Severity | What it means |
|---|---|---|
| `DANGLING_CNAME` | high | The name is an alias for a target that no longer exists. If the target can be re-registered at its provider (a storage bucket, an app host, a SaaS subdomain), someone else can serve content on your hostname. |
| `CERT_EXPIRED_LIVE` | medium | The name still resolves, but every certificate for it has expired. Usually an unowned system nobody is patching. |
| `CERT_EXPIRING` | low | The newest certificate expires within 21 days and no renewal has been logged. |

Names that no longer resolve and have no alias are history, not findings, and are counted but not flagged. Names covered only by a wildcard certificate (`*.example.com`) can't be listed from logs.

## What lookalikes checks

For the name part of the domain, domainwatch generates the variants phishing campaigns use most: dropped, doubled and swapped letters; neighbouring-key typos; look-alike characters such as `1` for `l` and `rn` for `m`; hyphens; attached words such as `-login` and `-secure`; and the same name under common suffixes including `.co.zw` and `.co.za`. It checks each candidate's nameservers, mail servers and address records, and ranks registered ones:

| Risk | What it means |
|---|---|
| `mail` | Has mail servers. It can send email that looks like yours and receive replies to it. |
| `web` | Has a website address. Can host a login page. |
| `parked` | Registered, but nothing set up yet. Worth watching: domains are often registered weeks before use. |

Some lookalikes will belong to you, a partner or a domain investor. Check ownership before you act on any of them.

## Command-line reference

```
domainwatch {surface,lookalikes} DOMAIN [--json]
```

| Option | Effect |
|---|---|
| `--json` | Print the full result as JSON for scripts and dashboards. Text output shows the first 25 lookalikes; JSON includes all of them. |

| Exit code | `surface` | `lookalikes` |
|---|---|---|
| 0 | Nothing needs attention. | No lookalike with mail or a website. |
| 1 | At least one finding. | At least one `mail` or `web` lookalike. |
| 2 | Certificate logs unavailable, or invalid domain. | Some candidates could not be checked, or invalid domain. Run again. |

## Limits

- Certificate logs list names that have had a public certificate. Internal names, names behind wildcard certificates, and services without TLS won't appear.
- Up to 2,000 hostnames are checked per run; larger estates should run per subdomain.
- Lookalike generation covers common variants, not every possible one, and doesn't include internationalised (Unicode) domain names.
- DNS answers can differ by resolver and change at any time. Confirm a finding before reporting it.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability in domainwatch itself, follow [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
