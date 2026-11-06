# Security policy

## Reporting a vulnerability in domainwatch

domainwatch parses responses from certificate logs and DNS answers it doesn't control. Examples worth reporting: a response that makes it connect to a target host, bypasses the size or page limits, hangs it, or makes a dangerous finding disappear. Report it privately:

- Use [GitHub private vulnerability reporting](https://github.com/xeroxzen/domainwatch/security/advisories/new), or
- Email andilembele020@gmail.com with the subject `domainwatch security`.

Include the version and steps to reproduce, using `example.com` and the RFC 5737 address ranges where you can. You'll get an acknowledgement within 3 working days.

Findings about other people's domains are not vulnerabilities in domainwatch. Report those to the domain owner.

## Supported versions

Only the latest release receives fixes.
