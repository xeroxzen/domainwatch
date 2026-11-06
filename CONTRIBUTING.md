# Contributing

Thanks for helping. Bug reports, new lookalike techniques, suffixes for other regions, and documentation fixes are all welcome.

## Set up

```bash
git clone https://github.com/xeroxzen/domainwatch.git
cd domainwatch
uv sync
```

## Rules for changes

- Keep it passive. domainwatch must never connect to the hosts it reports on. Changes that add active probing won't be accepted.
- Tests run offline. Use `tests/fakes.py` for DNS and build certificates in the test, with `example.com` names and RFC 5737 addresses. Don't commit real organisations' results.

## Before you open a pull request

All of these must pass with no warnings:

```bash
uv run pytest
uv run mypy src tests
uv run ruff check .
uv run ruff format --check .
```

Also:

- Add a test that fails without your change.
- Record the change in the [changelog](CHANGELOG.md).
