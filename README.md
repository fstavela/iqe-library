# iqe-library

Shared Python utilities for testing Red Hat Insights services, usable independently
without the IQE test framework.

## Development

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/) 0.12.1+.

```bash
uv sync --python 3.12 --all-extras
uv run pre-commit install
uv run pre-commit run --all-files
uv build
```

The checkout is installed in editable mode. Pre-commit runs Ruff, strict mypy,
and basic file checks.

To use the checkout in another uv project:

```bash
uv add --dev --editable '/path/to/iqe-library'
```

The base package has no runtime dependencies.

Licensed under [GPLv3](LICENSE).
