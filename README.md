# iqe-library

Shared Python utilities for testing Red Hat Insights services, usable independently
without the IQE test framework.

## Development

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/) 0.12.1+.

```bash
uv sync --python 3.12 --all-extras
uv run pre-commit install
uv run --locked --all-extras pytest -q
uv run pre-commit run --all-files
uv build
```

The checkout is installed in editable mode. Pre-commit runs Ruff, strict mypy,
and basic file checks; tests are offline and need no service credentials.
Use `uv run --all-extras pytest tests/test_config.py -q` to run one module.

To use the checkout in another uv project:

```bash
uv add --dev --editable '/path/to/iqe-library[config,vault]'
```

The base package has no runtime dependencies. Select only the extras you need:
`config`, `vault`, and `kerberos`.

## Configuration

Requires `config`. Load shared Stage/prod defaults with an optional consumer YAML
file. Consumer values override shared defaults; `.local.yaml` companions and
`DYNACONF_*` environment variables provide further overrides.

```yaml
# consumer.yaml
default:
  base_url: https://service.example.com
  username: '@jinja {{ env.DEMO_USERNAME }}'
```

```python
from iqe_library.config import load_config

settings = load_config("consumer.yaml", environment="stage")
print(settings.base_url)
```

The environment defaults to `ENV_FOR_DYNACONF`, then `stage`.
For example, `DYNACONF_VAULT__TIMEOUT=20` overrides a nested setting.
Jinja templates and `!from_vault {path: users/demo, key: password}` references
resolve only when accessed; Vault references also require the `vault` extra.

## Vault secrets

Requires `vault`. Read KV v2 secrets directly or through configuration references.
Successful reads are cached by path for each fetcher's lifetime.

```python
import os

from iqe_library.vault import VaultOptions, VaultSecretFetcher

fetcher = VaultSecretFetcher(
    VaultOptions(
        url="https://vault.example.com",
        mount_point="insights",
        token=os.environ["VAULT_TOKEN"],
    )
)
password = fetcher.get_value_from_vault("users/demo", "password")
secret = fetcher.get("users/demo")
```

Authentication supports explicit tokens, AppRole (`role_id`/`secret_id`), and
browserless OIDC. OIDC also requires `kerberos` and an existing Kerberos ticket.
Create a new fetcher when fresh secrets are needed.

Licensed under [GPLv3](LICENSE).
