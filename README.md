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
Use `uv run --all-extras pytest tests/test_http.py -q` to run one module.

To use the checkout in another uv project:

```bash
uv add --dev --editable '/path/to/iqe-library[http,config]'
```

The base package has no runtime dependencies. Select only the extras you need:
`http`, `config`, `vault`, and `kerberos`.

## Configuration

Requires `config`. Load shared Stage/prod defaults with an optional consumer YAML
file. Consumer values override shared defaults; `.local.yaml` companions and
`DYNACONF_*` environment variables provide further overrides.

```yaml
# consumer.yaml
default:
  default_user: viewer
  http:
    default_auth_type: basic
    timeout: 10
  users:
    viewer:
      auth:
        basic:
          username: demo
          password: '@jinja {{ env.DEMO_PASSWORD }}'
```

```python
from iqe_library.config import load_config

settings = load_config("consumer.yaml", environment="stage")
print(settings.base_url)
```

The environment defaults to `ENV_FOR_DYNACONF`, then `stage`.
For example, `DYNACONF_HTTP__TIMEOUT=20` overrides a nested setting.
Jinja templates and `!from_vault {path: users/demo, key: password}` references
resolve only when accessed; Vault references also require the `vault` extra.

## HTTP sessions and authentication

Requires `http`. Sessions are Requests-compatible, default to system TLS trust
and a 30-second timeout, and should be closed with a context manager.

```python
from iqe_library.http import create_session_from_config

with create_session_from_config(settings, user="viewer", auth_type="basic") as session:
    response = session.get(f"{settings.base_url}/api/inventory/v1/hosts")
    response.raise_for_status()
```

Config-backed sessions support `basic`, `jwt`, `cert`, `identity`, and `none`.
They also accept plain mappings without the `config` extra. For direct OAuth use:

```python
import os

from iqe_library.auth import OIDCAuth, TokenEndpoint
from iqe_library.http import create_session

endpoint = TokenEndpoint(token_url=os.environ["TOKEN_URL"])
auth = OIDCAuth.from_refresh_token(os.environ["OFFLINE_TOKEN"], endpoint)
with create_session(auth=auth) as session:
    response = session.get("https://service.example.com/api/items")
```

OAuth tokens are acquired lazily and renewed automatically. Service accounts can
use `OIDCAuth.from_client_credentials(secret, endpoint)` with an explicit client ID.
`IdentityAuth(identity, entitlements)` provides `x-rh-identity` authentication.
For client TLS, pass `CertificateAuth.from_files(cert_path, key_path)` or
`CertificateAuth.from_pem(cert_pem, key_pem)` as `auth`; session close removes only
library-owned PEM files. Use `settings.cert_base_url` for Stage/prod certificate APIs.

**Logging:** API summaries include full URLs and textual request bodies, which may
contain secrets. Disable them with `session.hooks["response"].clear()` or replace
the hook before sending sensitive data. OAuth exchanges are not logged.

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

## Insights archives

No extras required. Generate a modern Insights archive with unique host IDs and
hostname, using the bundled RHEL 9.4 template or your own archive.

```python
from shutil import rmtree

from iqe_library.archive import HostArchiveData, prepare_archive

archive = prepare_archive(HostArchiveData.random())
try:
    print(archive)  # Pass this Path to your uploader.
finally:
    rmtree(archive.parent)  # The caller owns the output directory.
```

Pass `source_archive=Path("custom.tar.gz")` for a filesystem template.
The source is never modified; archive uploading is left to the consumer.

Licensed under [GPLv3](LICENSE).
