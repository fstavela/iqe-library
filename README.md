# iqe-library

Shared Python utilities for testing Red Hat Insights services: configuration,
authentication, HTTP sessions, Vault secrets, Insights archives, and ephemeral
environment discovery and user provisioning. Utilities can be used independently
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
Use `uv run --all-extras pytest tests/test_archive.py -q` to run one module.

To use the checkout in another uv project:

```bash
uv add --dev --editable '/path/to/iqe-library[http,config]'
```

The base package has no runtime dependencies. Select only the extras you need:
`http`, `config`, `vault`, `kerberos`, `ephemeral`, and `users`.

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
use `OIDCAuth.from_client_credentials(secret, endpoint)` with an explicit client ID;
ephemeral Keycloak realms can use `OIDCAuth.from_password(username, password, endpoint)`.
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

## Ephemeral environments

Requires `ephemeral`, plus an installed and logged-in `oc` CLI. Discovery reads
the external gateway and SSO URL from the selected environment and caches them.

```python
from iqe_library.ephemeral import EphemeralEnvParser

environment = EphemeralEnvParser(namespace="ephemeral-example")
print(environment.env_hostname)
print(environment.sso_url)
```

Without an explicit namespace, `NAMESPACE` is used, then the current `oc project`.
With `config,ephemeral`, `load_config(environment="ephemeral")` supplies lazy gateway,
SSO, and Keycloak admin settings. Loading config alone does not contact OpenShift.

## User provisioning

Requires `users`. Create or reuse Keycloak users without changing RBAC roles/groups.
Admin credentials and user credentials are separate.

```python
import os

from iqe_library.users import create_user_provider

with create_user_provider(
    server_url="https://sso.example.com/auth/",
    username="admin",
    password=os.environ["KEYCLOAK_ADMIN_PASSWORD"],
) as provider:
    keycloak_id = provider.ensure_user(
        username="demo",
        password=os.environ["DEMO_PASSWORD"],
        attributes={
            "account_number": "012345",
            "org_id": "12345",
            "user_id": "123451",
            "email": "demo@example.com",
            "first_name": "Demo",
            "last_name": "User",
        },
        entitlements={"insights": {"is_entitled": True}},
    )
```

Reuse preserves the Keycloak UUID; `recreate=True` deletes and recreates the user.
The required Insights `user_id` is distinct from that UUID.
`provision_users_from_config(settings)` provisions configured users using their
`auth.basic`, `attributes`, and `entitlements` blocks and `keycloak_admin` settings.
For ephemeral use, install `config,ephemeral,users` and call provisioning explicitly
from test setup, not during imports or collection.

Licensed under [GPLv3](LICENSE).
