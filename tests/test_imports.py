"""Optional dependencies and lazy construction, checked in fresh Python processes."""

import subprocess
import sys
import textwrap

import pytest


@pytest.fixture
def isolated(tmp_path):
    def run(code, *, blocked=(), missing=(), args=()):
        guards = f"""
import importlib.abc
import sys

blocked, missing = {blocked!r}, {missing!r}
attempts = []

def matches(name, roots):
    return any(name == root or name.startswith(root + '.') for root in roots)

class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if matches(fullname, blocked):
            attempts.append(fullname)
            raise AssertionError('Forbidden import: ' + fullname)
        if matches(fullname, missing):
            raise ImportError('Not installed: ' + fullname)

assert not any(matches(name, blocked + missing) for name in sys.modules)
sys.meta_path.insert(0, Guard())

def audit(event, args):
    if event in ('socket.connect', 'socket.getaddrinfo', 'socket.sendto', 'subprocess.Popen'):
        attempts.append(event)
        raise AssertionError('External I/O during construction: ' + event)

sys.addaudithook(audit)
"""
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                guards + textwrap.dedent(code) + "\nassert not attempts",
                *args,
            ],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout == result.stderr == ""

    return run


@pytest.mark.parametrize("first", ["auth", "http"])
def test_http_auth_are_independent_and_lazy(isolated, first):
    isolated(
        f"""
        import importlib
        importlib.import_module('iqe_library.{first}')
        from pathlib import Path
        import requests
        from requests.auth import HTTPBasicAuth
        from iqe_library.auth import CertificateAuth, IdentityAuth, NoAuth, OIDCAuth, TokenEndpoint, certificate_files
        from iqe_library.http import create_session, create_session_from_config

        def no_requests(*args, **kwargs):
            raise AssertionError('Requests during construction')
        requests.Session.send = no_requests
        endpoint = TokenEndpoint(token_url='https://sso.invalid/token')
        auths = [None, NoAuth(), HTTPBasicAuth('u', 'p'), IdentityAuth({{}}),
                 OIDCAuth.from_refresh_token('offline', endpoint),
                 OIDCAuth.from_client_credentials('secret', endpoint),
                 OIDCAuth.from_password('user', 'password', endpoint),
                 CertificateAuth.from_pem('cert', 'key')]
        with certificate_files('cert', 'key') as paths:
            auths.append(CertificateAuth.from_files(*paths))
            for auth in auths:
                with create_session(auth=auth) as session:
                    assert isinstance(session, requests.Session)
                session.close()
            assert all(Path(path).is_file() for path in paths)
        assert all(not Path(path).exists() for path in paths)
        with create_session_from_config({{'http': {{'default_auth_type': 'none'}}}}) as session:
            assert isinstance(session.auth, NoAuth)
        """,
        blocked=("dynaconf", "hvac", "pytest", "iqe", "iqe_library.config", "iqe_library.vault"),
    )


@pytest.mark.parametrize(
    "module,blocked,construction",
    [
        ("iqe_library", ("dynaconf", "yaml", "jinja2", "hvac", "requests", "truststore"), ""),
        ("iqe_library.vault", ("dynaconf", "requests_gssapi"), ""),
        (
            "iqe_library.ephemeral",
            ("dynaconf", "hvac", "ocviapy"),
            "assert module.EphemeralEnvParser('selected').namespace == 'selected'",
        ),
        (
            "iqe_library.users",
            ("dynaconf", "hvac", "ocviapy"),
            """
with module.create_user_provider(server_url='https://sso.invalid/auth/', username='admin', password='private'):
    pass
with module.create_user_provider_from_config({'keycloak_admin': {'server_url': 'https://sso.invalid/auth/', 'username': 'admin', 'password': 'private'}}):
    pass
""",
        ),
    ],
)
def test_standalone_modules(isolated, module, blocked, construction):
    isolated(
        f"import importlib\nmodule = importlib.import_module({module!r})\n" + construction,
        blocked=(*blocked, "pytest", "iqe_library.config"),
    )


def test_config_loading_and_overrides_need_no_backends(isolated, config_file):
    path = config_file("default:\n  secret: !from_vault {path: never-read, key: password}\n")
    isolated(
        """
        import os
        from iqe_library.config import load_config
        settings = load_config(sys.argv[1], environment='ephemeral')
        assert settings.http.default_auth_type == 'basic'
        os.environ['DYNACONF_BASE_URL'] = 'https://override.invalid'
        os.environ['DYNACONF_SECRET'] = 'literal-override'
        overridden = load_config(sys.argv[1], environment='ephemeral')
        assert overridden.base_url == 'https://override.invalid'
        assert overridden.secret == 'literal-override'
        """,
        args=(str(path),),
        blocked=(
            "ocviapy",
            "keycloak",
            "hvac",
            "requests",
            "truststore",
            "urllib3",
            "iqe_library.vault",
        ),
    )


@pytest.mark.parametrize(
    "backend,dependency,key",
    [("vault", "hvac", "secret"), ("ephemeral", "ocviapy", "base_url")],
)
def test_missing_backends_fail_on_access(isolated, config_file, backend, dependency, key):
    path = config_file("default:\n  secret: !from_vault {path: never-read, key: password}\n")
    isolated(
        f"""
        import os
        os.environ['NAMESPACE'] = 'selected'
        from iqe_library.config import load_config
        settings = load_config(sys.argv[1], environment='ephemeral')
        assert settings.http.default_auth_type == 'basic'
        try:
            settings.get({key!r})
        except ImportError as error:
            assert 'iqe-library[{backend}]' in str(error)
        else:
            raise AssertionError('Access must require the backend extra')
        if {backend!r} == 'ephemeral':
            from iqe_library.ephemeral import EphemeralEnvParser
            parser = EphemeralEnvParser('selected')
            try:
                parser.env_hostname
            except ImportError as error:
                assert 'iqe-library[ephemeral]' in str(error)
            else:
                raise AssertionError('Discovery must require the extra')
        """,
        missing=(dependency,),
        args=(str(path),),
    )
