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
    ],
)
def test_standalone_modules(isolated, module, blocked, construction):
    isolated(
        f"import importlib\nmodule = importlib.import_module({module!r})\n" + construction,
        blocked=(*blocked, "pytest", "iqe_library.config"),
    )
