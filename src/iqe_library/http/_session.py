"""Requests-compatible defaults and certificate resource ownership."""

from collections.abc import Callable, Mapping, MutableMapping
from contextlib import ExitStack
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

import requests
from requests.auth import AuthBase

from iqe_library._transport import _SystemTrustAdapter
from iqe_library.auth import CertificateAuth, NoAuth
from iqe_library.auth._types import (
    _validate_proxies,
    _validate_timeout,
    _validate_trust_env,
    _validate_verify,
)

from ._logging import log_response

if TYPE_CHECKING:
    from requests.sessions import _Cert, _Settings, _TextMapping, _Verify


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parsed = urlsplit(url)
    port = parsed.port
    if port is None:
        port = {"http": 80, "https": 443}.get(parsed.scheme)
    return parsed.scheme, parsed.hostname, port


class _Session(requests.Session):
    def __init__(self, timeout: float) -> None:
        super().__init__()
        self._resources = ExitStack()
        self._timeout = timeout

    def request(self, *args: Any, **kwargs: Any) -> requests.Response:
        # Requests' ninth positional argument is timeout. Leave explicit values
        # and duplicate caller arguments untouched for upstream handling.
        if len(args) < 9 and "timeout" not in kwargs:
            kwargs["timeout"] = self._timeout
        return super().request(*args, **kwargs)

    def close(self) -> None:
        first_failure: BaseException | None = None
        # Native Session.close stops at the first failure. Attempt all mounted
        # adapters before releasing PEMs, including when an early close fails.
        for adapter in tuple(self.adapters.values()):
            try:
                adapter.close()
            except BaseException as error:
                if first_failure is None:
                    first_failure = error
        try:
            self._resources.close()
        except BaseException as error:
            if first_failure is None:
                first_failure = error
        if first_failure is not None:
            raise first_failure

    def merge_environment_settings(
        self,
        url: str | bytes | None,
        proxies: "_TextMapping | None",
        stream: bool | None,
        verify: "_Verify | None",
        cert: "_Cert | None",
    ) -> "_Settings":
        # Seed explicit session entries before Requests fills missing keys from
        # the environment, retaining request None entries as explicit exclusions.
        merged_proxies = dict(self.proxies)
        if proxies is not None:
            merged_proxies.update(proxies)
        settings = super().merge_environment_settings(
            url, merged_proxies, stream, self.verify if verify is None else verify, cert
        )
        # Requests removes None during merging, but its native redirect rebuild
        # needs those keys so setdefault cannot restore an excluded ambient proxy.
        # The upstream stubs omit supported None-valued proxy entries.
        effective_proxies = cast(MutableMapping[str, str | None], settings["proxies"])
        effective_proxies.update(
            {key: None for key, value in merged_proxies.items() if value is None}
        )
        return settings

    def rebuild_auth(
        self, prepared_request: requests.PreparedRequest, response: requests.Response
    ) -> None:
        old_url = response.request.url
        new_url = prepared_request.url
        assert old_url is not None and new_url is not None
        # Preserve Requests' safe same-host Authorization exceptions, but never
        # reapply netrc or invoke an auth callback for a redirected origin.
        should_strip_auth = cast(Callable[[str, str], bool], self.should_strip_auth)
        if should_strip_auth(old_url, new_url):
            prepared_request.headers.pop("Authorization", None)
        if _origin(old_url) != _origin(new_url):
            prepared_request.headers.pop("x-rh-identity", None)


def create_session(
    *,
    auth: AuthBase | tuple[str, str] | CertificateAuth | None = None,
    headers: Mapping[str, str] | None = None,
    cookies: Mapping[str, str] | None = None,
    proxies: Mapping[str, str] | None = None,
    verify: bool | str = True,
    timeout: float = 30,
    trust_env: bool = True,
) -> requests.Session:
    """Create a normal Requests session; close it to release owned PEM files."""
    _validate_verify(verify)
    proxy_settings = _validate_proxies(proxies)
    _validate_timeout(timeout)
    _validate_trust_env(trust_env)
    session = _Session(timeout)
    try:
        session.hooks["response"].append(log_response)
        session.verify = verify
        session.trust_env = trust_env
        if headers is not None:
            session.headers.update(headers)
        if cookies is not None:
            session.cookies.update(dict(cookies))
        if proxy_settings is not None:
            session.proxies.update(proxy_settings)
        if isinstance(auth, CertificateAuth):
            session.auth = NoAuth()
            session.cert = auth._materialize(session._resources)
        else:
            session.auth = NoAuth() if auth is None else auth
        adapter = _SystemTrustAdapter()
        try:
            session.get_adapter("https://").close()
            session.mount("https://", adapter)
        except BaseException:
            adapter.close()
            raise
    except BaseException:
        session.close()
        raise
    return session
