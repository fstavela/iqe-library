"""Read only the FrontendEnvironment and Keycloak secret needed by external tests."""

import base64
import json
import os
from collections.abc import Mapping
from functools import cached_property
from typing import Any
from urllib.parse import urlsplit


class EphemeralDiscoveryError(RuntimeError):
    """OpenShift discovery failed, without including secret contents or command output."""


def _oc(*args: str) -> str:
    try:
        from ocviapy import oc
    except ImportError:
        raise ImportError("OpenShift discovery requires iqe-library[ephemeral]") from None
    try:
        # ocviapy's get_json has no timeout parameter. Use its command wrapper
        # directly, with bounded waits and no logging of resource contents.
        return str(oc(*args, _silent=True, _timeout=30))
    except Exception:
        raise EphemeralDiscoveryError(
            "OpenShift command failed; check oc installation, login, and resource access"
        ) from None


def _read_json(resource: str, name: str, *, namespace: str | None = None) -> Mapping[str, Any]:
    args = ["get", resource, name, "-o", "json", "--request-timeout=30s"]
    if namespace is not None:
        args.extend(["--namespace", namespace])
    context = f"{resource} {name!r}"
    if namespace is not None:
        context += f" in namespace {namespace!r}"
    try:
        output = _oc(*args)
    except EphemeralDiscoveryError:
        raise EphemeralDiscoveryError(
            f"Could not read {context}; check oc login and access"
        ) from None
    try:
        data = json.loads(output)
        if not isinstance(data, dict):
            raise ValueError
    except (TypeError, ValueError):
        raise EphemeralDiscoveryError(f"Invalid JSON object returned for {context}") from None
    return data


class EphemeralEnvParser:
    """Snapshot an explicit namespace or NAMESPACE; otherwise discover the current project.

    Construction and imports do not call oc. Successful reads are cached on this
    instance. Use one instance per config/test session, and a new one for another
    namespace or fresh discovery. The current OpenShift context is never modified.
    """

    def __init__(self, namespace: str | None = None) -> None:
        if namespace is not None and (not isinstance(namespace, str) or not namespace.strip()):
            raise ValueError("namespace must be a nonempty string or None")
        self._namespace = namespace if namespace is not None else os.getenv("NAMESPACE") or None

    @cached_property
    def namespace(self) -> str:
        namespace = self._namespace or _oc("project", "--short").strip()
        if not namespace.strip():
            raise EphemeralDiscoveryError("Set NAMESPACE or select an oc project before discovery")
        return namespace

    @cached_property
    def _frontend_spec(self) -> Mapping[str, Any]:
        # FrontendEnvironment is cluster-scoped; the resource name selects the env.
        name = f"env-{self.namespace}"
        spec = _read_json("frontendenvironment", name).get("spec")
        if not isinstance(spec, Mapping):
            raise EphemeralDiscoveryError(f"FrontendEnvironment {name!r} has no valid spec")
        return spec

    def _frontend_value(self, key: str) -> str:
        value = self._frontend_spec.get(key)
        if not isinstance(value, str) or not value.strip():
            raise EphemeralDiscoveryError(
                f"FrontendEnvironment 'env-{self.namespace}' has no valid spec.{key}"
            )
        return value

    @property
    def env_hostname(self) -> str:
        """External gateway hostname."""
        return self._frontend_value("hostname")

    @property
    def sso_url(self) -> str:
        """Keycloak server URL, including its deployment-specific path."""
        value = self._frontend_value("sso")
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError
        except ValueError:
            raise EphemeralDiscoveryError(
                f"FrontendEnvironment 'env-{self.namespace}' has no valid spec.sso URL"
            ) from None
        return value.rstrip("/") + "/"

    @cached_property
    def _keycloak_config(self) -> Mapping[str, Any]:
        name = f"env-{self.namespace}-keycloak"
        data = _read_json("secret", name, namespace=self.namespace).get("data")
        if not isinstance(data, Mapping):
            raise EphemeralDiscoveryError(
                f"Keycloak secret {name!r} in namespace {self.namespace!r} has no valid data"
            )
        return data

    def _secret_value(self, key: str) -> str:
        try:
            value = base64.b64decode(self._keycloak_config[key], validate=True).decode("utf-8")
            if not value.strip():
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise EphemeralDiscoveryError(
                f"Keycloak secret 'env-{self.namespace}-keycloak' in namespace "
                f"{self.namespace!r} has no valid {key!r}"
            ) from None
        return value

    @property
    def sso_admin_username(self) -> str:
        return self._secret_value("username")

    @property
    def sso_admin_password(self) -> str:
        return self._secret_value("password")
