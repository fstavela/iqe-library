"""Lazy outside-cluster OpenShift discovery, independent of configuration."""

from ._discovery import EphemeralDiscoveryError, EphemeralEnvParser

__all__ = ["EphemeralDiscoveryError", "EphemeralEnvParser"]
