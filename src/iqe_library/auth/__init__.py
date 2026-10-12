"""Independent API authentication utilities, without configuration dependencies."""

from ._certificates import CertificateAuth, certificate_files
from ._headers import IdentityAuth, NoAuth
from ._oauth import OIDCAuth
from ._types import TokenAuthenticationError, TokenEndpoint

__all__ = [
    "CertificateAuth",
    "IdentityAuth",
    "NoAuth",
    "OIDCAuth",
    "TokenAuthenticationError",
    "TokenEndpoint",
    "certificate_files",
]
