"""Opt-out summaries of prepared requests, without reading transport streams."""

import logging
from typing import Any

import requests

_logger = logging.getLogger("iqe_library.http")


def _single_line(text: str) -> str:
    return "".join(char if char.isprintable() else ascii(char)[1:-1] for char in text)


def _request_body(request: requests.PreparedRequest) -> str:
    body = request.body
    if body is None:
        return "<none>"
    # Never stringify, read, or iterate arbitrary bodies (including files and
    # generators). Only inspect the strings/bytes already prepared by Requests.
    if not isinstance(body, (str, bytes)):
        return "<stream/unavailable omitted>"
    content_type: str | bytes = request.headers.get("Content-Type", "")
    # Requests accepts byte-valued headers; normalize locally without mutation.
    if isinstance(content_type, bytes):
        content_type = content_type.decode("latin-1")
    media_type = content_type.split(";", 1)[0].strip().lower()
    textual = (
        not media_type
        or media_type.startswith("text/")
        or media_type
        in {"application/json", "application/xml", "application/x-www-form-urlencoded"}
        or media_type.endswith(("+json", "+xml"))
    )
    if media_type.startswith("multipart/") or not textual:
        return "<binary omitted>"
    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return "<binary omitted>"
        # A textual MIME label alone is not enough: reject binary controls even
        # when UTF-8 decoding succeeds, while allowing ordinary text whitespace.
        if any(
            (ord(char) < 32 and char not in "\t\r\n") or 127 <= ord(char) < 160 for char in text
        ):
            return "<binary omitted>"
    else:
        text = body
    return _single_line(text)


def log_response(response: requests.Response, *args: Any, **kwargs: Any) -> None:
    """Log full URL/query and available textual request body at INFO.

    URLs and bodies can disclose secrets; remove or replace this native Requests
    hook when needed. No credential headers, response bodies or streams are read.
    Returning None preserves Requests' original response.
    """
    if not _logger.isEnabledFor(logging.INFO):
        return
    request = response.request
    method = (
        _single_line(request.method or "<unavailable>") if request is not None else "<unavailable>"
    )
    url = _single_line(request.url or "<unavailable>") if request is not None else "<unavailable>"
    body = _request_body(request) if request is not None else "<unavailable>"
    request_id = response.headers.get("x-rh-insights-request-id", "<none>")
    request_id = _single_line(request_id[:128])[:128]
    _logger.info(
        "%s %s status=%s request_id=%s body=%s",
        method,
        url,
        response.status_code,
        request_id,
        body,
    )
