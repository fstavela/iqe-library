"""Offline logging contracts through prepared requests and native response hooks."""

import logging
from io import BytesIO

import pytest
import requests

from iqe_library import http


def prepared_response(**kwargs):
    response = requests.Response()
    response.request = requests.Request(
        "POST", "https://api.invalid/items?filter=a%20b&page=2", **kwargs
    ).prepare()
    response.status_code = 201
    response.headers["x-rh-insights-request-id"] = "request-id-sentinel"
    response._content = b"response-body-secret"
    return response


def emit(response):
    hook = getattr(http, "log_response", None)
    assert callable(hook), "public log_response hook is missing"
    assert hook(response, stream=True, timeout=30) is None


@pytest.mark.parametrize(
    ("kwargs", "body"),
    [
        ({"json": {"name": "json-sentinel"}}, '{"name": "json-sentinel"}'),
        ({"data": {"name": "form sentinel"}}, "name=form+sentinel"),
        ({"data": "text-sentinel"}, "text-sentinel"),
        (
            {"data": "café-sentinel".encode(), "headers": {"Content-Type": "text/plain"}},
            "café-sentinel",
        ),
        ({"data": b"untyped-text-sentinel"}, "untyped-text-sentinel"),
    ],
)
def test_default_log_keeps_query_and_text_body(caplog, kwargs, body):
    response = prepared_response(**kwargs)
    request = response.request
    original_body = request.body
    with caplog.at_level(logging.INFO, logger="iqe_library.http"):
        emit(response)
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.name == "iqe_library.http"
    assert record.levelno == logging.INFO
    message = record.getMessage()
    for value in (
        "POST",
        "https://api.invalid/items?filter=a%20b&page=2",
        body,
        "201",
        "request-id-sentinel",
    ):
        assert value in message
    assert response.request is request
    assert request.body is original_body
    assert "response-body-secret" not in message


@pytest.mark.parametrize(
    "kwargs",
    [
        {"files": {"upload": ("secret.txt", b"multipart-secret")}},
        {"data": b"binary-secret", "headers": {"Content-Type": "application/octet-stream"}},
        {"data": b"archive-secret", "headers": {"Content-Type": "application/x-tar"}},
        {"data": "multipart-secret", "headers": {"Content-Type": "multipart/form-data"}},
        {"data": b"multipart-secret", "headers": {"Content-Type": "multipart/mixed+json"}},
        {"data": b"undecodable-secret\xff"},
        {"data": b"binary-secret\x00", "headers": {"Content-Type": "text/plain"}},
        {"data": b"PK\x03\x04zip-secret", "headers": {"Content-Type": "application/json"}},
    ],
)
def test_binary_bodies_are_not_dumped(caplog, kwargs):
    response = prepared_response(**kwargs)
    body = response.request.body
    with caplog.at_level(logging.INFO, logger="iqe_library.http"):
        emit(response)
    assert "binary" in caplog.text.lower()
    assert "secret" not in caplog.text
    assert response.request.body is body


class CountingFile(BytesIO):
    reads = 0
    iterations = 0

    def read(self, *args, **kwargs):
        self.reads += 1
        return super().read(*args, **kwargs)

    def __iter__(self):
        self.iterations += 1
        return super().__iter__()


@pytest.mark.parametrize("body_kind", ["file", "generator"])
def test_streaming_bodies_are_not_consumed(caplog, body_kind):
    iterations = []

    def chunks():
        iterations.append(True)
        yield b"stream-secret"

    body = CountingFile(b"file-secret") if body_kind == "file" else chunks()
    response = prepared_response(data=body)
    if body_kind == "file":
        assert body.reads == body.iterations == 0
    assert iterations == []
    with caplog.at_level(logging.INFO, logger="iqe_library.http"):
        emit(response)
    assert "stream" in caplog.text.lower()
    assert "secret" not in caplog.text
    assert response.request.body is body
    if body_kind == "file":
        assert body.reads == body.iterations == 0
        assert body.tell() == 0
    assert iterations == []


def test_unavailable_request_body_does_not_break_hook(caplog):
    class UnavailableBody:
        def __str__(self):
            raise AssertionError("must not stringify an arbitrary body")

        __repr__ = __str__

    response = prepared_response()
    response.request.body = UnavailableBody()
    with caplog.at_level(logging.INFO, logger="iqe_library.http"):
        emit(response)
    assert "omitted" in caplog.text.lower()


def test_response_without_request_does_not_break_hook(caplog):
    response = requests.Response()
    response.status_code = 204
    with caplog.at_level(logging.INFO, logger="iqe_library.http"):
        emit(response)
    assert "204" in caplog.text


def test_logger_does_not_read_streamed_response(caplog, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("must not access response content, text, JSON or stream")

    response = prepared_response(data="request-sentinel")
    monkeypatch.setattr(requests.Response, "content", property(forbidden))
    monkeypatch.setattr(requests.Response, "text", property(forbidden))
    monkeypatch.setattr(requests.Response, "json", forbidden)
    monkeypatch.setattr(requests.Response, "iter_content", forbidden)
    with caplog.at_level(logging.INFO, logger="iqe_library.http"):
        emit(response)
    assert "request-sentinel" in caplog.text


@pytest.mark.parametrize("request_id", ["id\r\nforged\t\x00\x1b\x7f\u2028\u0085", "a" * 200])
def test_request_id_is_single_line_and_bounded(caplog, request_id):
    response = prepared_response()
    response.headers["x-rh-insights-request-id"] = request_id
    with caplog.at_level(logging.INFO, logger="iqe_library.http"):
        emit(response)
    message = caplog.records[0].getMessage()
    identifier = message.split("request_id=", 1)[1].split(" body=", 1)[0]
    assert 0 < len(identifier) <= 128
    assert identifier.isprintable()
    if request_id.startswith("id"):
        assert identifier.startswith("id")
        assert "forged" in identifier
    else:
        assert identifier == "a" * 128


@pytest.mark.parametrize("header", ["X-Rh-Insights-Request-Id", None])
def test_request_id_uses_inventory_header_case_insensitively(caplog, header):
    response = prepared_response()
    response.headers.clear()
    response.headers["X-Request-ID"] = "wrong-header-sentinel"
    if header is not None:
        response.headers[header] = "inventory-id-sentinel"
    with caplog.at_level(logging.INFO, logger="iqe_library.http"):
        emit(response)
    expected = "inventory-id-sentinel" if header is not None else "<none>"
    assert f"request_id={expected}" in caplog.text
    assert "wrong-header-sentinel" not in caplog.text


def test_text_body_controls_are_escaped(caplog):
    response = prepared_response(data="first\r\nsecond\t\x1b\u2028")
    with caplog.at_level(logging.INFO, logger="iqe_library.http"):
        emit(response)
    message = caplog.records[0].getMessage()
    assert message.isprintable()
    assert "first" in message and "second" in message
    assert r"\r\n" in message


@pytest.fixture
def transport(http_transport):
    return http_transport.responses


@pytest.mark.parametrize(
    ("content_type", "textual"),
    [
        (b"text/plain", True),
        (b"text/plain; charset=utf-8", True),
        (b"application/octet-stream", False),
        (b"application/octet-stream; name=\xff", False),
        (b"multipart/mixed+json; boundary=unused", False),
    ],
)
def test_byte_content_type_does_not_break_response_hooks(caplog, transport, content_type, textual):
    body = b"body-visible"
    with (
        caplog.at_level(logging.INFO, logger="iqe_library.http"),
        http.create_session(trust_env=False) as session,
    ):
        response = session.post(
            "https://api.invalid/items?query=visible",
            headers={"Content-Type": content_type},
            data=body,
            stream=True,
        )
    assert response is transport[0]
    assert response.status_code == 200
    assert response.request.headers["Content-Type"] == content_type
    assert response.request.body is body
    assert len(caplog.records) == 1
    message = caplog.records[0].getMessage()
    assert "https://api.invalid/items?query=visible" in message
    if textual:
        assert "body-visible" in message
    else:
        assert "body-visible" not in message
        assert "binary" in message.lower()
    assert "response-secret" not in message


def test_factory_logs_at_transport_boundary_without_credential_headers(caplog, transport):
    with (
        caplog.at_level(logging.INFO, logger="iqe_library.http"),
        http.create_session(
            headers={"Authorization": "Bearer bearer-secret", "x-rh-identity": "identity-secret"},
            cookies={"session": "cookie-secret"},
            trust_env=False,
        ) as session,
    ):
        response = session.post("https://api.invalid/items?query=visible", data="body-visible")
    assert response is transport[0]
    assert len(caplog.records) == 1
    assert "https://api.invalid/items?query=visible" in caplog.text
    assert "body-visible" in caplog.text
    for value in ("secret", "Authorization", "Bearer", "x-rh-identity", "Cookie"):
        assert value not in caplog.text
    assert response.request.headers["Authorization"] == "Bearer bearer-secret"
    assert response.content == b"response-secret"


@pytest.mark.parametrize("mode", ["remove", "replace", "extend", "request-replace"])
def test_hooks_can_be_removed_replaced_or_extended(caplog, transport, mode):
    seen = []

    def custom_hook(response, **kwargs):
        seen.append(response)
        assert kwargs["stream"] is True

    with (
        caplog.at_level(logging.INFO, logger="iqe_library.http"),
        http.create_session(trust_env=False) as session,
    ):
        if mode == "remove":
            session.hooks["response"].clear()
        elif mode == "replace":
            session.hooks["response"] = [custom_hook]
        elif mode == "extend":
            session.hooks["response"].append(custom_hook)
        kwargs = {"hooks": {"response": [custom_hook]}} if mode == "request-replace" else {}
        response = session.get("https://api.invalid/items", stream=True, **kwargs)
    assert response is transport[0]
    assert seen == ([] if mode == "remove" else [response])
    assert len(caplog.records) == (1 if mode == "extend" else 0)
    assert response.content == b"response-secret"
