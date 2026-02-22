"""Tests for module.mcp.security - LocalNetworkMiddleware and _is_local()."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from module.mcp.security import LocalNetworkMiddleware, _is_local

# ---------------------------------------------------------------------------
# _is_local() unit tests
# ---------------------------------------------------------------------------


class TestIsLocal:
    """Verify _is_local() correctly classifies IP addresses."""

    # --- loopback ---

    def test_ipv4_loopback_127_0_0_1(self):
        """127.0.0.1 is the canonical loopback address."""
        assert _is_local("127.0.0.1") is True

    def test_ipv4_loopback_127_0_0_2(self):
        """127.0.0.2 is within 127.0.0.0/8 and therefore local."""
        assert _is_local("127.0.0.2") is True

    def test_ipv4_loopback_127_255_255_255(self):
        """Top of 127.0.0.0/8 range is still local."""
        assert _is_local("127.255.255.255") is True

    # --- RFC 1918 class-A (10.0.0.0/8) ---

    def test_ipv4_10_network_start(self):
        """10.0.0.1 is in 10.0.0.0/8 private range."""
        assert _is_local("10.0.0.1") is True

    def test_ipv4_10_network_mid(self):
        """10.10.20.30 is inside 10.0.0.0/8."""
        assert _is_local("10.10.20.30") is True

    def test_ipv4_10_network_end(self):
        """10.255.255.254 is the last usable address in 10.0.0.0/8."""
        assert _is_local("10.255.255.254") is True

    # --- RFC 1918 class-B (172.16.0.0/12) ---

    def test_ipv4_172_16_start(self):
        """172.16.0.1 is the first address in 172.16.0.0/12."""
        assert _is_local("172.16.0.1") is True

    def test_ipv4_172_31_end(self):
        """172.31.255.254 is at the top of the 172.16.0.0/12 range."""
        assert _is_local("172.31.255.254") is True

    def test_ipv4_172_15_not_local(self):
        """172.15.255.255 is just outside 172.16.0.0/12 (below the range)."""
        assert _is_local("172.15.255.255") is False

    def test_ipv4_172_32_not_local(self):
        """172.32.0.0 is just above 172.16.0.0/12 (outside the range)."""
        assert _is_local("172.32.0.0") is False

    # --- RFC 1918 class-C (192.168.0.0/16) ---

    def test_ipv4_192_168_start(self):
        """192.168.0.1 is a typical home-router address."""
        assert _is_local("192.168.0.1") is True

    def test_ipv4_192_168_end(self):
        """192.168.255.254 is at the top of 192.168.0.0/16."""
        assert _is_local("192.168.255.254") is True

    # --- Public IPv4 ---

    def test_public_ipv4_google_dns(self):
        """8.8.8.8 (Google DNS) is a public address."""
        assert _is_local("8.8.8.8") is False

    def test_public_ipv4_cloudflare_dns(self):
        """1.1.1.1 (Cloudflare) is a public address."""
        assert _is_local("1.1.1.1") is False

    def test_public_ipv4_broadcast_like(self):
        """203.0.113.1 (TEST-NET-3, RFC 5737) is not a private address."""
        assert _is_local("203.0.113.1") is False

    # --- IPv6 loopback ---

    def test_ipv6_loopback(self):
        """::1 is the IPv6 loopback address."""
        assert _is_local("::1") is True

    # --- IPv6 link-local (fe80::/10) ---

    def test_ipv6_link_local(self):
        """fe80::1 is an IPv6 link-local address."""
        assert _is_local("fe80::1") is True

    def test_ipv6_link_local_full(self):
        """fe80::aabb:ccdd is also link-local."""
        assert _is_local("fe80::aabb:ccdd") is True

    # --- IPv6 ULA (fc00::/7) ---

    def test_ipv6_ula_fc(self):
        """fc00::1 is within the ULA range fc00::/7."""
        assert _is_local("fc00::1") is True

    def test_ipv6_ula_fd(self):
        """fd00::1 is within the ULA range fc00::/7 (fd prefix)."""
        assert _is_local("fd00::1") is True

    # --- Public IPv6 ---

    def test_public_ipv6_google(self):
        """2001:4860:4860::8888 (Google IPv6 DNS) is a public address."""
        assert _is_local("2001:4860:4860::8888") is False

    def test_public_ipv6_documentation(self):
        """2001:db8::1 (documentation prefix, RFC 3849) is public."""
        assert _is_local("2001:db8::1") is False

    # --- Invalid inputs ---

    def test_invalid_hostname_returns_false(self):
        """A hostname string is not parseable as an IP and must return False."""
        assert _is_local("localhost") is False

    def test_invalid_string_returns_false(self):
        """A random non-IP string returns False without raising."""
        assert _is_local("not-an-ip") is False

    def test_empty_string_returns_false(self):
        """An empty string is not a valid IP address."""
        assert _is_local("") is False

    def test_malformed_ipv4_returns_false(self):
        """A string that looks like IPv4 but is malformed returns False."""
        assert _is_local("256.0.0.1") is False

    def test_partial_ipv4_returns_false(self):
        """An incomplete IPv4 address is not valid."""
        assert _is_local("192.168") is False


# ---------------------------------------------------------------------------
# LocalNetworkMiddleware integration tests
# ---------------------------------------------------------------------------


def _make_app_with_middleware() -> Starlette:
    """Build a minimal Starlette app with LocalNetworkMiddleware applied."""

    async def homepage(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(LocalNetworkMiddleware)
    return app


class TestLocalNetworkMiddleware:
    """Verify LocalNetworkMiddleware allows or denies requests by client IP."""

    @pytest.fixture
    def app(self):
        return _make_app_with_middleware()

    def test_local_ipv4_loopback_allowed(self, app):
        """Requests from 127.0.0.1 are allowed through."""
        # Starlette's TestClient identifies itself as "testclient", not a real IP.
        # Patch the scope so the middleware sees an actual loopback address.
        original_build = app.build_middleware_stack

        async def patched_app(scope, receive, send):
            if scope["type"] == "http":
                scope["client"] = ("127.0.0.1", 12345)
            await original_build()(scope, receive, send)

        app.build_middleware_stack = lambda: patched_app  # type: ignore[method-assign]

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/")
        assert response.status_code == 200
        assert response.text == "ok"

    def test_non_local_ip_blocked(self, app):
        """Requests from a public IP are rejected with 403."""
        # Patch the ASGI scope to simulate a public client
        original_build = app.build_middleware_stack

        async def patched_app(scope, receive, send):
            if scope["type"] == "http":
                scope["client"] = ("8.8.8.8", 12345)
            await original_build()(scope, receive, send)

        app.build_middleware_stack = lambda: patched_app  # type: ignore[method-assign]

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/")
        assert response.status_code == 403
        assert "MCP access is restricted to local network" in response.text

    def test_missing_client_blocked(self, app):
        """Requests with no client information are rejected with 403."""
        original_build = app.build_middleware_stack

        async def patched_app(scope, receive, send):
            if scope["type"] == "http":
                scope["client"] = None
            await original_build()(scope, receive, send)

        app.build_middleware_stack = lambda: patched_app  # type: ignore[method-assign]

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/")
        assert response.status_code == 403

    def test_blocked_response_is_json(self, app):
        """The 403 error body is valid JSON with an 'error' key."""
        import json

        original_build = app.build_middleware_stack

        async def patched_app(scope, receive, send):
            if scope["type"] == "http":
                scope["client"] = ("1.2.3.4", 9999)
            await original_build()(scope, receive, send)

        app.build_middleware_stack = lambda: patched_app  # type: ignore[method-assign]

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/")
        assert response.status_code == 403
        body = json.loads(response.text)
        assert "error" in body

    def test_private_192_168_allowed(self, app):
        """Requests from a 192.168.x.x address pass through."""
        original_build = app.build_middleware_stack

        async def patched_app(scope, receive, send):
            if scope["type"] == "http":
                scope["client"] = ("192.168.1.100", 54321)
            await original_build()(scope, receive, send)

        app.build_middleware_stack = lambda: patched_app  # type: ignore[method-assign]

        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/")
        assert response.status_code == 200
