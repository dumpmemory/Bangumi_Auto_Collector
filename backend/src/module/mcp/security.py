"""MCP access control: restricts connections to local network addresses only."""

import ipaddress
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# RFC 1918 private ranges + loopback + IPv6 equivalents
_ALLOWED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_local(host: str) -> bool:
    """Return True if *host* is a loopback or RFC 1918 private address."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in _ALLOWED_NETWORKS)


class LocalNetworkMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that blocks requests from non-local IP addresses.

    Returns HTTP 403 for any client outside loopback, RFC 1918, or IPv6
    link-local/unique-local ranges.
    """

    async def dispatch(self, request: Request, call_next):
        client_host = request.client.host if request.client else None
        if not client_host or not _is_local(client_host):
            logger.warning("[MCP] Rejected non-local connection from %s", client_host)
            return JSONResponse(
                status_code=403,
                content={"error": "MCP access is restricted to local network"},
            )
        return await call_next(request)
