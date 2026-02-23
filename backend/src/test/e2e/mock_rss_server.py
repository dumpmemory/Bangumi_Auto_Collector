"""Minimal HTTP server that serves static RSS XML fixtures."""

import asyncio
from pathlib import Path

from aiohttp import web

FIXTURES_DIR = Path(__file__).parent / "fixtures"


async def handle_rss(request: web.Request) -> web.Response:
    feed_name = request.match_info["feed_name"]
    xml_path = FIXTURES_DIR / f"{feed_name}.xml"
    if not xml_path.exists():
        return web.Response(status=404, text=f"Feed not found: {feed_name}")
    return web.Response(
        text=xml_path.read_text(encoding="utf-8"),
        content_type="application/xml",
    )


async def handle_health(request: web.Request) -> web.Response:
    return web.Response(text="OK")


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/health", handle_health)
    app.router.add_get("/rss/{feed_name}.xml", handle_rss)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="0.0.0.0", port=18888)
