"""Optional SDK Streamable HTTP transport, restricted to loopback bindings."""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from contextlib import asynccontextmanager


def validate_host(host: str) -> str:
    if host == "localhost":
        return host
    try:
        if ipaddress.ip_address(host).is_loopback:
            return host
    except ValueError:
        pass
    raise ValueError(
        "MCP HTTP is restricted to loopback; use an authenticated proxy for remote access"
    )


def create_app(configuration, host: str = "127.0.0.1"):
    """Create stateful MCP sessions with separate database leases and artifacts."""
    validate_host(host)
    try:
        from mcp import types
        from mcp.server.lowlevel import Server
        from mcp.server.lowlevel.helper_types import ReadResourceContents
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
        from mcp.server.transport_security import TransportSecuritySettings
        from starlette.applications import Starlette
        from starlette.routing import Mount
    except ImportError as error:
        raise RuntimeError(
            "Install ida-mcp-stdio[http] to enable HTTP transport"
        ) from error
    from . import __version__
    from .server import INSTRUCTIONS, StdioMCPServer

    @asynccontextmanager
    async def database_session(_):
        server = StdioMCPServer(
            backend=configuration.backend_name,
            tool_profile=configuration.tool_profile,
            max_workers=configuration.max_workers,
            session_log=configuration.session.log_path,
            agent=configuration.session.agent,
            inline_limit=configuration.session.inline_limit,
        )
        if configuration.binary_path:
            await asyncio.to_thread(
                server.manager.open_database, str(configuration.binary_path)
            )
        try:
            yield {"database_server": server}
        finally:
            await asyncio.to_thread(server._shutdown)

    mcp = Server(
        "ida-mcp-stdio",
        version=__version__,
        instructions=INSTRUCTIONS,
        lifespan=database_session,
    )

    def current():
        return mcp.request_context.lifespan_context["database_server"]

    @mcp.list_tools()
    async def list_tools():
        result = current()._handle_tools_list(0)["result"]["tools"]
        return [types.Tool(**tool) for tool in result]

    @mcp.call_tool()
    async def call_tool(name: str, arguments: dict):
        server = current()
        request_id = uuid.uuid4().hex
        server.prepare_request(request_id)
        task = asyncio.create_task(
            asyncio.to_thread(
                server._handle_tools_call,
                request_id,
                {"name": name, "arguments": arguments},
            )
        )
        try:
            response = await asyncio.shield(task)
        except asyncio.CancelledError:
            server.cancel_request(request_id)
            raise
        if "error" in response:
            return types.CallToolResult(
                content=[
                    types.TextContent(type="text", text=response["error"]["message"])
                ],
                isError=True,
            )
        return types.CallToolResult(**response["result"])

    @mcp.list_resources()
    async def list_resources():
        return [
            types.Resource(**resource)
            for resource in current().session.list_resources()
        ]

    @mcp.read_resource()
    async def read_resource(uri):
        page = current().session.read_resource(str(uri))["contents"][0]
        return [ReadResourceContents(content=page["text"], mime_type=page["mimeType"])]

    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
        allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
    )
    manager = StreamableHTTPSessionManager(
        mcp, json_response=True, security_settings=security
    )

    @asynccontextmanager
    async def lifespan(_):
        async with manager.run():
            yield

    return Starlette(
        routes=[Mount("/mcp", app=manager.handle_request)], lifespan=lifespan
    )


def serve(configuration, host: str = "127.0.0.1", port: int = 8737) -> None:
    app = create_app(configuration, host)
    try:
        import uvicorn
    except ImportError as error:
        raise RuntimeError(
            "Install ida-mcp-stdio[http] to enable HTTP transport"
        ) from error
    try:
        uvicorn.run(app, host=host, port=port)
    finally:
        configuration._shutdown()
