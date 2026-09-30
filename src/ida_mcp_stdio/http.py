"""Optional SDK Streamable HTTP transport, restricted to loopback bindings."""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar


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
        import anyio
        from mcp import types
        from mcp.server.lowlevel import Server
        from mcp.server.lowlevel.helper_types import ReadResourceContents
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
        from mcp.server.transport_security import TransportSecuritySettings
        from mcp.shared.message import SessionMessage
        from starlette.applications import Starlette
        from starlette.routing import Mount
    except ImportError as error:
        raise RuntimeError(
            "Install ida-mcp-stdio[http] to enable HTTP transport"
        ) from error
    from . import __version__
    from .server import INSTRUCTIONS, StdioMCPServer

    connection_context = ContextVar("ida_mcp_http_connection")
    session_log = configuration.session.log_path

    @asynccontextmanager
    async def database_session(_):
        connection = connection_context.get()
        server = StdioMCPServer(
            backend=configuration.backend_name,
            tool_profile=configuration.tool_profile,
            max_workers=configuration.max_workers,
            agent=configuration.session.agent,
            inline_limit=configuration.session.inline_limit,
            idle_timeout=configuration.idle_timeout,
        )
        connection["server"] = server
        if session_log is not None:
            server.session.log_path = session_log.with_name(
                f"{session_log.stem}-{server.session.session_id}{session_log.suffix}"
            )

        def notify(message):
            if connection["closed"] or connection["loop"].is_closed():
                return
            notification = SessionMessage(types.JSONRPCMessage.model_validate(message))
            coroutine = connection["writer"].send(notification)
            try:
                future = asyncio.run_coroutine_threadsafe(coroutine, connection["loop"])
            except RuntimeError:
                coroutine.close()
                return

            def completed(result):
                if not result.cancelled():
                    result.exception()

            future.add_done_callback(completed)

        server.set_notification_sink(notify)
        try:
            if configuration.binary_path:
                await asyncio.to_thread(
                    server.manager.open_database, str(configuration.binary_path)
                )
            yield {"database_server": server}
        finally:
            server.set_notification_sink(None)
            with anyio.CancelScope(shield=True):
                await asyncio.to_thread(server._shutdown)

    class HTTPServer(Server):
        async def run(
            self, read_stream, write_stream, initialization_options, **options
        ):
            # The SDK handles initialize before its application request callbacks.
            # Observe its public streams so lifecycle output is bound from startup.
            connection = {
                "writer": write_stream,
                "loop": asyncio.get_running_loop(),
                "initialize": {},
                "closed": False,
            }
            token = connection_context.set(connection)
            sender, receiver = anyio.create_memory_object_stream(0)

            async def forward():
                async with read_stream, sender:
                    async for message in read_stream:
                        if (
                            isinstance(message, SessionMessage)
                            and isinstance(message.message.root, types.JSONRPCRequest)
                            and message.message.root.method == "initialize"
                        ):
                            connection["initialize"] = message.message.root.params or {}
                        await sender.send(message)

            try:
                async with anyio.create_task_group() as tasks:
                    tasks.start_soon(forward)
                    try:
                        await super().run(
                            receiver, write_stream, initialization_options, **options
                        )
                    finally:
                        connection["closed"] = True
                        tasks.cancel_scope.cancel()
            finally:
                connection_context.reset(token)

    mcp = HTTPServer(
        "ida-mcp-stdio",
        version=__version__,
        instructions=INSTRUCTIONS,
        lifespan=database_session,
    )

    async def initialized(_):
        connection = connection_context.get()
        server = connection["server"]
        if not server._initialized:
            server._handle_initialize(None, connection["initialize"])

    mcp.notification_handlers[types.InitializedNotification] = initialized

    def current():
        context = mcp.request_context
        server = context.lifespan_context["database_server"]
        if not server._initialized:
            params = context.session.client_params
            server._handle_initialize(
                None,
                params.model_dump(by_alias=True, exclude_none=True) if params else {},
            )
        return server

    @mcp.set_logging_level()
    async def set_logging_level(level):
        current()._logging_level = level

    @mcp.list_tools()
    async def list_tools():
        result = current()._handle_tools_list(0)["result"]["tools"]
        return [types.Tool(**tool) for tool in result]

    @mcp.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict):
        server = current()
        request_id = uuid.uuid4().hex
        meta = mcp.request_context.meta
        metadata = (
            meta.model_dump(by_alias=True, exclude_none=True)
            if meta is not None
            else {}
        )
        server.prepare_request(request_id)
        task = asyncio.create_task(
            asyncio.to_thread(
                server._handle_tools_call,
                request_id,
                {"name": name, "arguments": arguments, "_meta": metadata},
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
