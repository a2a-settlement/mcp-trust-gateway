"""Entry point for the MCP Trust Gateway."""

from __future__ import annotations

import sys


def main() -> None:
    from .config import get_gateway_host, get_gateway_port
    from .server import create_app

    import uvicorn

    app = create_app()
    uvicorn.run(app, host=get_gateway_host(), port=get_gateway_port())


if __name__ == "__main__":
    main()
