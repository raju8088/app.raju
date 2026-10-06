import argparse
from http.server import ThreadingHTTPServer
from pathlib import Path

from omnidim_ui import config
from omnidim_ui.db import init_db
from omnidim_ui.handlers import AppHandler
from omnidim_ui.logging_config import logger, setup_logging


def main():
    parser = argparse.ArgumentParser(description="OmniDimension Control Center Local Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8787, help="Port to bind (default: 8787)")
    parser.add_argument("--db", type=str, default=None, help="Custom path to SQLite database")
    parser.add_argument(
        "--read-only",
        action="store_true",
        help="Run in read-only mode (all mutating API operations blocked)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable detailed debug logging",
    )
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)

    if args.read_only:
        config.READ_ONLY_MODE = True
        logger.warning("Starting server in READ-ONLY mode. Mutating actions will be rejected.")

    if args.db:
        config.DB_PATH = Path(args.db).resolve()
        logger.info("Using custom database path: %s", config.DB_PATH)

    init_db()

    server = ThreadingHTTPServer((args.host, args.port), AppHandler)
    logger.info("OmniDimension Control Center running at http://%s:%d", args.host, args.port)
    logger.info("Local Auth Token configured (pass via X-Local-Token header or cookie)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down server gracefully...")
    finally:
        server.server_close()
        logger.info("Server closed.")


if __name__ == "__main__":
    main()
