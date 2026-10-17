"""tds: run the client from the command line. It connects, logs in, runs a query, shows the conversation and closes.

    uv run tds --ca-file ../../docker/macos/tls/test-ca.pem                       # SELECT 1 against the local SQL Server 2025
    uv run tds --ca-file ../../docker/macos/tls/test-ca.pem --tds-version 8.0     # TLS first (TDS 8.0)
    uv run tds --ca-file ../../docker/macos/tls/test-ca.pem --observe full        # every message opened to its fields and bytes
    uv run tds --ca-file ../../docker/macos/tls/test-ca.pem --mars --channels 2   # two serial channels on one connection

The certificate is verified (D-10). --ca-file trusts the authority that signed it. Here that is the test container's
authority (docker/macos/tls/make-test-certificates.sh). Without --ca-file, the system's trusted authorities are used.

The password comes from an environment variable (default MSSQL_SA_PASSWORD), or otherwise from the
.env file that docker/macos/compose*.yaml use. It is never printed.
"""

import argparse
import asyncio
import os
import ssl
import sys
from pathlib import Path

from . import Batch, ConnectError, FetchedResponse, SerialChannelMisuse, ServerError, connect
from .login7 import DEFAULT_FEATURES, REQUEST
from .observe import Level, Printer

REQUESTABLE = tuple(REQUEST)  # the features the driver can request, each with its own switch
from .wire import MalformedMessage


def main() -> None:
    p = argparse.ArgumentParser(prog="tds", description="Connect, log in, run a query, and show the conversation.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=14325, help="default: the SQL Server 2025 container")
    p.add_argument("--user", default="sa")
    p.add_argument("--database", default="")
    p.add_argument("--query", default="SELECT 1")
    p.add_argument("--observe", choices=[l.value for l in Level], default="outline")
    p.add_argument("--mars", action="store_true", help="open serial channels as MARS sessions")
    p.add_argument("--no-odbc", dest="odbc", action="store_false",
                   help="log in without the ODBC flag: the server's own session defaults (TEXTSIZE 4,096 bytes)")
    p.add_argument("--channels", type=int, default=1, help="serial channels to open (more than 1 needs --mars)")
    p.add_argument("--ca-file", type=Path, help="trust the certificate authority in this PEM file (D-10)")
    p.add_argument("--server-hostname", help="the name the server's certificate carries, if not --host")
    p.add_argument("--tds-version", choices=["7.4", "8.0"], default="7.4", help="8.0: TLS first, always encrypted")
    p.add_argument("--app-name", default="tds (python)", help="the session's program_name, as administrators see it")
    p.add_argument("--host-name", help="this machine's name, as administrators see it (default: the real one)")
    p.add_argument("--language", default="", help="the session's language (default: the login's own)")
    p.add_argument("--read-only-intent", action="store_true",
                   help="tell an availability group the connection only reads (a routing hint: writes still work)")
    features = p.add_argument_group("login features (D-8)", "each one on or off; the defaults are tds.DEFAULT_FEATURES")
    for feature in REQUESTABLE:
        on = feature in DEFAULT_FEATURES
        features.add_argument(f"--{feature.name.lower().replace('_', '-')}", dest=feature.name, default=on,
                              action=argparse.BooleanOptionalAction, help=f"(default: {'on' if on else 'off'})")
    p.add_argument("--password-var", default="MSSQL_SA_PASSWORD")
    p.add_argument("--env-file", type=Path, help="default: the nearest docker/macos/.env above this directory")
    p.add_argument("--timeout", type=float, default=15.0, help="connection timer, in seconds")
    args = p.parse_args()
    if args.read_only_intent:
        print("note: --read-only-intent is a routing hint for availability groups, not a restriction. The session is "
              "not read-only: writes still work, unless the server it reaches is a read-only replica.", file=sys.stderr)

    password = os.environ.get(args.password_var) or read_env_file(args.env_file or find_env_file(), args.password_var)
    if not password:
        sys.exit(f"no password: set {args.password_var}, or pass --env-file")
    try:
        asyncio.run(run(args, password))
    except (ConnectError, ServerError, SerialChannelMisuse, MalformedMessage, OSError, TimeoutError) as e:
        sys.exit(f"error: {type(e).__name__}: {e}")


async def run(args: argparse.Namespace, password: str) -> None:
    level = Level(args.observe)
    connection = await connect(args.host, args.port, user=args.user, password=password, database=args.database,
                               mars=args.mars, odbc=args.odbc, tds_version=args.tds_version,
                               ssl_context=ssl.create_default_context(cafile=args.ca_file) if args.ca_file else None,
                               server_hostname=args.server_hostname,
                               features=[f for f in REQUESTABLE if getattr(args, f.name)], app_name=args.app_name,
                               host_name=args.host_name, language=args.language, read_only_intent=args.read_only_intent,
                               timeout=args.timeout, observe=Printer(level) if level is not Level.OFF else None)
    async with connection:
        channels = [connection.serial_channel() for _ in range(args.channels)]
        for channel in channels:
            async with await channel.exchange(Batch(args.query)) as response:
                try:
                    fetched = await response.fetch()
                except ServerError as e:
                    fetched = e.response
            show(args.query, fetched, channel.id if args.mars else None)
        for channel in channels:
            await channel.close()


def show(query: str, response: FetchedResponse, channel: int | None) -> None:
    """Print the response's record in order: result sets as tables, then each completion, message and error."""
    print(f"\n{query}" + (f"   (serial channel {channel})" if channel is not None else ""))
    for item in response.sequence:
        match type(item).__name__:
            case "ResultSet":
                names = [c.name or "(no name)" for c in item.columns]
                rows = [["NULL" if v is None else str(v) for v in row] for row in item.rows]
                widths = [max([len(n), *(len(r[i]) for r in rows)]) for i, n in enumerate(names)]
                print("  " + "  ".join(n.ljust(w) for n, w in zip(names, widths)))
                print("  " + "  ".join("-" * w for w in widths))
                for r in rows:
                    print("  " + "  ".join(v.ljust(w) for v, w in zip(r, widths)))
            case "Completion":
                count = "count not valid" if item.rows is None else f"{item.rows} row{'s' if item.rows != 1 else ''}"
                print(f"  ({count} · {item.kind.value} · statement code {item.statement})")
            case "Message":
                print(f"  message {item.number}: {item.text}")
            case "Error":
                print(f"  error {item.number} (severity {item.severity}): {item.text}")


def find_env_file() -> Path | None:
    for folder in [Path.cwd(), *Path.cwd().parents]:
        candidate = folder / "docker" / "macos" / ".env"
        if candidate.exists():
            return candidate
    return None


def read_env_file(path: Path | None, name: str) -> str | None:
    if path is None or not path.exists():
        return None
    for line in path.read_text().splitlines():
        key, _, value = line.partition("=")
        if key.strip() == name:
            return value.strip()
    return None


if __name__ == "__main__":
    main()
