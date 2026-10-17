"""Generate tds/collations.py from a running SQL Server (D-44).

The file says which code page each collation's varchar bytes are in, and where SQL Server reads or writes those bytes
differently from Python's codec for the same code page.

    uv run python tools/generate_collations.py --trust-server-certificate     # the local SQL Server 2025 container

MS-TDS has no such table, so the server is the authority. Run this script again for each new SQL Server version, and
review the diff.
The password comes from MSSQL_SA_PASSWORD, or else docker/macos/.env, as for the command-line tool. It is never printed.

How each code page is measured. Every single byte is stored in a varchar column under one of the code page's
collations, exactly as given. For the double-byte code pages, so is every pair with a lead byte of 0x81 or more and a
trail byte of 0x40 or more. Sequences that the server changes when they are stored are left out, because the server
can't hold them. For the other sequences, the server reports the characters it reads, and the bytes it writes when those
characters are stored back. A sequence whose characters the server writes back as the same bytes is *canonical*. Any
other sequence (a duplicate encoding, or a byte the server reads as a default character) is carried as escapes, so that
it too is sent back exactly (D-48).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tds  # noqa: E402
from tds.__main__ import find_env_file, read_env_file  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "tds" / "collations.py"
DOUBLE_BYTE = (932, 936, 949, 950)
NUMBERS = "SELECT TOP 256 ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS n FROM sys.all_objects"
SINGLES = f"SELECT CAST(CAST(n AS tinyint) AS binary(1)) FROM ({NUMBERS}) AS d"
PAIRS = (f"SELECT CAST(CAST(a.n AS tinyint) AS binary(1)) + CAST(CAST(b.n AS tinyint) AS binary(1)) "
         f"FROM ({NUMBERS}) AS a CROSS JOIN ({NUMBERS}) AS b WHERE a.n >= 0x81 AND b.n >= 0x40")


async def fetch(channel, sql: str) -> tds.FetchedResponse:
    async with await channel.exchange(tds.Batch(sql)) as response:
        return await response.fetch()


async def rows(channel, sql: str) -> tuple:
    return (await fetch(channel, sql)).result_sets[0].rows


async def measure(channel, collation: str, sequences: str) -> list[tuple[bytes, str, bytes]]:
    """(bytes, the characters the server reads, the bytes it writes those characters back as), for every sequence the
    server holds as given."""
    got = await rows(channel, f"""
        SET NOCOUNT ON;
        DECLARE @t TABLE (b varbinary(2), v varchar(2) COLLATE {collation});
        INSERT @t SELECT b, b FROM ({sequences}) AS s(b);
        DELETE @t WHERE CAST(v AS varbinary(2)) <> b OR DATALENGTH(v) <> DATALENGTH(b);  -- binary = pads with zeros
        DECLARE @u TABLE (b varbinary(2), back varchar(2) COLLATE {collation});
        INSERT @u SELECT b, CAST(v AS nvarchar(2)) FROM @t;
        SELECT t.b, CAST(t.v AS nvarchar(2)), CAST(u.back AS varbinary(2)) FROM @t AS t JOIN @u AS u ON u.b = t.b AND DATALENGTH(u.b) = DATALENGTH(t.b)""")
    return [(bytes(b), text, bytes(back)) for b, text, back in got]


def python_reads(data: bytes, page: int) -> str | None:
    try:
        return data.decode(f"cp{page}")
    except UnicodeDecodeError:
        return None


def python_writes(text: str, page: int) -> bytes | None:
    try:
        return text.encode(f"cp{page}")
    except UnicodeEncodeError:
        return None


def runs(pairs: list[tuple[bytes, str]]) -> list[tuple[str, int, int]]:
    """(first sequence, how many, first code point): consecutive sequences read as consecutive characters."""
    out: list[list] = []
    for data, text in sorted(pairs, key=lambda p: (len(p[0]), p[0])):
        n, cp = int.from_bytes(data, "big"), ord(text)
        if out and len(bytes.fromhex(out[-1][0])) == len(data):
            first, count, first_cp = out[-1]
            if int(first, 16) + count == n and first_cp + count == cp:
                out[-1][1] += 1
                continue
        out.append([data.hex().upper(), 1, cp])
    return [tuple(r) for r in out]


def ranges(values: list[int]) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for v in sorted(values):
        if out and out[-1][1] + 1 == v:
            out[-1][1] = v
        else:
            out.append([v, v])
    return [tuple(r) for r in out]


async def generate(args: argparse.Namespace, password: str) -> str:
    connection = await tds.connect(args.host, args.port, user=args.user, password=password,
                                   trust_server_certificate=args.trust_server_certificate)
    async with connection:
        async with connection.serial_channel() as channel:
            await fetch(channel, "SET ANSI_WARNINGS ON; SET ARITHABORT ON")  # errors, not NULLs, if anything overflows
            version = connection.server.server_version
            server = f"{version.major}.{version.minor}.{version.build}"
            catalogue = await rows(channel, """
                SELECT name, CAST(COLLATIONPROPERTY(name, 'LCID') AS int), CAST(COLLATIONPROPERTY(name, 'SortID') AS int),
                       CAST(COLLATIONPROPERTY(name, 'CodePage') AS int)
                FROM sys.fn_helpcollations()""")
            print(f"SQL Server {server}: {len(catalogue)} collations", file=sys.stderr)

            sorts: dict[int, set[int]] = {}
            locales: dict[int, set[int]] = {}
            examples: dict[int, str] = {}
            for name, lcid, sort_id, page in catalogue:
                if name.endswith("_UTF8"):
                    if page != 65001:
                        raise SystemExit(f"{name}: a UTF-8 collation whose code page is {page}")
                    continue
                (sorts if sort_id else locales).setdefault(sort_id or lcid, set()).add(page)
                if page:
                    examples.setdefault(page, name)
            for table, what in ((sorts, "sort id"), (locales, "locale id")):
                for key, pages in table.items():
                    if len(pages) != 1:
                        raise SystemExit(f"{what} {key} maps to more than one code page: {sorted(pages)}")

            leads, characters, escaped, server_bytes = {}, {}, {}, {}
            for page, collation in sorted(examples.items()):
                measured = await measure(channel, collation, SINGLES)
                if page in DOUBLE_BYTE:
                    measured += await measure(channel, collation, PAIRS)
                pair_leads, read, escape, writes = set(), [], [], {}
                for data, text, back in measured:
                    if len(text) != 1:
                        continue  # not one character: the decoder takes these bytes one at a time
                    if len(data) == 2:
                        pair_leads.add(data[0])
                    if back == data:  # canonical: the server reads this character, and writes it back as these bytes
                        if python_reads(data, page) != text:
                            read.append((data, text))  # an override for the decoder; its inverse is one for the encoder
                        elif python_writes(text, page) != data:
                            # Python reads these bytes correctly, but writes the character as other bytes
                            writes[ord(text)] = data
                    elif python_reads(data, page) is not None:
                        # Python would read it as a character that the server writes differently
                        escape.append(data.hex().upper())
                leads[page] = ranges(list(pair_leads)) if page in DOUBLE_BYTE else []
                characters[page], escaped[page] = runs(read), sorted(escape)
                server_bytes[page] = [(cp, n, first) for first, n, cp in runs([(b, chr(c)) for c, b in writes.items()])]
                print(f"  cp{page:<5} {collation:<34} {len(measured):>6} sequences held · {len(read)} read differently from "
                      f"Python · {len(escape)} carried as escapes · {len(writes)} more written differently", file=sys.stderr)

    def table(name: str, comment: str, body: dict, show) -> list[str]:
        out = [f"# {comment}", f"{name} = {{"]
        for page, entries in sorted(body.items()):
            if entries:
                out.append(f"    {page}: {show(entries)},")
        return out + ["}", ""]

    lines = [
        '"""Collations: which code page a collation\'s varchar bytes are in, and where SQL Server reads or writes those bytes',
        "differently from Python's codec for the same code page. GENERATED by tools/generate_collations.py: don't edit by",
        "hand; regenerate, and review the diff.",
        "",
        "Reference: Data Types › Collation. Decisions: D-44, D-48. MS-TDS has no such table: the server is the authority.",
        "",
        f"Generated from SQL Server {server}.",
        '"""',
        "",
        f'SERVER = "{server}"',
        "",
        "# SQL collations (sort id not 0): sort id → code page.",
        "SORT_CODE_PAGES = {",
        *[f"    {k}: {next(iter(v))}," for k, v in sorted(sorts.items())],
        "}",
        "",
        "# Windows collations (sort id 0): locale id → code page. 0 means Unicode only: no varchar, unless the collation is UTF-8.",
        "LOCALE_CODE_PAGES = {",
        *[f"    {k:#06x}: {next(iter(v))}," for k, v in sorted(locales.items())],
        "}",
        "",
        *table("LEAD_BYTES", "Double-byte code pages: the bytes that start a two-byte character, as (first, last) ranges.",
               leads, lambda r: "[" + ", ".join(f"({a:#04x}, {b:#04x})" for a, b in r) + "]"),
        *table("SERVER_CHARACTERS", "Sequences the server reads as a character Python's codec doesn't give: (first "
               "sequence, how many, first code point),\n# consecutive sequences reading as consecutive characters.",
               characters, lambda r: "[\n" + "".join(f'        ("{a}", {n}, {c:#06x}),\n' for a, n, c in r) + "    ]"),
        *table("ESCAPED", "Sequences the server holds but writes back differently (duplicate encodings, default "
               "characters):\n# Python would read them as a character, so they are listed to be carried as escapes.",
               escaped, lambda r: "[\n" + "".join(f"        {' '.join(chunk)!r},\n" for chunk in
                                                   (r[i : i + 12] for i in range(0, len(r), 12))) + "    ]"),
        *table("SERVER_BYTES", "Characters the server writes as other bytes than Python's codec does, beyond SERVER_CHARACTERS'\n"
               "# own (which are written back as read): (first code point, how many, first sequence).",
               server_bytes, lambda r: "[\n" + "".join(f'        ({c:#06x}, {n}, "{a}"),\n' for c, n, a in r) + "    ]"),
    ]
    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=14325)
    p.add_argument("--user", default="sa")
    p.add_argument("--trust-server-certificate", action="store_true")
    p.add_argument("--password-var", default="MSSQL_SA_PASSWORD")
    args = p.parse_args()
    password = os.environ.get(args.password_var) or read_env_file(find_env_file(), args.password_var)
    if not password:
        sys.exit(f"no password: set {args.password_var}")
    OUT.write_text(asyncio.run(generate(args, password)))
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
