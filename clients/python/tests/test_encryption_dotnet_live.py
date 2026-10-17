"""Always Encrypted, pass 2 (M15, D-61).

Microsoft's SqlClient reads what the driver wrote, by INSERT and by bulk load, and the driver reads what SqlClient
wrote. This holds for every type the driver can encrypt, deterministic and randomized, with lookups in both directions.

SqlClient runs in Microsoft's .NET SDK image, in the SQL Server container's network (AeCheck in tests/dotnet, with a
key store provider for the driver's local key files). Values cross between the two as exact text: floats as their
bits, times as 100-nanosecond ticks, binary as hex, and text as hex of its UTF-16 code units. The test needs docker.
The first run downloads SqlClient into a docker volume.
"""

import asyncio
import json
import os
import shutil
import struct
import subprocess
import uuid
from decimal import Decimal
from pathlib import Path

import datetime as dt
import pytest

import tds
from conftest import fetch
from test_encryption_live import TYPES, ae, encrypted, executesql, store  # noqa: F401 (ae is a fixture)
from tds import types
from tds.types import SqlDateTime, SqlDateTimeOffset, SqlDateTime2, SqlTime

pytestmark = pytest.mark.live

RUN = Path(__file__).parent / "dotnet" / "run.sh"
def as_sqlclient_has_it(v):
    """SqlClient decodes and encodes UTF-16 with replacement, whether encrypted or not. An unpaired surrogate becomes
    U+FFFD. The driver keeps it (D-48)."""
    if isinstance(v, str):
        return v.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
    return v


SQLCLIENT_CANT_WRITE = {  # SqlClient's limits, not the driver's: its writes are refused, but its reads are checked
    "time(0)": "Operand type clash: time(7) encrypted",  # to SqlClient, a Scale of 0 means "unset", so it sends time(7)
}


def text(kind: str, value):
    """A value as exact text, as AeCheck reads and writes it."""
    if value is None:
        return None
    match kind:
        case "bit":
            return "1" if value else "0"
        case "real":
            return struct.pack(">f", value).hex()
        case "float":
            return struct.pack(">d", value).hex()
        case "time":
            return str(value.ticks)
        case "datetime2":
            return f"{value.date.isoformat()}|{value.ticks}"
        case "datetimeoffset":
            return f"{value.utc_date.isoformat()}|{value.utc_ticks}|{value.offset_minutes}"
        case "datetime":
            return f"{value.days}|{value.ticks}"
        case "smalldatetime":
            return value.strftime("%Y-%m-%dT%H:%M")
        case "date":
            return value.isoformat()
        case "decimal" | "numeric" | "money" | "smallmoney":
            return format(value, "f")  # never 1E-10
        case "binary" | "varbinary":
            return value.hex()
        case "char" | "varchar" | "nchar" | "nvarchar":
            return value.encode("utf-16-le", "surrogatepass").hex()  # code units: unpaired surrogates cross too
    return str(value)


def value(kind: str, text: str | None):
    """Exact text from AeCheck, as the driver's value."""
    if text is None:
        return None
    match kind:
        case "tinyint" | "smallint" | "int" | "bigint":
            return int(text)
        case "bit":
            return text == "1"
        case "real":
            return struct.unpack(">f", bytes.fromhex(text))[0]
        case "float":
            return struct.unpack(">d", bytes.fromhex(text))[0]
        case "decimal" | "numeric" | "money" | "smallmoney":
            return Decimal(text)
        case "date":
            return dt.date.fromisoformat(text)
        case "time":
            return SqlTime(int(text))
        case "datetime2":
            day, ticks = text.split("|")
            return SqlDateTime2(dt.date.fromisoformat(day), int(ticks))
        case "datetimeoffset":
            day, ticks, offset = text.split("|")
            return SqlDateTimeOffset(dt.date.fromisoformat(day), int(ticks), int(offset))
        case "datetime":
            days, ticks = text.split("|")
            return SqlDateTime(int(days), int(ticks))
        case "smalldatetime":
            return dt.datetime.strptime(text, "%Y-%m-%dT%H:%M")
        case "uniqueidentifier":
            return uuid.UUID(text)
        case "binary" | "varbinary":
            return bytes.fromhex(text)
        case "char" | "varchar" | "nchar" | "nvarchar":
            return bytes.fromhex(text).decode("utf-16-le", "surrogatepass")
    return text


def case(i: int, declared: str, sql_type) -> dict:
    kind = declared.split("(")[0]
    size = getattr(sql_type, "length", None)
    size = -1 if size is types.MAX else size
    return {"table": f"t{i}", "kind": kind, "size": size, "precision": getattr(sql_type, "precision", None),
            "scale": getattr(sql_type, "scale", None) if kind in ("decimal", "numeric", "time", "datetime2", "datetimeoffset") else None}


@pytest.mark.skipif(shutil.which("docker") is None, reason="needs docker, for .NET's SqlClient")
def test_sqlclient_and_the_driver_read_each_others_values(ae, server):
    options, encryption = ae
    cases = [case(i, declared, sql_type) for i, (declared, sql_type, _, _) in enumerate(TYPES)]

    async def write():
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                for c, (declared, sql_type, collation, values) in zip(cases, TYPES):
                    for side in ("py", "pyb", "net"):
                        await fetch(channel, f"CREATE TABLE dbo.{side}_{c['table']} (id int NOT NULL, "
                                             f"{encrypted('d', declared, 'DETERMINISTIC', collation)}, "
                                             f"{encrypted('r', declared, 'RANDOMIZED', collation)})")
                    for i, v in enumerate([*values, None]):
                        await fetch(channel, executesql(f"INSERT dbo.py_{c['table']} VALUES (@id, @d, @r)",
                                                        f"@id int, @d {declared}, @r {declared}",
                                                        tds.Param("@id", types.int, i), tds.Param("@d", sql_type, v),
                                                        tds.Param("@r", sql_type, v)))
                    columns = (await fetch(channel, f"SELECT TOP 0 id, d, r FROM dbo.pyb_{c['table']}")).result_sets[0].columns
                    cipher = columns[1].type.cipher
                    await fetch(channel, tds.BulkInsert(f"INSERT BULK dbo.pyb_{c['table']} (id int NOT NULL, d {cipher}, r {cipher})"))
                    await fetch(channel, tds.BulkRows(columns, [(i, v, v) for i, v in enumerate([*values, None])]))

    async def read():
        found = []
        async with await encryption.connect(**options) as connection:
            async with connection.serial_channel() as channel:
                for c, (declared, sql_type, _, values) in zip(cases, TYPES):
                    rows = (await fetch(channel, f"SELECT d, r FROM dbo.net_{c['table']} ORDER BY id")).result_sets[0].rows
                    ids = [(await fetch(channel, executesql(f"SELECT id FROM dbo.net_{c['table']} WHERE d = @d",
                                                            f"@d {declared}", tds.Param("@d", sql_type, v)))).result_sets[0].rows
                           for v in values]
                    found.append((rows, ids))
        return found

    asyncio.run(write())
    spec = {"database": options["database"], "read": ["py", "pyb"],
            "cases": [{**c, "values": [text(c["kind"], v) for v in values]} for c, (_, _, _, values) in zip(cases, TYPES)]}
    ran = subprocess.run([str(RUN), str(store().directory)], input=json.dumps(spec), capture_output=True, text=True,
                         env={**os.environ, "TDS_PASSWORD": "" + server["password"]}, timeout=900)
    assert ran.returncode == 0, ran.stderr[-3000:]
    dotnet = json.loads(ran.stdout.strip().splitlines()[-1])["cases"]
    read_back = asyncio.run(read())

    for c, (declared, _, _, values), result, (rows, ids) in zip(cases, TYPES, dotnet, read_back):
        expected = [as_sqlclient_has_it(v) for v in [*values, None]]
        same = [as_sqlclient_has_it(v) == v for v in values]  # a value SqlClient changes encrypts differently, so a
        # lookup for it on one side finds nothing written by the other
        for prefix, how in (("py", "inserted"), ("pyb", "bulk-loaded")):
            assert [(value(c["kind"], d), value(c["kind"], r)) for d, r in result["read"][prefix]] == \
                [(v, v) for v in expected], f"SqlClient read the driver's {how} {declared} differently"
            assert result["lookup"][prefix] == [[i] if same[i] else [] for i in range(len(values))], \
                f"SqlClient's lookups in the driver's {how} {declared}"
        if declared in SQLCLIENT_CANT_WRITE:
            assert SQLCLIENT_CANT_WRITE[declared] in result["error"]
            continue
        assert "error" not in result, f"{declared}: {result['error']}"
        assert rows == tuple((v, v) for v in expected), f"the driver read SqlClient's {declared} differently"
        assert ids == [((i,),) if same[i] else () for i in range(len(values))], \
            f"the driver's lookups in SqlClient's {declared}"
