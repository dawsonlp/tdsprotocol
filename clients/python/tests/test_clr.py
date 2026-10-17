"""CLR types (M7), checked against the core alone.

A column's type description names the type and its assembly. A parameter names the type. Values are the type's
serialized bytes, as PLP (D-43).
"""

from tds import types
from tds.types import MAX, TypeInfo, ValueRefused
from tds.wire import Field, Reader, Writer

import pytest


def text(value: str, width: int = 1) -> bytes:
    return (len(value)).to_bytes(width, "little") + value.encode("utf-16-le")


def test_a_columns_clr_type_names_the_type_and_its_assembly():
    assembly = "Microsoft.SqlServer.Types.SqlGeometry, Microsoft.SqlServer.Types, Version=11.0.0.0"
    data = b"\xf0\xff\xff" + text("master") + text("sys") + text("geometry") + text(assembly, 2)
    sql_type = Reader(data, False).read(Field("type", TypeInfo()))
    assert str(sql_type) == "master.sys.geometry" and sql_type.assembly == assembly and sql_type.max_size is MAX
    assert sql_type.large  # values come as PLP


def test_a_parameter_names_its_clr_type_and_sends_bytes_as_plp():
    w = Writer(record=False)
    types.hierarchyid.write_info(w)
    types.hierarchyid.write_value(w, b"\x5b\xc0")
    assert bytes(w.buf) == (b"\xf0" + text("") + text("sys") + text("hierarchyid")
                            + (2).to_bytes(8, "little") + (2).to_bytes(4, "little") + b"\x5b\xc0" + bytes(4))


def test_clr_names_and_values():
    assert types.clr("dbo.Point") == types.Clr("", "dbo", "Point") and str(types.clr("shop.dbo.Point")) == "shop.dbo.Point"
    with pytest.raises(ValueError):
        types.clr("Point")
    with pytest.raises(ValueRefused):
        types.geography.check("POINT (1 2)")  # its serialized bytes, not text. An outer layer turns text into shapes.
