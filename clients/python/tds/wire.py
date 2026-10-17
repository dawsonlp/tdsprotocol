"""Machinery: how bytes become values, and values become bytes.

This module holds the value types (integers, text, byte strings), the small vocabulary that the
definition files are written in (Field, Struct, Directory, PointerTable, Repeat, OneOf,
Token, TokenStream), and the one engine that reads and writes them while building the
inspection tree that observability shows.

It holds no protocol knowledge, such as tag values, field names or message types. Those are
in the definition files. Every bounds check is here.
"""

import enum
from contextlib import contextmanager
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Callable


class MalformedMessage(Exception):
    """The bytes don't match the definition. It carries the offset where reading failed, and the partial tree."""

    def __init__(self, what: str, offset: int, tree: Node | None = None):
        super().__init__(f"{what} (at byte {offset:#x})")
        self.what, self.offset, self.tree = what, offset, tree


class Incomplete(Exception):
    """Reading went past the bytes received so far, in a message whose later packets haven't arrived yet.
    This is not an error. The reader tries again when more bytes have arrived."""


# --------------------------------------------------------------------------- inspection tree

KEPT = 8192  # an inspection node keeps at most this many of its bytes, so a large value is never held whole (D-47)


def kept(data: bytes) -> bytes:
    return bytes(data[:KEPT])


@dataclass
class Node:
    """One entry in the inspection tree: a field, or a group of fields."""

    name: str
    start: int
    end: int = 0
    raw: bytes = b""
    shown: str = ""
    children: list[Node] = dataclass_field(default_factory=list)
    source: str | None = None  # MS-TDS section of the definition
    sensitive: bool = False

    def find(self, *names: str) -> Node:
        """The node at a path of names. Each name matches a child's name, or the start of it. For example:
        event.node.find("login reply", "LOGINACK", "tds version"). Every byte of a message can be reached this way."""
        node = self
        for name in names:
            node = next((c for c in node.children if c.name == name), None) \
                or next((c for c in node.children if c.name.startswith(name)), None)
            if node is None:
                raise KeyError(f"no {name!r} under this node")
        return node


class Record(dict):
    """Decoded values that can also be read as attributes, such as reply.encryption and ack.tds_version."""

    token = ""  # for tokens, which token it is (LOGINACK, DONE, …)
    node: Node | None = None

    def __getattr__(self, key: str) -> Any:
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key) from None


def as_record(values: Any) -> Any:
    """Converts plain nested dicts (as callers write them) to Records, so summaries can read them the same way."""
    if isinstance(values, dict):
        rec = Record({k: as_record(v) for k, v in values.items()})
        return rec
    return values


# --------------------------------------------------------------------------- reader & writer


class _Recorder:
    """What Reader and Writer share: building the inspection tree while they work."""

    def __init__(self, record: bool):
        self.record = record
        self._stack: list[Node] = [Node("root", 0)]
        self.values: list[Record] = []  # values of the structures being read, innermost last
        self.context: dict[str, Any] = {}  # facts that later fields depend on (for example, a result's columns)
        self.places: list[str] = []  # where the writer is, as structures name it ("parameter @a"), outermost first

    @property
    def tree(self) -> Node:
        return self._stack[0]

    def _add(self, node: Node) -> None:
        if self.record:
            self._stack[-1].children.append(node)

    @contextmanager
    def group(self, name: str, source: str | None = None):
        node = Node(name, self.pos, source=source)
        self._add(node)
        self._stack.append(node)
        try:
            yield node
        finally:
            self._stack.pop()
            node.end = self.pos
            node.raw = kept(self._bytes()[node.start : min(node.end, node.start + KEPT)])

    def _leaf(self, f: Field, start: int, shown: str) -> Node | None:
        if not self.record:
            return None
        node = Node(f.label, start, self.pos, kept(self._bytes()[start : min(self.pos, start + KEPT)]), shown,
                    sensitive=f.sensitive)
        self._add(node)
        return node


class Reader(_Recorder):
    """Reads definitions from bytes. It refuses to read past the end of the bytes that it was given.

    `complete=False` means more of the message may still arrive. Reading past the end of the bytes (outside any
    length-limited element) then raises Incomplete instead of MalformedMessage, so the caller can wait and try again.
    """

    def __init__(self, data: bytes, record: bool = True, complete: bool = True):
        super().__init__(record)
        self.data, self.pos, self.end = data, 0, len(data)
        self.complete = complete
        self._limits = 0  # how many length-limited elements the reader is inside

    def _bytes(self) -> bytes:
        return self.data

    def _short(self, what: str) -> Exception:
        if not self.complete and self._limits == 0:
            return Incomplete(what)
        return MalformedMessage(what, self.pos, self.tree)

    def take(self, n: int, what: str) -> bytes:
        if n < 0:
            raise MalformedMessage(f"{what} needs {n} bytes", self.pos, self.tree)
        if self.pos + n > self.end:
            raise self._short(f"{what} needs {n} bytes, {self.end - self.pos} left")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def peek(self) -> int:
        if self.pos >= self.end:
            raise self._short("expected another byte")
        return self.data[self.pos]

    def seek(self, to: int, what: str) -> None:
        if not 0 <= to <= self.end:
            raise MalformedMessage(f"{what} points outside the message ({to:#x})", self.pos, self.tree)
        self.pos = to

    @contextmanager
    def limit(self, n: int, what: str):
        """The next n bytes belong to one element, which must use exactly those bytes."""
        if n < 0:
            raise MalformedMessage(f"{what} claims {n} bytes", self.pos, self.tree)
        if self.pos + n > self.end:
            raise self._short(f"{what} claims {n} bytes, {self.end - self.pos} left")
        outer, self.end = self.end, self.pos + n
        self._limits += 1
        try:
            yield
        finally:
            self._limits -= 1
        if self.pos != self.end:
            raise MalformedMessage(f"{what} left {self.end - self.pos} bytes unread", self.pos, self.tree)
        self.end = outer

    def read(self, f: Field) -> Any:
        t = f.type.resolve(self)
        start = self.pos
        if t.composite:
            with self.group(f.label) as node:
                value = f.convert(t.read(self))
            node.shown = f.show(value, t)
            node.sensitive = f.sensitive
            return value
        value = f.convert(t.read(self))
        self._leaf(f, start, f.show(value, t))
        return value


class Writer(_Recorder):
    """Writes definitions to bytes."""

    def __init__(self, record: bool = True):
        super().__init__(record)
        self.buf = bytearray()

    def _bytes(self) -> bytes:
        return self.buf

    @property
    def pos(self) -> int:
        return len(self.buf)

    def put(self, data: bytes) -> None:
        self.buf += data

    def patch(self, at: int, t: Int, value: int) -> None:
        self.buf[at : at + t.size] = t.pack(value)

    def write(self, f: Field, value: Any) -> Node | None:
        t = f.type.resolve(self)
        start = self.pos
        if t.composite:
            with self.group(f.label) as node:
                t.write(self, value)
            node.shown = f.show(value, t)
            node.sensitive = f.sensitive
            return node
        t.write(self, value)
        return self._leaf(f, start, f.show(value, t))


# --------------------------------------------------------------------------- value types


class Type:
    """How one kind of value is laid out in bytes."""

    composite = False  # True if it is made of named parts that appear in the inspection tree

    def resolve(self, rw: _Recorder) -> Type:
        return self

    def read(self, r: Reader) -> Any:
        raise NotImplementedError

    def write(self, w: Writer, value: Any) -> None:
        raise NotImplementedError

    def show(self, value: Any) -> str:
        return "" if self.composite else str(value)  # a group shows only its own summary, never its values


class Int(Type):
    def __init__(self, size: int, order: str = "little", signed: bool = False):
        self.size, self.order, self.signed = size, order, signed

    def pack(self, value: int) -> bytes:
        return int(value).to_bytes(self.size, self.order, signed=self.signed)

    def read(self, r: Reader) -> int:
        return int.from_bytes(r.take(self.size, "integer"), self.order, signed=self.signed)

    def write(self, w: Writer, value: int) -> None:
        w.put(self.pack(value))


U8, U16, U32, U64 = Int(1), Int(2), Int(4), Int(8)
I32 = Int(4, signed=True)
U16BE, U32BE = Int(2, "big"), Int(4, "big")


class Raw(Type):
    """Bytes shown as hex. With a size, exactly that many bytes. Without a size, everything up to the current limit."""

    def __init__(self, size: int | None = None):
        self.size = size

    def read(self, r: Reader) -> bytes:
        return bytes(r.take(r.end - r.pos if self.size is None else self.size, "bytes"))

    def write(self, w: Writer, value: bytes) -> None:
        w.put(bytes(value))

    def show(self, value: bytes) -> str:
        return value.hex(" ").upper() if value else "(empty)"


class Text(Type):
    """UTF-16LE text. With a count type, it is prefixed by its length in UTF-16 code units. Without one, it is
    everything up to the limit. Unpaired surrogates are kept, because SQL Server's text can hold them."""

    def __init__(self, count: Int | None = None):
        self.count = count

    def read(self, r: Reader) -> str:
        n = self.count.read(r) * 2 if self.count else r.end - r.pos
        return bytes(r.take(n, "text")).decode("utf-16-le", "surrogatepass")

    def write(self, w: Writer, value: str) -> None:
        data = value.encode("utf-16-le", "surrogatepass")
        if self.count:
            self.count.write(w, len(data) // 2)
        w.put(data)

    def show(self, value: str) -> str:
        return f"“{value.rstrip(chr(0))}”" if value else "(empty)"


class Blob(Type):
    """Bytes prefixed by their length."""

    def __init__(self, count: Int):
        self.count = count

    def read(self, r: Reader) -> bytes:
        return bytes(r.take(self.count.read(r), "bytes"))

    def write(self, w: Writer, value: bytes) -> None:
        self.count.write(w, len(value))
        w.put(value)

    def show(self, value: bytes) -> str:
        return value.hex(" ").upper() if value else "(empty)"


# --------------------------------------------------------------------------- the definition vocabulary


@dataclass
class Field:
    """A named, typed value. The label shown to people is the name with spaces: tds_version → “tds version”."""

    name: str
    type: Type
    enum: type[enum.Enum] | None = None
    sensitive: bool = False  # never shown, as value or bytes, by observability
    total: bool = False  # filled in when writing: the length of the structure that this field opens
    fmt: Callable[[Any], str] | None = None  # how to show the value, if not the type's way

    @property
    def label(self) -> str:
        return self.name.replace("_", " ")

    def convert(self, value: Any) -> Any:
        if self.enum is not None and isinstance(value, int):
            try:
                return self.enum(value)
            except ValueError:
                return value
        return value

    def show(self, value: Any, resolved: Type | None = None) -> str:
        if self.sensitive:
            return "•••• (hidden)"
        if self.fmt:
            return self.fmt(value)
        if isinstance(value, enum.Flag):
            return " · ".join(m.name.lower().replace("_", " ") for m in type(value) if m in value and m.value) or "none"
        if isinstance(value, enum.Enum):
            return value.name.lower().replace("_", " ")
        if self.enum is not None and isinstance(value, int):
            return f"unknown ({value:#x})"
        return (resolved or self.type).show(value)


class Struct(Type):
    """Fields in order. Most structures and tokens are only this."""

    composite = True

    def __init__(self, name: str, fields: list[Field], source: str | None = None,
                 summary: Callable[[Record], str] | None = None, where: Callable[[dict], str] | None = None):
        self.name, self.fields, self.source, self.summary = name, fields, source, summary
        self.where = where  # names this structure's place, for errors raised while writing it (literate errors)

    def read(self, r: Reader) -> Record:
        rec = Record()
        r.values.append(rec)
        try:
            for f in self.fields:
                rec[f.name] = r.read(f)
        finally:
            r.values.pop()
        return rec

    def write(self, w: Writer, rec: dict) -> None:
        start, totals = w.pos, []
        w.values.append(rec)
        place = self.where(rec) if self.where else None
        if place:
            w.places.append(place)
        try:
            for f in self.fields:
                if f.total:
                    totals.append((w.pos, f, w.write(f, 0)))
                else:
                    w.write(f, rec[f.name])
        except Exception as e:
            if place and hasattr(e, "within"):  # an error that says where it happened (ValueRefused)
                e.within(place)
            raise
        finally:
            w.values.pop()
            if place:
                w.places.pop()
        for at, f, node in totals:  # lengths are known only after everything is written
            w.patch(at, f.type, w.pos - start)
            if node is not None:
                node.raw, node.shown = bytes(w.buf[at : at + f.type.size]), f.show(w.pos - start)

    def show(self, rec: dict) -> str:
        return self.summary(as_record(rec)) if self.summary else ""

    def decode(self, data: bytes, record: bool = True, context: dict | None = None) -> Record:
        """Read a whole message body as this structure. `context` holds facts that fields may need while reading,
        such as which request a reply answers."""
        r = Reader(data, record)
        r.context.update(context or {})
        with r.group(self.name, self.source) as node:
            rec = self.read(r)
        if r.pos != r.end:
            raise MalformedMessage(f"{r.end - r.pos} bytes after the end of {self.name}", r.pos, r.tree)
        node.shown = self.show(rec)
        rec.node = node
        return rec

    def encode(self, values: dict, record: bool = True, context: dict | None = None) -> tuple[bytes, Node]:
        """Write a whole message body as this structure. Returns the bytes and their inspection tree. `context` holds
        facts that fields may need while writing, such as a request's collation."""
        w = Writer(record)
        w.context.update(context or {})
        with w.group(self.name, self.source) as node:
            self.write(w, values)
        node.shown = self.summary(as_record(values)) if self.summary else ""
        return bytes(w.buf), node


class OneOf(Type):
    """A value whose layout depends on an earlier field of the same structure: OneOf('kind', {...})."""

    def __init__(self, on: str, layouts: dict[Any, Type]):
        self.on, self.layouts = on, layouts

    def resolve(self, rw: _Recorder) -> Type:
        key = rw.values[-1][self.on]
        if key not in self.layouts:
            raise MalformedMessage(f"no layout known for {self.on} = {key!r}", rw.pos, rw.tree)
        return self.layouts[key]


class When(Type):
    """A value that is present only when an earlier value says so. `test` is given the reader or writer, whose
    `values` and `context` hold what came before. When absent, it reads as None and writes nothing."""

    def __init__(self, test: Callable[[_Recorder], bool], inner: Type):
        self.test, self.inner = test, inner
        self.composite = inner.composite

    def read(self, r: Reader) -> Any:
        return self.inner.read(r) if self.test(r) else None

    def write(self, w: Writer, value: Any) -> None:
        if value is not None:
            self.inner.write(w, value)

    def show(self, value: Any) -> str:
        return "(absent)" if value is None else self.inner.show(value)


class Repeat(Type):
    """A list whose length was given by an earlier field. `none` is a count value that means “no list”."""

    composite = True

    def __init__(self, count_field: str | None, item: Type, none: int | None = None, stop_at: bytes = b""):
        self.count_field, self.item, self.none = count_field, item, none  # no count field: up to the current limit,
        self.stop_at = stop_at  # or up to a byte that ends the list (a separator that follows it)

    def read(self, r: Reader) -> list:
        if self.count_field is None:
            items = []
            while r.pos < r.end and r.peek() not in self.stop_at:
                items.append(r.read(Field(self._label(len(items)), self.item)))
            return items
        n = r.values[-1][self.count_field]
        if n == self.none:
            return []
        return [r.read(Field(self._label(i), self.item)) for i in range(n)]

    def write(self, w: Writer, items: list) -> None:
        for i, item in enumerate(items):
            w.write(Field(self._label(i), self.item), item)

    def _label(self, i: int) -> str:
        return f"{getattr(self.item, 'name', 'item')} {i + 1}"

    def show(self, items: list) -> str:
        return f"{len(items)} item{'' if len(items) == 1 else 's'}"


class Separated(Type):
    """Items one after another with a one-byte separator between them, to the end of the message."""

    composite = True

    def __init__(self, item: Type, separator: int, name: str = "item"):
        self.item, self.separator, self.name = item, separator, name

    def read(self, r: Reader) -> list:
        items = [r.read(Field(f"{self.name} 1", self.item))]
        while r.pos < r.end:
            r.read(Field("separator", U8))
            items.append(r.read(Field(f"{self.name} {len(items) + 1}", self.item)))
        return items

    def write(self, w: Writer, items: list) -> None:
        for i, item in enumerate(items):
            if i:
                w.write(Field("separator", U8, fmt=lambda v: f"{v:#04x}"), self.separator)
            w.write(Field(f"{self.name} {i + 1}", self.item), item)

    def show(self, items: list) -> str:
        return f"{len(items)} {self.name}{'' if len(items) == 1 else 's'}"


class Prefixed(Type):
    """A value preceded by its own length in bytes."""

    composite = True

    def __init__(self, length: Int, inner: Struct):
        self.length, self.inner = length, inner

    def read(self, r: Reader) -> Record:
        n = r.read(Field("length", self.length))
        with r.limit(n, self.inner.name):
            return self.inner.read(r)

    def write(self, w: Writer, rec: dict) -> None:
        at = w.pos
        w.write(Field("length", self.length), 0)
        self.inner.write(w, rec)
        w.patch(at, self.length, w.pos - at - self.length.size)

    def show(self, rec: Record) -> str:
        return self.inner.show(rec)


class Directory(Type):
    """An option directory: (option, offset, length) entries ending in a terminator, then the values they point to.
    Offsets count from where the directory starts. Unknown options are skipped."""

    composite = True

    def __init__(self, option: Int, offset: Int, length: Int, terminator: int, options: dict[int, Field]):
        self.option, self.offset, self.length, self.terminator, self.options = option, offset, length, terminator, options

    def _name(self, option: int) -> str:
        return self.options[option].label if option in self.options else f"option {option:#x}"

    def read(self, r: Reader) -> Record:
        base, entries, rec = r.pos, [], Record()
        with r.group("directory"):
            while r.peek() != self.terminator:
                with r.group("entry") as entry:
                    option = r.read(Field("option", self.option, fmt=self._name))
                    at = r.read(Field("offset", self.offset, fmt=lambda v: f"{v:#x} in body"))
                    size = r.read(Field("length", self.length, fmt=lambda v: f"{v} byte{'' if v == 1 else 's'}"))
                entry.name, entry.shown = self._name(option), f"{size} byte{'' if size == 1 else 's'} at {at:#x}"
                entries.append((option, at, size))
            r.read(Field("end", self.option, fmt=lambda v: "end of directory"))
        with r.group("data"):
            for option, at, size in entries:
                if size == 0:
                    continue  # an empty option has no value (for example, the server's thread id)
                r.seek(base + at, f"the {self._name(option)} entry")
                with r.limit(size, self._name(option)):
                    f = self.options.get(option, Field(f"option_{option:x}", Raw()))
                    rec[f.name] = r.read(f)
        return rec

    def write(self, w: Writer, rec: dict) -> None:
        present = [(option, f) for option, f in self.options.items() if f.name in rec]
        sizes = []
        for _, f in present:  # first pass: how long each value is
            probe = Writer(record=False)
            probe.write(f, rec[f.name])
            sizes.append(probe.pos)
        at = len(present) * (self.option.size + self.offset.size + self.length.size) + self.option.size
        with w.group("directory"):
            for (option, f), size in zip(present, sizes):
                with w.group(f.label) as entry:
                    entry.shown = f"{size} byte{'' if size == 1 else 's'} at {at:#x}"  # as the reader shows it
                    w.write(Field("option", self.option, fmt=self._name), option)
                    w.write(Field("offset", self.offset, fmt=lambda v: f"{v:#x} in body"), at)
                    w.write(Field("length", self.length, fmt=lambda v: f"{v} byte{'' if v == 1 else 's'}"), size)
                at += size
            w.write(Field("end", self.option, fmt=lambda v: "end of directory"), self.terminator)
        with w.group("data"):
            for _, f in present:
                w.write(f, rec[f.name])


@dataclass
class Pointer:
    """An entry in a pointer table: an offset and a length pointing into the data that follows the table."""

    name: str
    unit: int = 2  # bytes per unit of length: 2 for text (lengths count characters), 1 for bytes
    sensitive: bool = False
    encode: Callable[[bytes], bytes] | None = None  # applied to the bytes when writing (for example, scrambling)
    decode: Callable[[bytes], bytes] | None = None  # and reversed when reading

    @property
    def label(self) -> str:
        return self.name.replace("_", " ")


class PointerTable(Type):
    """(offset u16, length u16) pointers, mixed with fields stored inline, then the data that the pointers point to.
    Offsets count from the start of the message body. Values are text (unit 2) or bytes (unit 1)."""

    composite = True

    def __init__(self, entries: list[Pointer | Field]):
        self.entries = entries

    def _value(self, p: Pointer, data: bytes) -> Any:
        if p.decode:
            data = p.decode(data)
        return data.decode("utf-16-le") if p.unit == 2 else data

    def _show(self, p: Pointer, value: Any) -> str:
        if p.sensitive:
            return "•••• (hidden)"
        return (f"“{value}”" if value else "(empty)") if p.unit == 2 else (value.hex(" ").upper() or "(empty)")

    def read(self, r: Reader) -> Record:
        rec, pointers = Record(), []
        with r.group("pointer table"):
            for e in self.entries:
                if isinstance(e, Field):
                    rec[e.name] = r.read(e)
                    continue
                at = r.read(Field(f"{e.name}_offset", U16, fmt=lambda v: f"{v:#x} in body"))
                n = r.read(Field(f"{e.name}_length", U16, fmt=lambda v, u=e.unit: f"{v} {'characters' if u == 2 else 'bytes'}"))
                pointers.append((e, at, n))
        end = r.pos
        with r.group("data part"):
            for p, at, n in pointers:
                if n == 0:
                    rec[p.name] = "" if p.unit == 2 else b""
                    continue
                r.seek(at, f"the {p.label} offset")
                start = r.pos
                rec[p.name] = self._value(p, bytes(r.take(n * p.unit, p.label)))
                if r.record:
                    r._add(Node(p.label, start, r.pos, bytes(r.data[start:r.pos]), self._show(p, rec[p.name]), sensitive=p.sensitive))
                end = max(end, r.pos)
        r.seek(end, "the data part")
        return rec

    def write(self, w: Writer, rec: dict) -> None:
        def data_of(p: Pointer) -> bytes:
            value = rec.get(p.name) or ("" if p.unit == 2 else b"")
            raw = value.encode("utf-16-le") if p.unit == 2 else bytes(value)
            return p.encode(raw) if p.encode else raw

        size = sum(2 * U16.size if isinstance(e, Pointer) else _size_of(e, rec[e.name]) for e in self.entries)
        at = w.pos + size  # the data part starts immediately after the table
        pointers = []
        with w.group("pointer table"):
            for e in self.entries:
                if isinstance(e, Field):
                    w.write(e, rec[e.name])
                    continue
                data = data_of(e)
                w.write(Field(f"{e.name}_offset", U16, fmt=lambda v: f"{v:#x} in body"), at)
                w.write(Field(f"{e.name}_length", U16, fmt=lambda v, u=e.unit: f"{v} {'characters' if u == 2 else 'bytes'}"), len(data) // e.unit)
                pointers.append((e, data))
                at += len(data)
        with w.group("data part"):
            for p, data in pointers:
                if data:
                    start = w.pos
                    w.put(data)
                    if w.record:
                        w._add(Node(p.label, start, w.pos, data, self._show(p, rec.get(p.name)), sensitive=p.sensitive))


def _size_of(f: Field, value: Any) -> int:
    probe = Writer(record=False)
    probe.write(f, value)
    return probe.pos


# --------------------------------------------------------------------------- token streams


@dataclass
class Token:
    """A token: a 1-byte tag, then a body. If `length` is set, the body is length-prefixed. If it is not set,
    the body's own fields decide where it ends (fixed size, or read field by field). `remember` stores a field for
    later tokens to use. `beyond_length`, given the body's first byte, says when the length doesn't cover the body.
    The body's own fields then decide where it ends."""

    tag: int
    name: str
    body: Struct
    length: Int | None = None
    remember: str | None = None
    source: str | None = None
    beyond_length: Callable[[int], bool] | None = None


class TokenStream:
    """Tokens one after another with no separators. Each tag's definition decides where its token ends."""

    def __init__(self, tokens: list[Token]):
        self.tokens = {t.tag: t for t in tokens}

    def decode(self, data: bytes, record: bool = True, context: dict | None = None) -> list[Record]:
        """Read a whole token stream that has fully arrived."""
        r = Reader(data, record)
        if context:
            r.context.update(context)
        out = []
        while r.pos < r.end:
            out.append(self.read_one(r))
        return out

    def read_one(self, r: Reader) -> Record:
        """Read the next token. Raises Incomplete if reading goes past the bytes received so far (see Reader)."""
        tag = r.peek()
        token = self.tokens.get(tag)
        if token is None:
            raise MalformedMessage(f"unknown token tag {tag:#04x}: without its length rule the rest can't be read", r.pos, r.tree)
        with r.group(token.name, token.source) as node:
            r.read(Field("tag", U8, fmt=lambda v, n=token.name: n))
            if token.length is not None:
                n = r.read(Field("length", token.length, fmt=lambda v: f"{v} bytes follow"))
                if token.beyond_length is not None and token.beyond_length(r.peek()):
                    rec = token.body.read(r)
                else:
                    with r.limit(n, token.name):
                        rec = token.body.read(r)
            else:
                rec = token.body.read(r)
        rec.token, rec.node = token.name, node
        node.shown = token.body.show(rec)
        if token.remember:
            r.context[token.remember] = rec[token.remember]
        return rec
