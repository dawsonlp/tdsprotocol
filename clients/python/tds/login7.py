"""LOGIN7 (log in): who the client is, how to authenticate it, and how it wants the session set up.

Reference: LOGIN7. Checked against MS-TDS v20260617, §2.2.6.4.
"""

import enum

from .wire import Field, I32, Pointer, PointerTable, Raw, Reader, Struct, Type, U8, U32, Writer

TDS_7_4 = 0x74000004  # LOGIN7 writes it little-endian (04 00 00 74), and LOGINACK writes it big-endian (74 00 00 04)


def tds_version_name(value: int) -> str:
    return f"TDS {value >> 28}.{(value >> 24) & 0xF}"


class OptionFlags1(enum.IntFlag):
    BIG_ENDIAN_CLIENT = 0x01
    EBCDIC = 0x02
    BULK_LOAD_OFF = 0x10
    REPORT_DATABASE_CHANGES = 0x20
    INITIAL_DATABASE_MUST_SUCCEED = 0x40
    REPORT_LANGUAGE_CHANGES = 0x80


class OptionFlags2(enum.IntFlag):
    INITIAL_LANGUAGE_MUST_SUCCEED = 0x01
    ODBC_CLIENT = 0x02
    WINDOWS_AUTH = 0x80


class TypeFlags(enum.IntFlag):
    TSQL_DIALECT = 0x01
    OLEDB_CLIENT = 0x10
    READ_ONLY_INTENT = 0x20


class OptionFlags3(enum.IntFlag):
    CHANGE_PASSWORD = 0x01
    BINARY_XML = 0x02
    USER_INSTANCE = 0x04
    UNKNOWN_COLLATION_HANDLING = 0x08
    FEATURE_LIST_PRESENT = 0x10


class Feature(enum.IntEnum):
    """Features that a login can request in its feature list, with the names that MS-TDS uses (D-8).
    connect(features=…) takes a list of them. The default is DEFAULT_FEATURES."""

    SESSION_RECOVERY = 0x01
    FEDERATED_AUTH = 0x02
    COLUMN_ENCRYPTION = 0x04
    GLOBAL_TRANSACTIONS = 0x05
    AZURE_SQL_SUPPORT = 0x08
    DATA_CLASSIFICATION = 0x09
    UTF8_SUPPORT = 0x0A
    AZURE_DNS_CACHING = 0x0B
    JSON_SUPPORT = 0x0D
    VECTOR_SUPPORT = 0x0E
    ENHANCED_ROUTING = 0x0F
    USER_AGENT = 0x10



FEATURES_END = 0xFF
JSON_SUPPORT_VERSION = 1  # the json data type
VECTOR_SUPPORT_VERSION = 2  # vectors of float32 and float16


REQUEST = {  # what the driver sends for each feature it implements: the version it reads (D-8)
    Feature.JSON_SUPPORT: bytes([JSON_SUPPORT_VERSION]),
    Feature.VECTOR_SUPPORT: bytes([VECTOR_SUPPORT_VERSION]),
    Feature.UTF8_SUPPORT: b"\x01",  # invalid stored UTF-8 bytes arrive as stored, not replaced (D-48)
    Feature.DATA_CLASSIFICATION: b"\x02",  # version 2, which includes sensitivity ranks
    Feature.COLUMN_ENCRYPTION: b"\x01",  # version 1: Always Encrypted without enclaves (D-60). It is
    # requested by tds.encryption, which can decrypt what it changes. tds.encryption asks for version 2 for enclaves
    Feature.SESSION_RECOVERY: b"",  # no data, which means “recover this session if it breaks” (D-57). A
    # recovery login sends the session's state instead (session.RECOVERY)
    # Azure SQL's features (M18) are requested to observe what each one changes. None is a default until that is known.
    Feature.AZURE_SQL_SUPPORT: b"\x01",  # bit 0: failover partner login with read-only intent
    Feature.AZURE_DNS_CACHING: b"",
    Feature.ENHANCED_ROUTING: b"",
    Feature.GLOBAL_TRANSACTIONS: b"",
}

NOT_YET = {  # features that the driver can't request yet, with the reason and when (D-8)
    Feature.FEDERATED_AUTH: "it is the login's own: connect(login=EntraToken(…)) or connect(login=EntraLogin(…)) "
                            "adds it (D-55)",
    Feature.USER_AGENT: "the driver leaves it out: SQL Server ignores it, and identifies the driver already (D-8)",
}

DEFAULT_FEATURES = (Feature.JSON_SUPPORT, Feature.VECTOR_SUPPORT, Feature.UTF8_SUPPORT, Feature.DATA_CLASSIFICATION,
                    Feature.SESSION_RECOVERY)


def result_context(features: dict) -> dict:
    """Accepted wire settings needed to read later results, live or on replay."""
    utf8 = features.get(Feature.UTF8_SUPPORT)
    context = {"utf8_support": bool(utf8 and utf8[0] & 1)}
    encryption = features.get(Feature.COLUMN_ENCRYPTION)
    if encryption:
        context["column_encryption"] = encryption[0]
        if encryption[0] >= 2 and len(encryption) > 1:
            context["enclave_type"] = bytes(encryption[2:2 + 2 * encryption[1]]).decode("utf-16-le")
    classification = features.get(Feature.DATA_CLASSIFICATION)
    if classification:
        context["data_classification_version"] = classification[0]
    return context


def feature_list(features, data: dict | None = None) -> dict:
    """The login's feature list for these features. Each feature has the data that the driver sends, unless data is
    given. The caller gives data as (feature, data), or through `data` (a recovery login's session, D-57). A feature
    that the driver can't read yet is refused with the reason and when."""
    out = {}
    for f in features:
        given = None
        if isinstance(f, tuple):  # (feature, its data): the caller chooses the data (a version, for tds.encryption)
            f, given = f
        f = Feature(f)
        if f in NOT_YET:
            raise ValueError(f"the login can't ask for {f.name} yet: {NOT_YET[f]}")
        out[f] = (data or {}).get(f, given if given is not None else REQUEST[f])
    return out


class FeatureList(Type):
    """Features, one after another, then FF. Each feature is an id (u8), its data's length (u32) and its data. A login
    points to its list through the extension entry (MS-TDS §2.2.6.4). The server answers with the same layout in
    FEATUREEXTACK."""

    composite = True

    def read(self, r: Reader) -> dict:
        features = {}
        while r.peek() != FEATURES_END:
            feature = r.read(Field("feature", U8, enum=Feature))
            n = r.read(Field("length", U32, fmt=lambda v: f"{v} bytes"))
            features[feature] = bytes(r.read(Field("data", Raw(n))))
        r.read(Field("end", U8, fmt=lambda v: "end of the list"))
        return features

    def write(self, w: Writer, features: dict) -> None:
        for feature, data in features.items():
            w.write(Field("feature", U8, enum=Feature), feature)
            w.write(Field("length", U32, fmt=lambda v: f"{v} bytes"), len(data))
            w.write(Field("data", Raw()), data)
        w.write(Field("end", U8, fmt=lambda v: "end of the list"), FEATURES_END)

    def show(self, features: dict) -> str:
        return " · ".join(f"{Feature(f).name.lower().replace('_', ' ') if f in Feature._value2member_map_ else f}"
                          + (f" {data[0]}" if len(data) == 1 else "") for f, data in features.items())


def scramble(data: bytes) -> bytes:
    """Passwords are obscured, not protected (TLS protects them). Swap each byte's halves, then XOR with A5."""
    return bytes((((b << 4) | (b >> 4)) & 0xFF) ^ 0xA5 for b in data)


def unscramble(data: bytes) -> bytes:
    return bytes(((((b ^ 0xA5) << 4) | ((b ^ 0xA5) >> 4)) & 0xFF) for b in data)


LOGIN7 = Struct("LOGIN7", [
    # fixed part
    Field("length", U32, total=True, fmt=lambda v: f"{v} bytes"),
    Field("tds_version", U32, fmt=tds_version_name),
    Field("packet_size", U32),
    Field("client_library_version", U32, fmt=lambda v: f"{v:#010x}"),
    Field("client_process_id", U32),
    Field("connection_id", U32),
    Field("option_flags_1", U8, enum=OptionFlags1),
    Field("option_flags_2", U8, enum=OptionFlags2),
    Field("type_flags", U8, enum=TypeFlags),
    Field("option_flags_3", U8, enum=OptionFlags3),
    Field("time_zone", I32),
    Field("locale", U32, fmt=lambda v: f"{v:#06x}"),
    # the pointer table, then the data part that it points to
    Field("variable_part", PointerTable([
        Pointer("host_name"),
        Pointer("user_name"),
        Pointer("password", sensitive=True, encode=scramble, decode=unscramble),
        Pointer("app_name"),
        Pointer("server_name"),
        Pointer("extension", unit=1),  # points to the feature list, when one is sent
        Pointer("library_name"),
        Pointer("language"),
        Pointer("database"),
        Field("client_id", Raw(6)),
        Pointer("windows_auth", unit=1, sensitive=True),  # a Windows login's first token, which is a credential
        Pointer("attach_file"),
        Pointer("new_password", sensitive=True, encode=scramble, decode=unscramble),
        Field("large_windows_auth_length", U32),
    ])),
    Field("features", Raw()),  # the feature list, when one is sent. The extension entry holds its offset.
], source="§2.2.6.4",
    summary=lambda l: (f"user {l.variable_part.user_name}" if l.variable_part.user_name else
                       "Windows login" if l.option_flags_2 & OptionFlags2.WINDOWS_AUTH else "no user name: a token login")
                      + f" · app {l.variable_part.app_name} · {tds_version_name(l.tds_version)}"
                      f" · ODBC flag {'on' if OptionFlags2.ODBC_CLIENT in l.option_flags_2 else 'off'}")


def login(values: dict, features: dict, record: bool = True):
    """Encode a LOGIN7 with a feature list. The extension entry holds the list's offset (4 bytes), so the login is
    encoded once to find where the list starts, then again with that offset."""
    if not features:
        return LOGIN7.encode({**values, "features": b""}, record)
    values = {**values, "option_flags_3": values["option_flags_3"] | OptionFlags3.FEATURE_LIST_PRESENT}
    first, _ = LOGIN7.encode({**values, "features": b"",
                              "variable_part": {**values["variable_part"], "extension": bytes(4)}}, False)
    listed, _ = Struct("features", [Field("list", FeatureList())]).encode({"list": features}, False)
    body, node = LOGIN7.encode({**values, "features": listed,
                                "variable_part": {**values["variable_part"], "extension": len(first).to_bytes(4, "little")}},
                               record)
    if node is not None and Feature.FEDERATED_AUTH in features:  # its token is a credential: the list is shown by length only
        for child in node.children:
            if child.name == "features":
                child.sensitive = True
    return body, node
