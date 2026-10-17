"""tds: a TDS 7.4 and 8.0 client. Its code teaches the protocol, and while it runs it shows what it does.

Read in this order: packet → prelogin → login7 → tokens → requests → response → connection/core.
The design is in docs/design.
"""

from .connection.core import ConnectError, LoginRejected, OutOfTurn, Routed, SerialChannelMisuse, SessionNotRecovered
from .connection.shell import Connection, Pool, SerialChannel, connect
from . import browser, transactions, types
from .login7 import DEFAULT_FEATURES, Feature
from .logins import EntraLogin, EntraToken, WindowsLogin, Workflow
from .requests import DEFAULT, Batch, BulkInsert, BulkRows, Builtin, Call, CallOptions, Calls, Param
from .response import (Cancelled, FetchedResponse, NotYetRead, Response, ResultSet, RowsNotAvailable, ServerError,
                       StreamedRow, Unread, ValueStream)

__all__ = ["connect", "Pool", "Connection", "SerialChannel", "Batch", "Call", "Calls", "Param", "Builtin", "CallOptions",
           "BulkInsert", "BulkRows", "transactions", "browser", "Feature", "DEFAULT_FEATURES", "WindowsLogin", "EntraToken", "EntraLogin", "Workflow",
           "DEFAULT", "types", "Response", "FetchedResponse", "ResultSet", "StreamedRow", "ValueStream",
           "Unread", "ServerError", "Cancelled", "NotYetRead", "RowsNotAvailable",
           "ConnectError", "LoginRejected", "Routed", "SessionNotRecovered", "SerialChannelMisuse", "OutOfTurn"]
