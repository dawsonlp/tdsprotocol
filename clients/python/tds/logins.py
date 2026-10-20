"""How a connection proves its identity: the ways to log in, and what each takes from the application (D-55).

Reference: Conversations › Login; Connect. Checked against MS-TDS v20260617, §2.2.6.4 (LOGIN7 and its FEDAUTH feature),
§2.2.6.3 (the federated authentication token), §2.2.7.12 (FEDAUTHINFO), §2.2.7.22 (SSPI).

  SQL Server login      user and password, in LOGIN7: connect(user=…, password=…). An expired password is changed
                        during the login: connect(…, new_password=…).
  Windows login         Kerberos or NTLM. The client and the server exchange tokens: the first in LOGIN7, then one
                        answer to each of the server's challenges (SSPI), until the server accepts the login.
                        connect(login=WindowsLogin(…)).
  Entra ID, in advance  an access token in LOGIN7's federated authentication feature: connect(login=EntraToken(…)).
  Entra ID, mid-login   the login says that a token will follow. The server says where to get one (FEDAUTHINFO: its
                        token endpoint and the resource the token is for). The client fetches the token and sends it.
                        connect(login=EntraLogin(…)).

The driver carries each exchange of tokens as TDS defines it, and does nothing else. The tokens come from the
application: from a library it chooses, through an adapter (tds.adapters), or from its own code. Each connection,
including routed and recovered connections, begins its own exchange of tokens.
"""

import enum
from dataclasses import dataclass, field, replace
from typing import Any, Awaitable, Callable, Protocol

MAX_TOKEN = 48 * 1024  # driver resource limits, not TDS protocol maxima
MAX_ROUNDS = 8         # includes the initial provider step
MAX_LOGIN_MESSAGE = 64 * 1024


def _redact_authentication(node):
    """Copy an inspection tree without SSPI payloads or ancestor raw copies.

    Decoded records used by the provider remain untouched. Safe sibling fields
    such as LOGINACK remain inspectable even when they share the same message.
    """
    def visit(item, hidden=False):
        hidden = hidden or item.name == "SSPI"
        children = [visit(child, hidden) for child in item.children]
        contains = hidden or any(secret for _, secret in children)
        return (replace(item, raw=bytes(len(item.raw)) if contains else item.raw,
                        shown="authentication payload hidden" if hidden else item.shown,
                        children=[child for child, _ in children]), contains)
    return visit(node)[0] if node is not None else None


class SecurityExchange(Protocol):
    """One Windows login's exchange of tokens with the server: Kerberos, NTLM, or SPNEGO choosing between them."""

    def step(self, challenge: bytes | None) -> bytes | None | Awaitable[bytes | None]:
        """The next token. Given None, it returns the first token, for LOGIN7. Given the server's challenge, it
        returns the answer to it. It returns None or b"" when there is nothing more to send."""

    # Optional: `complete`, a bool read after the login reply's steps. If it is False when the server accepts the
    # login, the login is refused (H1). Providers without it are accepted as before.


class SecurityProvider(Protocol):
    """What a Windows login takes: an object that begins an exchange of tokens with a server, one per connection."""

    def begin(self, host: str, port: int) -> SecurityExchange: ...


@dataclass(frozen=True)
class WindowsLogin:
    """Kerberos or NTLM: connect(login=WindowsLogin(provider)). The provider chooses which, and whose credentials."""

    provider: SecurityProvider


Token = str | Callable[[], str | Awaitable[str]]


@dataclass(frozen=True)
class EntraToken:
    """An Entra ID access token for https://database.windows.net/, sent in the login. It is the token itself, or a
    function that gives one. The function is called for each connection, so that a pool's connections and routed
    connections get a current token."""

    token: Token = field(repr=False)


class Workflow(enum.IntEnum):
    """What the login tells the server about how the token will be fetched. MS-TDS names 1 and 2. Microsoft's drivers
    send 3 for every other way, such as interactive, device code, managed identity and default."""

    PASSWORD = 0x01  # Microsoft's drivers send this for service principals too
    INTEGRATED = 0x02
    INTERACTIVE = 0x03


Fetch = Callable[[str, str], str | Awaitable[str]]


@dataclass(frozen=True)
class EntraLogin:
    """An Entra ID access token fetched mid-login. The server says what the token is for (its resource, the SPN) and
    where to get it (its token endpoint, the STS URL), and `fetch(spn, sts_url)` returns the token."""

    fetch: Fetch = field(repr=False)
    workflow: Workflow = Workflow.INTERACTIVE


Login = WindowsLogin | EntraToken | EntraLogin


class FedAuthLibrary(enum.IntEnum):  # the FEDAUTH feature's library (§2.2.6.4)
    SECURITY_TOKEN = 0x01  # the token is in the login
    MSAL = 0x02  # the token is fetched mid-login (MS-TDS still calls it ADAL)


def fed_auth_feature(login: EntraToken | EntraLogin, token: str | None, echo: bool, nonce: bytes | None) -> bytes:
    """The FEDAUTH feature's data: the library and whether the hello's FEDAUTHREQUIRED is echoed, then the token and
    the server's nonce (token in advance), or the workflow (mid-login)."""
    if isinstance(login, EntraLogin):
        return bytes([FedAuthLibrary.MSAL << 1 | echo, login.workflow])
    data = token.encode("utf-16-le")
    return bytes([FedAuthLibrary.SECURITY_TOKEN << 1 | echo]) + len(data).to_bytes(4, "little") + data + (nonce or b"")


def fed_auth_token(token: str, nonce: bytes | None) -> bytes:
    """The federated authentication token message (packet type 08, §2.2.6.3): its length, the token, the nonce."""
    data = token.encode("utf-16-le")
    body = len(data).to_bytes(4, "little") + data + (nonce or b"")
    return len(body).to_bytes(4, "little") + body


async def called(fn: Callable[..., Any], *args: Any) -> Any:
    """Call an application's function, sync or async. The shell runs it for the Obtain action."""
    result = fn(*args)
    return await result if hasattr(result, "__await__") else result
