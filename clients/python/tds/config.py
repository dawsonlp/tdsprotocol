"""Current connection settings as values; reading them grants no SQL authority.

Reference: docs/design/H-pool-configuration.md. A pool reads only when opening
or recovering a connection. TLS objects/callbacks and pool limits stay fixed.
"""
import asyncio
from dataclasses import dataclass, field, fields, replace
from typing import Any, Protocol

from . import login7


class ConfigurationError(Exception):
    """Safe phase/reason; a source's original exception is inspectable separately.

    Source messages can contain secrets. They are deliberately excluded from
    exception chaining/formatting, including the ordinary traceback view.
    """

    def __init__(self, phase: str, reason: str, source_error: Exception | None = None):
        super().__init__(f"configuration {phase}: {reason}")
        self.phase, self.source_error = phase, source_error


@dataclass(frozen=True, slots=True)
class ConnectionConfig:
    """Immutable effective login settings. Equality includes the password.

    `windows` names a Windows login's protocol ("ntlm", "kerberos" or "negotiate"); `user` and `password` are then the
    Windows identity, and each opening makes its own Spnego provider (C3: a pool re-reads a rotated password after
    18452, as Rust's does). Without it, they are a SQL Server login.

    A file format and secret resolution belong to ConfigService's implementation.
    An equivalent newly allocated value is unchanged. Features are normalized to
    a tuple; no runtime callback, TLS context, timestamp or hash is a field.
    """

    host: str
    port: int
    user: str
    password: str = field(repr=False)
    database: str = ""
    tds_version: str = "7.4"
    mars: bool = False
    app_name: str = "tds (python)"
    host_name: str | None = None
    language: str = ""
    odbc: bool = True
    read_only_intent: bool = False
    follow_routing: bool = True
    features: tuple = field(default=login7.DEFAULT_FEATURES, repr=False)
    windows: str | None = None

    def __post_init__(self):
        texts = (self.host, self.user, self.password, self.database, self.app_name, self.language)
        if not all(isinstance(v, str) for v in texts) or not self.host or not self.user:
            raise ConfigurationError("validation", "host/user must be nonempty text; login fields must be text")
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ConfigurationError("validation", "port must be an integer from 1 to 65535")
        if self.tds_version not in ("7.4", "8.0"):
            raise ConfigurationError("validation", "TDS version must be 7.4 or 8.0")
        if self.host_name is not None and not isinstance(self.host_name, str):
            raise ConfigurationError("validation", "host_name must be text or None")
        if self.windows not in (None, "ntlm", "kerberos", "negotiate"):
            raise ConfigurationError("validation", "windows must be None, \"ntlm\", \"kerberos\" or \"negotiate\"")
        for name in ("mars", "odbc", "read_only_intent", "follow_routing"):
            if type(getattr(self, name)) is not bool:
                raise ConfigurationError("validation", f"{name} must be a boolean")
        try:
            requested = login7.feature_list(self.features)
            features = tuple(f if bytes(data) == login7.REQUEST[f] else (f, bytes(data))
                             for f, data in sorted(requested.items()))
        except Exception as failure:
            raise ConfigurationError("validation", "unsupported feature selection", failure) from None
        object.__setattr__(self, "features", features)

    def compatible_with(self, previous: ConnectionConfig) -> bool:
        """Only a credential refresh can continue an existing logical session."""
        return replace(self, password=previous.password) == previous

    def _options(self) -> dict[str, Any]:
        options = {f.name: getattr(self, f.name) for f in fields(self) if f.name != "windows"}
        if self.windows is not None:  # a new provider for each opening, from the current values
            from .adapters.spnego import Spnego
            from .logins import WindowsLogin
            options["login"] = WindowsLogin(Spnego(self.user, self.password, self.windows))
            options["user"] = options["password"] = ""
        return options


class ConfigService(Protocol):
    async def read(self) -> ConnectionConfig:
        """Return current values; cooperate with async scheduling/cancellation."""
        ...


@dataclass(frozen=True, slots=True)
class StaticConfig:
    configuration: ConnectionConfig = field(repr=False)

    async def read(self) -> ConnectionConfig:
        return self.configuration


@dataclass(frozen=True, slots=True, repr=False)
class ConnectionServices:
    """Fixed runtime bindings, excluded from snapshot comparison."""

    ssl_context: Any = None
    server_hostname: str | None = None
    observe: Any = None
    capture_factory: Any = None


class _ConfigState:
    """Per-pool acceptance, independently owned by borrowed connections too.

    No connection registry or pool back-reference is held here. The async gate
    orders reads/acceptance, but is released before network login begins.
    """

    def __init__(self, source: ConfigService):
        if not callable(getattr(source, "read", None)):
            raise TypeError("configuration source must have an async read method")
        self.source = source
        self.current: ConnectionConfig | None = None
        self._gate = asyncio.Lock()

    async def read(self, deadline: float) -> ConnectionConfig:
        try:
            async with asyncio.timeout_at(deadline):
                async with self._gate:
                    try:
                        candidate = await self.source.read()
                    except ConfigurationError:
                        raise
                    except Exception as failure:
                        raise ConfigurationError("read", "source read failed", failure) from None
                    if not isinstance(candidate, ConnectionConfig):
                        raise ConfigurationError("validation", "source must return ConnectionConfig")
                    # Validate again at the source boundary; frozen values still
                    # rely on application code respecting Python's object model.
                    candidate = replace(candidate)
                    self.current = candidate
                    return candidate
        except TimeoutError:
            raise ConfigurationError("timeout", "configuration read deadline expired") from None

    def matches(self, configuration: ConnectionConfig) -> bool:
        return self.current == configuration

    def require_current(self, configuration: ConnectionConfig) -> None:
        if not self.matches(configuration):
            raise ConfigurationError("superseded", "settings changed before opening completed")
