"""The connection manager's shell (asyncio): sockets, timers, tasks and waiting. Nothing else.

It runs the core's procedures and performs each action they yield. After connecting, it reads the socket
for every serial channel and delivers each packet to its channel's inbox. A live response reads its packets
through the shell (the response's Source). The pool is here too, because lending is only waiting and record
keeping. What a connection must do when it is given back belongs to the core (ConnectionCore.release).
"""

import asyncio
import contextlib
import dataclasses
import socket
import ssl
from collections import deque
from typing import Any, Callable, Generator, Iterable

from ..requests import Request
from ..response import Response
from .. import login7
from .core import (END, Action, AwaitWindow, ConnectError, ConnectionCore, Event, Obtain, Options, Produce, Read, Receive,
                   Routed, Send, SessionNotRecovered)
from ..logins import Login, called

Observer = Callable[[Event], None]

INBOX_PACKETS = 8  # without MARS: how far the socket reader may get ahead of the response's reader


class Inbox:
    """A serial channel's packets, waiting to be read. Without MARS it is bounded, so the socket reader pauses when
    the response's reader is slower, and TCP flow control makes the server wait. Under MARS the server's window
    bounds it instead, and the socket reader must never pause, because other channels share it."""

    def __init__(self, capacity: int | None):
        self._items: deque = deque()
        self._capacity = capacity
        self._changed = asyncio.Condition()
        self._failure: BaseException | None = None

    async def put(self, item) -> None:
        async with self._changed:
            while self._capacity is not None and len(self._items) >= self._capacity and self._failure is None:
                await self._changed.wait()
            self._items.append(item)
            self._changed.notify_all()

    async def get(self):
        async with self._changed:
            while not self._items:
                if self._failure is not None:
                    raise self._failure
                await self._changed.wait()
            item = self._items.popleft()
            self._changed.notify_all()
            return item

    async def fail(self, failure: BaseException) -> None:
        async with self._changed:
            self._failure = failure
            self._changed.notify_all()


async def connect(host: str, port: int, *, user: str = "", password: str = "", login: Login | None = None,
                  new_password: str = "", database: str = "", mars: bool = False,
                  odbc: bool = True, tds_version: str | None = None, strict: bool = False,
                  ssl_context: ssl.SSLContext | None = None, server_hostname: str | None = None, timeout: float = 15.0,
                  observe: Callable[[Event], None] | None = None, capture: Any = None,
                  features: Iterable[login7.Feature] = login7.DEFAULT_FEATURES, app_name: str = "tds (python)",
                  host_name: str | None = None, language: str = "", read_only_intent: bool = False,
                  follow_routing: bool = True) -> Connection:
    """Open a connection and log in. The connection timer covers everything up to ready. Every option, with its
    default, is listed in the Options section of docs/design/3-reference/connect.md.

    How it logs in (D-55, tds.logins): either a SQL Server login, with `user` and `password` (and `new_password` to
    change an expired password during the login), or `login`, which is a WindowsLogin (Kerberos or NTLM), an
    EntraToken or an EntraLogin (Entra ID). Each of these takes its tokens from the application.

    `database`: where the session starts. Without it, the server uses the login's default database and announces it
    (connection.session.database). If the database can't be opened, the login fails with an error that says why.
    The driver doesn't try another database (D-9).

    `features`: what the login asks for (D-8), as a list of tds.Feature. The default is tds.DEFAULT_FEATURES (JSON
    support, vector support, UTF-8 support, data classification). connection.features shows what the server
    accepted. A feature that the driver can't read yet is refused, with an error that says why and when.

    `app_name`, `host_name` (default: this machine's name) and the process ID identify the connection to the server's
    administrators (program_name, host_name, host_process_id). `language` sets the session's language, and so the
    language of its messages. The default is the login's own language. `read_only_intent` tells an availability group
    that the connection only reads, so that it can be routed to a readable secondary. It is a routing hint, and it
    doesn't stop writes (D-9).

    `follow_routing`: when a login reply routes the connection to another server, the driver follows the route once.
    It connects there with the same options, within the same connection timer, and connection.routed_from says where
    the connection was routed from. A second route fails with an error that names the chain of servers. With False,
    Routed is raised instead (D-11).

    `tds_version` is "7.4" (the default) or "8.0". `strict=True` also selects "8.0", as Microsoft's drivers name it
    (Encrypt=Strict). Under 7.4 the client and server agree on encryption in the hello, and either the whole
    connection is encrypted or the connection fails. Under 8.0 TLS comes before anything else, and everything is
    always encrypted. 8.0 needs SQL Server 2022 or later with a certificate configured. The driver never tries 7.4
    when 8.0 fails. The error says why and what the options are (D-10).

    The server's certificate is checked with Python's standard ssl.SSLContext (D-10). The default context verifies
    it against the system's trusted authorities and the host name. For anything else, pass `ssl_context`:

        ssl.create_default_context(cafile="test-ca.pem")      trust a private or self-signed authority
        ctx.load_verify_locations(cadata=pem)                  trust one certificate, given as text
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3           insist on TLS 1.3 (8.0 only: 7.4 stops at TLS 1.2)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                                                               no verification at all (7.4 only: refused under 8.0,
                                                               where it couldn't stop a man in the middle)

    A certificate that names another host is checked against `server_hostname`, as in asyncio.open_connection.
    Under 8.0 the driver sets the context's ALPN protocols to "tds/8.0".

    `observe` sees the running client (D-12). It is an observer called with each Event, and its `level` says how much
    it wants (observe.Level: OFF, OUTLINE or FULL; a plain callable counts as FULL). None is off: no events and no
    inspection trees are built. This is the optimized mode. `connection.observe` changes it between exchanges.

    `capture` (tds.capture.Capture) saves the conversation, every event and every plaintext packet, so that it can be
    replayed offline into the identical view (D-12). `connection.capture` starts or stops one between exchanges.

    `odbc` sets LOGIN7's ODBC flag (MS-TDS calls it fODBC), which is on by default (D-9). The server then starts the
    session with ODBC's defaults, as ODBC, .NET and JDBC clients get them. ANSI_NULLS, ANSI_PADDING, ANSI_WARNINGS,
    CONCAT_NULL_YIELDS_NULL and QUOTED_IDENTIFIER are on, and TEXTSIZE is unlimited. With odbc=False the server's own
    defaults apply. Those options are off, and TEXTSIZE is 4,096 bytes, so every large value is cut to 4,096 bytes.
    The driver never changes a session with SET statements of its own."""
    if strict and tds_version not in (None, "8.0"):
        raise ValueError(f"strict=True is TDS 8.0, but tds_version={tds_version!r} was given: pass one of them")
    version = "8.0" if strict else tds_version or "7.4"
    if version not in ("7.4", "8.0"):
        raise ValueError(f"tds_version is \"7.4\" or \"8.0\" (D-2), not {version!r}")
    if login is None and not user:
        raise ValueError("connect needs a way to log in: user and password for a SQL Server login, or login=… "
                         "(tds.WindowsLogin, tds.EntraToken, tds.EntraLogin)")
    if login is not None and (user or password or new_password):
        raise ValueError(f"login={type(login).__name__}(…) logs in with its own tokens: user, password and "
                         "new_password belong to a SQL Server login")
    options = Options(host, port, user, password, database, login=login, new_password=new_password,
                      host_name=host_name or socket.gethostname(),
                      tds_version=version, ssl_context=ssl_context, server_hostname=server_hostname, mars=mars,
                      odbc=odbc, features=tuple(features), app_name=app_name, language=language,
                      read_only_intent=read_only_intent)
    login7.feature_list(options.features)  # a feature the driver can't read yet is refused here, before connecting
    chain: list[str] = []  # where routing has sent this connection from
    writer = None
    try:
        async with asyncio.timeout(timeout):  # one connection timer, however many connections it takes (D-11)
            while True:
                core = ConnectionCore(options, observe)
                if capture is not None:
                    core.set_capture(capture)
                try:
                    reader, writer = await asyncio.open_connection(options.host, options.port)
                except OSError as e:
                    raise ConnectError("start", f"couldn't reach {options.host}:{options.port}: {e.strerror or e}") from e
                connection = Connection(core, reader, writer)
                try:
                    await connection._run(core.connect())
                    break
                except Routed as routed:
                    writer.close()
                    writer = None
                    here, there = f"{options.host}:{options.port}", f"{routed.server}:{routed.port}"
                    if not follow_routing:
                        raise
                    if chain:
                        raise ConnectError("log in", f"routed a second time: {' → '.join([*chain, here, there])}. "
                                                     "The driver follows one redirect (D-11)") from routed
                    chain.append(here)
                    core._step("routed", f"to {there}")
                    options = dataclasses.replace(options, host=routed.server, port=routed.port, server_hostname=None,
                                                  login_server_name=f"{routed.server},{routed.port}")  # Azure SQL's
                    # nodes need the routed server and port (observed; SqlClient sends the same)
    except TimeoutError as e:
        if writer is not None:
            writer.close()
        raise ConnectError(core.step, f"the connection timer ran out: {timeout} s passed without the server "
                                      f"finishing this step ({options.host}:{options.port})") from e
    except BaseException:
        if writer is not None:
            writer.close()
        raise
    connection.routed_from = chain[0] if chain else None
    connection._timeout = timeout
    connection._start_reading()
    return connection


class Connection:
    def __init__(self, core: ConnectionCore, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._core, self._reader, self._writer = core, reader, writer
        self._inboxes: dict[int, Inbox] = {}
        self._reading: asyncio.Task | None = None
        self._arrived = asyncio.Event()  # set (then replaced) each time frames from the server have been processed
        self._failure: BaseException | None = None  # why the connection can't continue, once it can't
        self.routed_from: str | None = None  # where routing sent this connection from, "host:port" (D-11)
        self.recoveries = 0  # how many times this connection's session has been recovered on a new connection (D-57)
        self._timeout = 15.0  # the connection timer, also used when recovering

    @property
    def session(self):
        return self._core.session

    @property
    def observe(self) -> Callable[[Event], None] | None:
        """Who sees this connection's running client, and how much (D-12). It can be set between exchanges, to observe
        a pooled connection that is already open: connection.observe = Printer(Level.FULL)."""
        return self._core._observer

    @observe.setter
    def observe(self, observe: Callable[[Event], None] | None) -> None:
        self._core.set_observe(observe)

    @property
    def capture(self) -> Any:
        """The capture that saves this conversation, if any (D-12). It can be set between exchanges."""
        return self._core._capture

    @capture.setter
    def capture(self, capture: Any) -> None:
        self._core.set_capture(capture)

    @property
    def server(self):
        return self._core.server

    @property
    def features(self) -> dict:
        """The features the server accepted at login (FEATUREEXTACK), each with its data, such as a version."""
        return self._core.features

    @property
    def session_id(self) -> int:
        """The server's id for this connection's session. It is unique while the session lives. SQL Server reuses
        ids after a session ends, so a new connection can get the id of a closed one."""
        return self._core.session_id

    @property
    def alive(self) -> bool:
        return (self._failure is None and self._core.failure is None and self._reading is not None
                and not self._reading.done())

    async def recover(self) -> None:
        """Recover this broken connection's session on a new connection (D-57). The new connection's login carries
        the session as login established it and as the server last reported it, and the server rebuilds the session:
        its database, language, collation, SET options and the other states the server reports. The serial channels
        that were open before are open again, with the same ids, and each is free. A request that was in progress
        when the connection broke is not sent again. When the connection broke with no request in progress, the next
        exchange recovers the session by itself.

        Raises SessionNotRecovered, which says why. The reasons are: the connection isn't broken; the login didn't
        ask for session recovery, or the server didn't agree to it; the server marked the session not recoverable
        (for example, a transaction is open, or a temporary table exists); or the recovery login failed."""
        old = self._core
        if self.alive:
            raise SessionNotRecovered(f"session {old.session_id} isn't broken: there is nothing to recover")
        old.broken_while_idle = False  # one attempt for each time it's found broken
        if why := old.recovery_refusal():
            raise SessionNotRecovered(f"session {old.session_id} can't be recovered: {why}. The connection broke: "
                                      f"{old.failure}") from old.failure
        o = old.options
        core = ConnectionCore(o, old._observer)
        if old._capture is not None:
            core.set_capture(old._capture)
        core._step("recover", f"session {old.session_id}, on a new connection to {o.host}:{o.port}")
        writer = None
        try:
            async with asyncio.timeout(self._timeout):
                try:
                    reader, writer = await asyncio.open_connection(o.host, o.port)
                except OSError as e:
                    raise ConnectError("start", f"couldn't reach {o.host}:{o.port}: {e.strerror or e}") from e
                await Connection(core, reader, writer)._run(core.connect(old.recovery_data()))
            if login7.Feature.SESSION_RECOVERY not in core.features:
                raise ConnectError("log in", "the server logged in a new session without agreeing to recover the "
                                             "old one, so the session's state is gone")
        except BaseException as e:
            if writer is not None:
                writer.close()
            why = f"the connection timer ran out ({self._timeout} s) at step {core.step}" if isinstance(e, TimeoutError) else e
            raise SessionNotRecovered(f"session {old.session_id} couldn't be recovered: {why}. The connection broke: "
                                      f"{old.failure}") from e
        sends = core.adopt(old)
        old_writer = self._writer
        self._core, self._reader, self._writer, self._failure = core, reader, writer, None
        self._inboxes = {c: Inbox(None if core.link.mars else INBOX_PACKETS) for c in core.link.channels}
        self._write(sends)
        self.recoveries += 1
        core._step("recovered", f"session {old.session_id} → {core.session_id} · database {core.session.database}")
        old_writer.close()
        self._start_reading()

    def serial_channel(self) -> SerialChannel:
        """Open a serial channel owned by the current task. Use it as
        `async with connection.serial_channel() as ch:`."""
        owner = asyncio.current_task()
        channel_id, sends = self._core.open_channel(owner)
        self._inboxes[channel_id] = Inbox(None if self._core.link.mars else INBOX_PACKETS)
        self._write(sends)
        return SerialChannel(self, channel_id)

    async def close(self) -> None:
        self._write(self._core.close())
        with contextlib.suppress(ConnectionError):
            await self._writer.drain()
        if self._reading:
            self._reading.cancel()
        self._writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await self._writer.wait_closed()

    async def __aenter__(self) -> Connection:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def _release(self) -> bool:
        """Called when given back to a pool. True if this connection can be lent again (see ConnectionCore.release)."""
        if not self.alive:
            return False
        reusable, sends = self._core.release()
        self._write(sends)
        return reusable

    # ----------------------------------------------------------------------- performing the core's actions

    async def _run(self, procedure: Generator[Action, Any, Any], undo_on_cancel: bool = False) -> Any:
        """Perform each action a core procedure yields, until it returns its result. Failures are thrown into the
        procedure, so its own cleanup runs. With undo_on_cancel, a cancellation is also thrown in, once. The exchange
        then undoes its request before CancelledError reaches the caller (D-41)."""
        result, failure = None, None
        while True:
            try:
                action = procedure.throw(failure) if failure else procedure.send(result)
            except StopIteration as finished:
                return finished.value
            result, failure = None, None
            try:
                match action:
                    case Send(data):
                        self._writer.write(data)
                        await self._writer.drain()
                    case Read():
                        result = await self._reader.read(65536)
                    case Receive(channel):
                        try:
                            result = await self._inboxes[channel].get()
                        except Exception as e:  # the connection failed: thrown into the procedure
                            failure = e
                    case AwaitWindow():
                        if self._failure is None:  # a failed connection will never raise the window
                            await self._arrived.wait()  # the procedure checks the window again when it resumes
                        failure = self._failure
                    case Obtain(fn, args):
                        try:
                            result = await called(fn, *args)
                        except Exception as e:  # the application's token function failed: thrown into the procedure
                            failure = e
                    case Produce(source):
                        try:
                            result = await anext(source)
                        except StopAsyncIteration:
                            result = END
                        except Exception as e:  # the source failed: thrown into the procedure, which undoes the request
                            failure = e
            except asyncio.CancelledError as e:
                if not undo_on_cancel:
                    raise
                failure, undo_on_cancel = e, False

    def _write(self, sends: list[Send]) -> None:
        for s in sends:
            self._writer.write(s.data)

    def _start_reading(self) -> None:
        self._reading = asyncio.create_task(self._read_for_every_channel(), name="tds reader")

    async def _read_for_every_channel(self) -> None:
        failure: BaseException
        try:
            while data := await self._reader.read(65536):
                for item in self._core.feed(data):
                    if isinstance(item, Send):
                        self._writer.write(item.data)  # for example, Attention that was waiting for MARS window credit
                    else:
                        channel_id, packet = item
                        await self._inboxes[channel_id].put(packet)  # without MARS, waits while the inbox is full
                self._wake_waiters()
            failure = ConnectionError("the server closed the connection")
        except asyncio.CancelledError:
            return
        except Exception as e:  # for example, a malformed message: the connection can't continue
            failure = e
        in_flight = [c.reader.request for c in self._core.link.channels.values() if c.busy and c.reader is not None]
        self._core.in_flight_when_broken = [str(r) for r in in_flight]
        self._core.broken_while_idle = isinstance(failure, OSError) and not in_flight  # the network, not the bytes
        self._failure = failure
        if self._core.failure is None:  # the core refuses every later request with the reason
            self._core.failure = failure
        for inbox in self._inboxes.values():  # a fatal error fails every serial channel (D-17)
            await inbox.fail(failure)
        self._wake_waiters()

    def _wake_waiters(self) -> None:
        """Resume every procedure waiting for a MARS window; each checks its own window again."""
        self._arrived.set()
        self._arrived = asyncio.Event()


class SerialChannel:
    """One request at a time, owned by the task that opened it (D-21, D-22). Anyone may close it (D-23)."""

    def __init__(self, connection: Connection, channel_id: int):
        self._connection, self.id = connection, channel_id

    async def exchange(self, request: Request, *, decrypt: Callable | None = None) -> Response:
        """One exchange in the conversation: send one request, and return its response, open and ready to be read.

        A conversation is the ordered sequence of messages on a serial channel. The client speaks, then the server
        answers, one exchange at a time (D-22). Every operation that an application performs is built on this one
        step. The operation chooses what to send (the request: Batch, and Call from M3) and how to read what comes
        back (the response, read forward as it arrives; see The Client §4). The response holds this channel until it
        has been read to its end, finished, closed, or canceled and acknowledged.

        Design constraint (D-33): this method and the response reader never branch on the kind of operation.
        What differs between operations belongs in the request definitions (what is sent) or in the layers around
        the driver (which parts of the response they keep). A branch on the operation here is a sign of a design error.

        `decrypt` is Always Encrypted's hook, given by tds.encryption (D-60). It turns an encrypted value's ciphertext
        into its value. Without it, encrypted values arrive as EncryptedValue, their ciphertext as sent.
        """
        if isinstance(request, str):
            raise TypeError("exchange takes a request, not SQL text: tds.Batch(sql) sends T-SQL as written")
        connection = self._connection
        if not connection.alive and connection._core.broken_while_idle:
            await connection.recover()  # broken with no request in progress: recover, then send (D-57)
        core = connection._core
        reader = await connection._run(core.exchange(self.id, asyncio.current_task(), request, decrypt),
                                       undo_on_cancel=True)
        return Response(reader, _ChannelSource(self))

    def hand_over(self, task: asyncio.Task) -> None:
        self._connection._core.hand_over(self.id, asyncio.current_task(), task)

    async def close(self) -> None:
        self._connection._write(self._connection._core.close_channel(self.id))

    async def __aenter__(self) -> SerialChannel:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()


class _ChannelSource:
    """Where a live response's packets come from: its serial channel's inbox, read by the owner's task."""

    def __init__(self, channel: SerialChannel):
        self._channel = channel
        self._core = channel._connection._core  # the connection the request was sent on (after a recovery, the old one)

    async def read_more(self) -> None:
        await self._channel._connection._run(self._core.read(self._channel.id, asyncio.current_task()))

    def cancel(self) -> None:
        connection = self._channel._connection
        if self._core is connection._core:  # the old connection's requests ended with it
            connection._write(self._core.cancel(self._channel.id))

    def resume(self) -> None:
        self._core.resume(self._channel.id)

    def describe(self) -> str:
        return f"serial channel {self._channel.id}"


class Pool:
    """Connections lent whole, each to one borrower at a time (D-36).

    A borrowed connection's session belongs to its borrower alone. No other borrower's requests share its
    transaction or settings, and the borrower opens every serial channel on it. Giving it back resets its session
    before anyone else uses it. A connection given back with a request still in progress is closed instead and
    never lent again, because its next borrower would read that request's response.

        async with pool.connection() as connection:
            async with connection.serial_channel() as channel:
                ...
    """

    def __init__(self, host: str, port: int, *, size: int = 10, observe: Observer | None = None, **options: Any):
        self.size = size
        self._host, self._port, self._options = host, port, options
        self._observe = observe or (lambda event: None)
        self._idle: list[Connection] = []
        self._lent: set[Connection] = set()
        self._opening = 0
        self._changed = asyncio.Condition()  # a connection was given back, or opening one failed
        self._closed = False

    @property
    def in_use(self) -> int:
        return len(self._lent)

    @property
    def idle(self) -> int:
        return len(self._idle)

    @contextlib.asynccontextmanager
    async def connection(self):
        """Borrow a whole connection. Only the caller uses it until the block ends. Then it is given back and reset."""
        connection = await self._borrow()
        try:
            yield connection
        finally:
            await self._give_back(connection)

    async def close(self) -> None:
        """Close the idle connections immediately. Lent connections are closed when they are given back."""
        async with self._changed:
            self._closed, idle, self._idle = True, self._idle, []
            self._changed.notify_all()
        for connection in idle:
            await connection.close()

    async def __aenter__(self) -> Pool:
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    def _event(self, text: str) -> None:
        self._observe(Event("pool", f"pool · {text} · {self.in_use} of {self.size} lent"))

    async def _borrow(self) -> Connection:
        async with self._changed:
            while True:
                if self._closed:
                    raise RuntimeError("the pool is closed")
                while self._idle:
                    connection = self._idle.pop()
                    if connection.alive:
                        self._lent.add(connection)
                        self._event(f"lend session {connection.session_id}")
                        return connection
                    await connection.close()  # it failed while idle
                if len(self._lent) + self._opening < self.size:
                    self._opening += 1
                    break
                self._event("waiting: every connection is lent")
                await self._changed.wait()
        try:
            connection = await connect(self._host, self._port, observe=self._observe, **self._options)
        except BaseException:
            async with self._changed:
                self._opening -= 1
                self._changed.notify()
            raise
        async with self._changed:
            self._opening -= 1
            self._lent.add(connection)
        self._event(f"open and lend session {connection.session_id}")
        return connection

    async def _give_back(self, connection: Connection) -> None:
        reusable = connection._release() and not self._closed
        async with self._changed:
            self._lent.discard(connection)
            if reusable:
                self._idle.append(connection)
            self._changed.notify()
        if reusable:
            self._event(f"session {connection.session_id} given back")
        else:
            await connection.close()
            self._event(f"session {connection.session_id} closed, not lent again")
