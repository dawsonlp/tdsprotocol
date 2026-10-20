"""Windows logins through pyspnego: Kerberos, NTLM, or SPNEGO choosing between them (D-55).

    tds.connect(host, port, login=tds.WindowsLogin(Spnego()))                                  # the current user
    tds.connect(host, port, login=tds.WindowsLogin(Spnego("TDS\\\\tdsuser", password, "ntlm")))  # named, by NTLM

Kerberos needs the server's full host name, as it was registered in the server's service name: MSSQLSvc/host:port.
Connect by that name, not by an address. Kerberos needs pyspnego's kerberos extra (gssapi, and a Kerberos library on
the system).

pyspnego's calls block: making a context can wait on a KDC, and so can each step. They run in a small pool of worker
threads, so the opening's deadline and the event loop stay in charge. A call cannot be interrupted once it runs: if the
opening is canceled or times out, the call finishes in its worker, which keeps its slot until then, and its result is
released, never installed. A process that exits while a call runs waits for it. Workers use the process's identity.
"""

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

WORKERS = 4  # native calls running at once, across every connection; more wait their turn
_executor = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="tds-spnego")


@dataclass(frozen=True)
class Spnego:
    """A security provider (tds.logins.SecurityProvider) over pyspnego. Without a user name, it uses the current
    user's credentials: a Kerberos ticket from kinit, or the logged-in Windows user's."""

    username: str | None = None
    password: str | None = field(default=None, repr=False)
    protocol: str = "negotiate"  # "kerberos", "ntlm", or "negotiate": SPNEGO, which prefers Kerberos
    service: str = "MSSQLSvc"

    def begin(self, host: str, port: int) -> "Exchange":
        try:
            import spnego  # noqa: F401  (imported here so a missing extra is reported at once)
        except ImportError as e:
            raise ImportError("Windows logins through Spnego need pyspnego: pip install 'tds[windows]' (NTLM), or "
                              "'tds[kerberos]' (Kerberos too)") from e
        return Exchange(self, host, port)


class Exchange:
    """One login's exchange (tds.logins.SecurityExchange). Its context is made by its first step, in a worker; each
    step is an awaitable that runs in a worker, one at a time."""

    def __init__(self, provider: Spnego, host: str, port: int):
        self._provider, self._host, self._port = provider, host, port
        self._context = None
        self._lock = threading.Lock()  # one native call at a time for this context, even a late one
        self._abandoned = False

    def step(self, challenge: bytes | None):
        return self._step(challenge)

    async def _step(self, challenge: bytes | None) -> bytes | None:
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(_executor, self._native, challenge)
        except asyncio.CancelledError:
            self.abandon()  # a call still running finishes in its worker; its result is released
            raise

    def abandon(self) -> None:
        """The opening gave up: release the context now, or as soon as a running call finishes."""
        self._abandoned = True
        if self._lock.acquire(blocking=False):
            try:
                self._context = None
            finally:
                self._lock.release()

    def _native(self, challenge: bytes | None) -> bytes | None:
        with self._lock:
            if self._abandoned:
                self._context = None
                raise RuntimeError("the login was abandoned")
            if self._context is None:
                import spnego
                provider = self._provider
                # MSSQLSvc/host:port, the service name SQL Server registers for TCP
                self._context = spnego.client(provider.username, provider.password,
                                              hostname=f"{self._host}:{self._port}", service=provider.service,
                                              protocol=provider.protocol)
                if self._abandoned:  # gave up while the context was being made: no step follows
                    self._context = None
                    raise RuntimeError("the login was abandoned")
            token = self._context.step(challenge)
            if self._abandoned:  # canceled while this call ran: nothing is installed
                self._context = None
            return token
