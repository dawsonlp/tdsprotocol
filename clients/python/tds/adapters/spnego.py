"""Windows logins through pyspnego: Kerberos, NTLM, or SPNEGO choosing between them (D-55).

    tds.connect(host, port, login=tds.WindowsLogin(Spnego()))                                  # the current user
    tds.connect(host, port, login=tds.WindowsLogin(Spnego("TDS\\\\tdsuser", password, "ntlm")))  # named, by NTLM

Kerberos needs the server's full host name, as it was registered in the server's service name: MSSQLSvc/host:port.
Connect by that name, not by an address. Kerberos needs pyspnego's kerberos extra (gssapi, and a Kerberos library on
the system).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Spnego:
    """A security provider (tds.logins.SecurityProvider) over pyspnego. Without a user name, it uses the current
    user's credentials: a Kerberos ticket from kinit, or the logged-in Windows user's."""

    username: str | None = None
    password: str | None = field(default=None, repr=False)
    protocol: str = "negotiate"  # "kerberos", "ntlm", or "negotiate": SPNEGO, which prefers Kerberos
    service: str = "MSSQLSvc"

    def begin(self, host: str, port: int):
        try:
            import spnego
        except ImportError as e:
            raise ImportError("Windows logins through Spnego need pyspnego: pip install 'tds[windows]' (NTLM), or "
                              "'tds[kerberos]' (Kerberos too)") from e
        # MSSQLSvc/host:port, the service name SQL Server registers for TCP
        return spnego.client(self.username, self.password, hostname=f"{host}:{port}", service=self.service,
                             protocol=self.protocol)
