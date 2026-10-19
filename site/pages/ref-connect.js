/* Reference: Connect (procedure). */
(function () {
  const { T, L, D, table, flow, source } = window.TDS;

  window.TDS.page({
    id: 'ref/connect', group: 'Reference', kind: 'procedure',
    title: 'Connect',
    where: 'The first conversation on every connection. It ends in <b>ready</b> or <b>closed</b>.',
    outcome: 'follow, implement or debug the steps from opening a TCP connection to being ready for requests.',
    body: () => `
      <h2>Purpose</h2>
      <p>This procedure turns a TCP connection into an authenticated, encrypted session whose ${T('session state')} the client knows.
      This page covers SQL Server login; the other three ways to log in are listed in ${L('ref/conversations', 'Conversations')}.
      The ${T('connection manager')} runs this procedure. Client code sees only the result: a ready connection on which to open ${T('serial channel', 'serial channels')}
      (${L('client', 'The Client', '3-connections-and-serial-channels')}).</p>

      <h2>Shape</h2>
      <h3>TDS 7.4</h3>
      ${flow([{ label: 'start', sub: 'open TCP' }, { label: 'hello' }, { label: 'secure', sub: 'TLS inside hello packets' }, { label: 'log in' }, { label: 'ready', kind: 'end' }])}
      <h3>TDS 8.0</h3>
      ${flow([{ label: 'start', sub: 'open TCP' }, { label: 'secure', sub: 'TLS first, ALPN tds/8.0' }, { label: 'hello' }, { label: 'log in' }, { label: 'ready', kind: 'end' }])}
      <p>From <i>log in</i>, a redirect leads to <b>routed</b>, then closed. Any failure, at any step, leads to <b>closed</b>.</p>

      ${table(['Step', 'Client sends', 'Client expects', 'Next if all is well', 'Otherwise closed, because…'], [
        ['<b>secure</b> (8.0, first)', 'TLS handshake on raw TCP, offering ALPN <code>tds/8.0</code>', 'TLS completes; certificate valid', 'hello', 'TLS failed or certificate rejected'],
        ['<b>hello</b>', L('ref/prelogin', 'PRELOGIN'), 'PRELOGIN reply (type <code>04</code>)', '7.4 with encryption agreed: secure · 8.0: log in',
          `malformed reply; instance mismatch; encryption outcome not acceptable (${D(10)})`],
        ['<b>secure</b> (7.4)', 'TLS records inside type <code>12</code> packets, until done', 'TLS records inside type <code>12</code> packets', 'log in', 'TLS failed or certificate rejected'],
        ['<b>log in</b>', L('ref/login7', 'LOGIN7'), L('ref/login-response', 'login response'), 'ready, or routed if redirected', 'no LOGINACK (the server sent ERROR); version not 7.4; malformed reply'],
        ['<b>ready</b>', '—', '—', 'serial channels may be opened', '—'],
        ['<b>routed</b>', '—', '—', `closed; reconnect to the named server (${D(11)})`, '—'],
      ])}

      <h2>Rules</h2>
      <ul>
        <li><b>One timer covers the whole procedure.</b> The connection timer (default 15 s) runs from <i>start</i> until <i>ready</i> or <i>closed</i>.</li>
        <li><b>Fail closed.</b> If a message is malformed, or isn’t expected at the current step, close the connection, enter <i>closed</i>, and report the step, what was expected and what arrived.</li>
        <li><b>Session state</b> is built only from the login reply’s announcements, starting from these defaults: packet size 4096, nothing else known.</li>
        <li><b>Packet size</b> switches to the announced value after the login reply, before the first request.</li>
        <li><b>The client chooses 8.0, and nothing falls back</b> (${D(10)}). <code>tds_version="8.0"</code> (or <code>strict=True</code>) starts with TLS. If that fails, the connection fails, saying why and what the options are. It never retries as 7.4, because that would silently lose the protection 8.0 gives.</li>
        <li><b>Under 7.4, the whole connection is encrypted, or the connection fails</b> (${D(10)}). A server that offers only login encryption, or none, is refused with an explanation.</li>
        <li><b>The server’s certificate is verified</b> with Python’s <code>ssl.SSLContext</code> (${D(10)}): by default against the system’s trusted authorities and the host name connected to. A certificate naming another host is checked against <code>server_hostname</code>. Under 8.0, a context that doesn’t verify is refused: TLS that accepts any certificate can’t prevent a man-in-the-middle attack.</li>
      </ul>

      <h2>Session recovery</h2>
      <p><b>When a connection breaks, a new one can continue its session</b> (${D(57)}). The login asks for session recovery (it is among the default features), and the server then reports the session’s state as it changes. To recover, the driver opens a new connection whose login carries that state, and the server rebuilds the session from it.</p>
      ${table(['When', 'The client sends', 'The server sends'], [
        ['the first login', 'the session recovery feature, with no data', 'its acknowledgement, holding the session’s initial states'],
        ['each response', '—', 'a SESSIONSTATE token for each change: a sequence number, whether the session can be recovered, and the states that changed'],
        ['a recovery login', 'the session recovery feature, with two snapshots: the session as the first login established it (database, collation, language, states), and as it is now (only what differs)', 'the session as it was, or a failed login'],
      ], 'compact')}
      <p><b>A state</b> is an id and a value that the client keeps without interpreting. Only the server knows what each one means. The client needs only its value at login and every change after that.</p>
      <p><b>When the driver recovers:</b></p>
      <ul>
        <li><b>By itself,</b> when an exchange finds the connection broken and no request in progress. The driver recovers once, then sends the request.</li>
        <li><b>When asked:</b> <code>await connection.recover()</code>.</li>
        <li><b>A request in progress when the connection broke is never sent again.</b> Whether it ran is unknown. The request’s own error says so, and the next exchange doesn’t recover by itself. <code>connection.recover()</code> recovers the session as the server last reported it; it neither determines nor undoes the interrupted request’s effects.</li>
        <li><b>The steps show the recovery:</b> <i>recover</i> (<code>● recover · session 81, on a new connection to …</code>), then the usual hello, secure and log in, then <i>recovered</i> (<code>● recovered · session 81 → 81 · database tempdb</code>: SQL Server can give the new session the old one’s id, once the old one has ended). <code>connection.recoveries</code> counts the recoveries.</li>
        <li><b>Serial channels continue:</b> each one that was open before is open again, with the same application id and owner, under MARS too. MARS wire ids are allocated afresh on the new physical connection and incoming frames map back to application ids. Connection/channel close permissions remain valid. Old responses cannot read or cancel new requests. Channels closed by the application stay closed.</li>
        <li><b>It can’t happen</b> when the login didn’t ask for session recovery, the server didn’t agree to it, the server marked the session not recoverable, or the recovery login failed. <code>SessionNotRecovered</code> then says why. It names the session and what broke the connection, and for a session marked not recoverable, the request after which the server marked it.</li>
      </ul>

      <p>The same recovery contract is implemented in Rust for its supported SQL/token subset: <code>connection.recover().await</code>, <code>connection.recoveries()</code> and <code>ErrorKind::SessionNotRecovered</code>. The driver retires the physical epoch before waking failed waiters; old request/read/cleanup guards cannot revoke the replacement. Python pins old response sources and running procedures to the failed core/transport. Retained data remain inspectable. See the ${L('recovery-experiment', 'experiment and Python/Rust results')}.</p>

      <h2>Options</h2>
      <p>This table lists every option of <code>tds.connect(host, port, *, user, password, …)</code>, with its default. The command line (<code>python -m tds --help</code>) offers the same, under the names shown.</p>
      ${table(['Option', 'Command line', 'Default', 'What it does', 'Decision'], [
        ['<code>user</code>, <code>password</code>', '<code>--user</code>, <code>--password-var</code>', '—', 'A SQL Server login.', '—'],
        ['<code>new_password</code>', '—', 'none', 'Changes a SQL Server login’s expired password as it logs in (error 18488 says it must).', D(54)],
        ['<code>login</code>', '—', 'none: a SQL Server login', `A Windows login (<code>tds.WindowsLogin</code>: Kerberos or NTLM) or an Entra ID login (<code>tds.EntraToken</code>, <code>tds.EntraLogin</code>), each taking its tokens from the application (${L('ref/conversations', 'Conversations', 'what-each-way-of-logging-in-needs--built-d-54-d-55')}).`, D(55)],
        ['<code>database</code>', '<code>--database</code>', 'the login’s default', 'Where the session starts. If it can’t be opened, the login fails, saying why; there is no fallback.', D(9)],
        ['<code>tds_version</code>', '<code>--tds-version</code>', '<code>"7.4"</code>', '<code>"8.0"</code>: TLS first, always encrypted. Nothing falls back from 8.0.', D(10)],
        ['<code>strict</code>', '—', '<code>False</code>', '<code>True</code> is <code>tds_version="8.0"</code>, as Microsoft’s drivers spell it (Encrypt=Strict).', D(10)],
        ['<code>ssl_context</code>', '<code>--ca-file</code>', 'the system’s trusted authorities, checking the host name', 'How the server’s certificate is checked: Python’s <code>ssl.SSLContext</code>.', D(10)],
        ['<code>server_hostname</code>', '<code>--server-hostname</code>', 'the host connected to', 'The name the certificate must carry.', D(10)],
        ['<code>timeout</code>', '<code>--timeout</code>', '15 s', 'The connection timer, from opening TCP to ready (routing included).', '—'],
        ['<code>cleanup_timeout</code>', '—', '5 s', 'Total channel-close cleanup budget, separate from connection/query time. Finite and nonnegative; failure/cancellation discards.', '—'],
        ['<code>mars</code>', '<code>--mars</code>', 'off', 'Serial channels are MARS sessions, so several can run at once.', D(18)],
        ['<code>odbc</code>', '<code>--no-odbc</code>', 'on', 'LOGIN7’s ODBC flag: the session starts with ODBC’s defaults (ANSI options on, TEXTSIZE unlimited). When off, the session starts with the server’s own defaults (TEXTSIZE 4,096 bytes).', D(9)],
        ['<code>features</code>', 'one switch per feature, below', '<code>tds.DEFAULT_FEATURES</code>', 'What the login asks for. <code>connection.features</code> shows what the server accepted.', D(8)],
        ['<code>app_name</code>', '<code>--app-name</code>', '<code>"tds (python)"</code>', 'The session’s <code>program_name</code>, as administrators see it.', D(9)],
        ['<code>host_name</code>', '<code>--host-name</code>', 'this machine’s name', 'The session’s <code>host_name</code>. The process ID is always the real one.', D(9)],
        ['<code>language</code>', '<code>--language</code>', 'the login’s default', 'The session’s language, and so the language of its messages.', D(9)],
        ['<code>read_only_intent</code>', '<code>--read-only-intent</code>', 'off', 'Tells an availability group the connection only reads, so it can be routed to a readable secondary. It is only a routing hint; writes still work.', D(9)],
        ['<code>follow_routing</code>', '—', 'on', 'A valid TCP routing reply is followed once under the original deadline, verifying the destination’s name. Non-TCP/invalid targets are rejected. When off, <code>tds.Routed</code> reports a valid target instead.', D(11)],
        ['<code>observe</code>', '<code>--observe</code>', 'off', 'Shows the running client at off/outline/full. A failed callback is disabled; its exception is available as <code>connection.observation_error</code> until replaced.', D(12)],
        ['<code>capture</code>', '—', 'none', 'Saves one physical connection for replay; cannot move to another. Write/flush failure raises <code>CaptureError</code> and discards the connection. Mutually exclusive with <code>capture_factory</code>.', D(12)],
        ['<code>capture_factory</code>', '—', 'none', 'Callable creating a fresh capture with a distinct output for each physical connection, including routing/recovery. Required for pool recording; loans of the same transport keep its capture. The application owns/closes Python capture resources.', D(12)],
      ], 'compact')}
      <p><b>Login features.</b> <code>features</code> is a list of <code>tds.Feature</code>. The command-line switches turn each feature on or off, overriding its default.</p>
      ${table(['Feature', 'Command line', 'Default', 'Version sent', 'What it changes'], [
        ['<code>JSON_SUPPORT</code>', '<code>--json-support</code>', 'on', '1', '<code>json</code> columns arrive as <code>json</code>, not as text.'],
        ['<code>VECTOR_SUPPORT</code>', '<code>--vector-support</code>', 'on', '2', '<code>vector</code> columns arrive as vectors of float32 or float16, not as text.'],
        ['<code>UTF8_SUPPORT</code>', '<code>--utf8-support</code>', 'on', '1', `Text in a UTF-8 collation arrives as stored, invalid bytes included; <code>json</code> arrives as UTF-8 (${L('ref/types', 'Data Types', 'edge-cases')}).`],
        ['<code>DATA_CLASSIFICATION</code>', '<code>--data-classification</code>', 'on', '2', 'A result whose columns are classified says how, with ranks (<code>ResultSet.classification</code>).'],
        ['<code>SESSION_RECOVERY</code>', '<code>--session-recovery</code>', 'on', '— (no data; a recovery login sends the session)', `A broken connection’s session can be recovered (${L('ref/connect', 'Session recovery', 'session-recovery')}).`],
        ['<code>COLUMN_ENCRYPTION</code>', '<code>--column-encryption</code>', 'off', '1; 2 for enclaves', `Always Encrypted: every result’s column descriptions carry a key table, and each encrypted column carries its crypto metadata. <code>tds.encryption</code> asks for it (version 2 when it uses enclaves) and decrypts the values (${L('ref/always-encrypted', 'Always Encrypted')}). If the feature is asked for without <code>tds.encryption</code>, encrypted values arrive as ciphertext.`],
        ['<code>AZURE_SQL_SUPPORT</code>', '<code>--azure-sql-support</code>', 'off', '1', 'Azure SQL: failover partner login with read-only intent. Azure SQL Database acknowledged it (1).'],
        ['<code>AZURE_DNS_CACHING</code>', '<code>--azure-dns-caching</code>', 'off', '—', `Azure SQL may say the client can cache its address. Azure SQL Database acknowledged it (1). The driver caches nothing itself; caching is the application’s choice (${D(39)}).`],
        ['<code>ENHANCED_ROUTING</code>', '<code>--enhanced-routing</code>', 'off', '—', 'Routing that names a database too (ENVCHANGE 21). The test server acknowledged it with 0, meaning not enabled.'],
        ['<code>GLOBAL_TRANSACTIONS</code>', '<code>--global-transactions</code>', 'off', '—', 'Azure SQL’s elastic transactions across databases. Azure SQL Database acknowledged it (1).'],
      ], 'compact')}
      <p><code>connect(features=…)</code> can also give a feature’s data, as <code>(feature, data)</code>. <code>tds.encryption</code> asks for column encryption version 2 this way. Federated authentication isn’t asked for as a feature; it is part of the login itself (<code>login=EntraToken(…)</code>). The user agent feature is left out. SQL Server ignores it, and the driver is identified already (${D(8)}).</p>

      <h2>Example</h2>
      <p>The ${L('example', 'Worked Example')} follows the 7.4 path step by step: hello → secure → log in → ready.</p>

      <h2>Edge cases</h2>
      <ul>
        <li><b>Login-only encryption</b> (both sides said <i>off</i>): TLS encrypts only the login packet, and everything after it is unencrypted. The driver refuses it (${D(10)}).</li>
        <li><b>8.0:</b> the hello’s encryption value is ignored, and no second TLS handshake follows it.</li>
        <li><b>A named instance’s port</b> comes from the ${L('ref/browser', 'Browser')}, before connecting.</li>
        <li><b>The dedicated administrator connection (DAC)</b> is SQL Server’s reserved connection for an administrator, for when the server is too busy or unresponsive to accept a normal one. It is this same procedure on another port: 1434 on a default instance, otherwise the port the Browser gives. Only one DAC can be open at a time, only for sysadmins, and from another machine only when <i>remote admin connections</i> is on. The test container has it on, and forwards the DAC as port 14345.</li>
      </ul>
      <p><b>What MS-TDS doesn’t state.</b> Observed from SQL Server 2025 (17.0.5015), or Azure SQL Database where named.</p>
      <ul>
        <li><b>SQL Server accepts 8.0 only once it has a certificate configured.</b> Without one, it closes the connection when the client starts with TLS. The test container’s setup is in <code>docker/macos/tls</code>.</li>
        <li><b>Under 8.0, SQL Server answers the hello’s encryption option with <i>not supported</i>,</b> because TLS is already running.</li>
        <li><b>Under 8.0, the login reply still says TDS 7.4</b> (<code>74 00 00 04</code>). Only ALPN says 8.0.</li>
        <li><b>A refused DAC closes the connection at the hello, with no message:</b> for example, a second DAC while one is open. SQL Server gives the reason only in its error log. The driver’s error says so.</li>
        <li><b>Under 7.4, SQL Server negotiates TLS 1.2 at most,</b> even when the client offers 1.3. A context that requires TLS 1.3 makes the server close the connection during the handshake; under 8.0, TLS 1.3 is negotiated.</li>
        <li><b>Which server name a routed login sends:</b> MS-TDS doesn’t say. Azure SQL’s nodes need the routed server and its port, as <code>server,port</code>; the name the application asked for is refused, with error 40613 and the message saying <code>server ''</code> (observed, Azure SQL Database, connection policy Redirect; SqlClient sends the same). The driver sends <code>server,port</code>.</li>
        <li><b>Azure SQL with connection policy Redirect routes every connection, from outside Azure too:</b> the gateway’s LOGINACK comes with a routing announcement to a node (<code>….worker.database.windows.net:11063</code>), where the login is made again. Under TDS 8.0 the node’s certificate is valid for the node’s own name.</li>
        <li><b>Session recovery,</b> observed:
          <ul>
            <li><b>What comes back:</b> the database, language and collation; the SET options (ANSI_NULLS, QUOTED_IDENTIFIER, NOCOUNT, XACT_ABORT, IMPLICIT_TRANSACTIONS and the rest); DATEFIRST and DATEFORMAT; TEXTSIZE; LOCK_TIMEOUT; DEADLOCK_PRIORITY; the isolation level; ROWCOUNT; CONTEXT_INFO.</li>
            <li><b>What doesn’t:</b> values set with <code>sp_set_session_context</code>. The server reports no state for them, so a recovered session doesn’t have them.</li>
            <li><b>What the server doesn’t allow to be recovered:</b> it marks the session with state 254, whose value names why: 4, a transaction is open; 5, a temporary table exists (local or global); 13, the session is impersonating another login (<code>EXECUTE AS</code>); 3, the session was killed while a request ran. The mark is removed when the cause ends (the transaction ends, the table is dropped, <code>REVERT</code>). MS-TDS defines neither the state nor its codes. The driver names the codes it has seen, and shows any other code as it arrived.</li>
            <li><b>A session killed while idle can be recovered:</b> no response carries a mark, so the last state is still recoverable.</li>
            <li><b>The recovery login’s reply</b> announces the recovered database, language and collation, and acknowledges session recovery; it carries no SESSIONSTATE.</li>
          </ul></li>
      </ul>

      ${source('§2.1, §2.2.6.5, §3.1.5 (figures 3–4), §3.2.2, §3.2.4, §3.2.5.1–§3.2.5.4, §3.2.5.10')}`,
  });
})();
