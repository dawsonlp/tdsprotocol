/* Reference: Conversations. A view of docs/design/3-reference/conversations.md (the record, D-29). */
(function () {
  const { T, L, D, table, flow, callout, source } = window.TDS;
  const yes = '<span class="badge badge-agreed">built</span>';
  const no = '<span class="badge badge-open">not yet</span>';

  window.TDS.page({
    id: 'ref/conversations', group: 'Reference', kind: 'reference',
    title: 'Conversations',
    where: 'Above the bytes. A conversation is the ordered exchange of messages between client and server.',
    outcome: 'see every conversation TDS 7.4 and 8.0 define, how each one runs, and which ones this project’s client has built.',
    body: () => `
      <h2>Purpose</h2>
      <p>MS-TDS defines <b>nine distinct conversations</b>, in three families. It draws seven sequence diagrams. They show five conversations, because two are drawn twice: once for 7.x and once for 8.0. The other four conversations appear only in its text.</p>
      ${table(['Family', 'Shared shape', 'Conversations'], [
        ['<b>Connecting</b>', 'hello → secure → log in → ready', '4: one per way of logging in'],
        ['<b>Requests</b>', `one ${T('exchange')}: a request, then the server’s token stream, ending in a final DONE`, '4'],
        ['<b>Control</b>', 'interrupting an exchange that is in progress', '1'],
      ])}

      <h2>Connecting</h2>
      <p>All four share the steps of ${L('ref/connect', 'Connect')}; only <i>log in</i> differs. In TDS 8.0 the secure step comes first. Any of them can end in <b>routed</b> instead of ready (${D(11)}).</p>
      ${flow([{ label: 'hello' }, { label: 'secure' }, { label: 'log in', kind: 'group', sub: 'differs: 1 · 2 · 3 · 4' }, { label: 'ready', kind: 'end' }, { sep: 'or' }, { label: 'routed', kind: 'fail' }])}
      ${table(['#', 'Conversation', 'What <i>log in</i> involves', 'Messages (packet type)', ''], [
        ['1', '<b>SQL Server login</b>', 'a user name and password in LOGIN7', 'LOGIN7 (<code>10</code>) → login reply', `${yes} 7.4`],
        ['2', '<b>Windows login</b> (SSPI)', 'Kerberos or NTLM, negotiated through SPNEGO. The first token is sent in LOGIN7. The server answers with an SSPI token, and the client answers that with an SSPI message when its security library has one. This repeats until authentication is done.', 'LOGIN7 (<code>10</code>) → SSPI token ⇄ SSPI message (<code>11</code>) … → login reply', `${yes} (M17, ${D(55)})`],
        ['3', '<b>Federated login, token in advance</b>', 'the client already holds a token (for example an Entra ID access token) and sends it in LOGIN7’s feature list', 'LOGIN7 (<code>10</code>) → login reply with FEATUREEXTACK', `${yes} (M17, ${D(55)})`],
        ['4', '<b>Federated login, token fetched mid-login</b>', 'the server first tells the client where to get a token, then receives it', 'LOGIN7 (<code>10</code>) → FEDAUTHINFO → token message (<code>08</code>) → login reply', `${yes} (M17, ${D(55)})`],
      ])}

      <h3 id="what-each-way-of-logging-in-needs--built-d-54-d-55">What each way of logging in needs · <i>built, ${D(54)}, ${D(55)}</i></h3>
      <p>Each was built in M17 and tested on Azure (${D(62)}). The tokens come from the application (${D(55)}). <code>connect(login=…)</code> takes a WindowsLogin, an EntraToken or an EntraLogin (<code>tds.logins</code>). Adapters in <code>tds.adapters</code> make them from pyspnego and azure-identity.</p>
      ${table(['Login', 'Server side', 'The client gives', 'Tested'], [
        ['<b>1, variants:</b> changing an expired password at login; a contained database’s user', 'any SQL Server. The new password goes in LOGIN7’s change-password field; a contained user names its database', '<code>connect(…, new_password=…)</code>; <code>connect(…, database=…)</code>', 'the local container'],
        ['<b>2, Kerberos</b>', 'SQL Server on Windows, or on Linux with a key file for its service name (<code>MSSQLSvc/host:port</code>), in an Active Directory domain. On Linux, Kerberos is the only integrated login.', '<code>WindowsLogin(Spnego())</code>: a ticket (kinit), and the server’s full host name, not an address', 'a Windows Server domain controller and SQL Server on Windows, from a Linux VM in the domain’s network'],
        ['<b>2, NTLM</b>', 'SQL Server on Windows only. SQL Server on Linux refuses NTLM for remote connections. No domain is needed; a local Windows account is enough.', '<code>WindowsLogin(Spnego(user, password, "ntlm"))</code>', 'SQL Server on Windows, with a local account and a domain account'],
        ['<b>3, token in advance</b>', 'Azure SQL Database or Managed Instance; SQL Server 2022 or later through Azure Arc, on Windows or Linux but not in a container; or on Windows configured manually, without Arc', '<code>EntraToken(token)</code>: a token for <code>https://database.windows.net/</code>, or a function that gives one', 'Azure SQL Database, as its Entra admin'],
        ['<b>4, token fetched mid-login</b>', 'as 3', '<code>EntraLogin(fetch)</code>: <code>fetch(spn, sts_url)</code> gives a token for the resource the server names', 'as 3'],
      ], 'compact')}
      <p><b>How each ran, observed</b> (SQL Server 2022 on Windows; Azure SQL Database):</p>
      <ul>
        <li><b>NTLM</b> takes three messages before the login reply: the client’s NEGOTIATE in LOGIN7, the server’s CHALLENGE in an SSPI token, and the client’s AUTHENTICATE in an SSPI message (<code>11</code>).</li>
        <li><b>Kerberos</b> takes two: the client’s ticket in LOGIN7, and the server’s SSPI token (its mutual-authentication answer). The server sends the login reply immediately after its SSPI token, without waiting. The client sends nothing in between. An empty SSPI message would arrive after the login, and the server would close the connection.</li>
        <li><b>A wrong Windows password</b> is refused with error 18452, “The login is from an untrusted domain”, not 18456.</li>
        <li><b>Both federated logins</b> echo the hello’s FEDAUTHREQUIRED. The client asks in the hello, and the server answers. In login 4, Azure SQL’s FEDAUTHINFO named a token endpoint and the resource <code>https://database.windows.net/</code>.</li>
      </ul>
      <p>Logins 2–4 start in the hello. A client choosing between a Windows login and a federated one can ask there whether the server requires federated authentication (FEDAUTHREQUIRED), and the server answers. The server may also send a nonce, which the federated login echoes back. The driver asks whenever the login is a federated one, and echoes the answer and any nonce. The driver uses no Kerberos, NTLM or token library itself; the application gives the tokens (${D(55)}).</p>

      <h2>Requests</h2>
      <p>Each is one exchange on a ${T('serial channel')}, except bulk load, which takes two. Batches, RPCs and transaction-manager requests begin with the headers that carry the current transaction descriptor. ${L('ref/response', 'Request Response')} describes how the server’s response is structured.</p>
      ${table(['#', 'Conversation', 'What it’s for', 'Request (packet type)', 'What the response adds', ''], [
        ['5', '<b>SQL batch</b>', 'T-SQL text', 'SQL batch (<code>01</code>)', 'result sets, row counts, messages', yes],
        ['6', '<b>Remote procedure call</b>', 'stored procedures by name; built-ins by number: <code>sp_executesql</code> (10) for parameters; <code>sp_prepare</code> 11, <code>sp_execute</code> 12, <code>sp_prepexec</code> 13, <code>sp_unprepare</code> 15 for prepared statements; cursors 1–9. Several calls can share one message.', 'RPC (<code>03</code>)', '<b>output values</b> and a <b>return status</b>', yes],
        ['7', '<b>Bulk load</b>', 'inserting many rows efficiently; the rows are sent as a stream (D-41)', `exchange 1: <code>INSERT BULK …</code> batch (<code>01</code>); exchange 2: bulk data (<code>07</code>): COLMETADATA, ROW tokens, DONE, as the server would send the same rows, except large values of known length (${L('ref/requests', 'Requests', 'edge-cases')})`, 'row counts', `${yes} (${D(50)})`],
        ['8', '<b>Transaction-manager request</b>', 'transactions through the protocol rather than SQL: begin, commit, roll back, savepoint, and distributed operations (get coordinator address, enlist, promote)', 'transaction manager (<code>0E</code>)', 'announcements of the new transaction state; the coordinator’s address as one row', `${yes} (${D(51)})`],
      ])}

      <h2>Control</h2>
      ${table(['#', 'Conversation', 'How it runs', ''], [
        ['9', '<b>Cancel</b>', 'While a response is open, the client sends an Attention message (<code>06</code>, header only), then reads and discards everything except SESSIONSTATE, up to the DONE marked <i>cancel acknowledged</i>. If the request was only partly sent, the client instead sends its next packet with the <i>ignore</i> and <i>last</i> flags. The server answers with a DONE marked <i>error</i>.', yes],
      ])}

      <h2>Rules</h2>
      <ul>
        <li><b>Connecting happens once per connection;</b> requests and cancels follow on its serial channels.</li>
        <li><b>A request conversation is one exchange</b>, except bulk load, which takes two. So every application operation is built on the same step (${D(33)}).</li>
        <li><b>Cancel is not a request.</b> It doesn’t open an exchange; it ends the one in progress.</li>
      </ul>

      <h2>Example</h2>
      <p>The ${L('example', 'Worked Example')} traces conversation 1 byte by byte. The Python client’s command-line tool runs 1 and then 5.</p>

      <h2>Edge cases</h2>
      <ul>
        <li><b>TDS 7.4 vs 8.0:</b> every conversation exists in both; only <i>when TLS starts</i> differs.</li>
        <li><b>Not conversations:</b> MARS sessions (framing beneath packets, in MC-SMP), connection reset (a flag on the next request), packet-size change (an announcement in the login reply).</li>
        <li><b>Legacy variant:</b> bulk load also has an <code>UPDATETEXT</code>/<code>WRITETEXT BULK</code> form for the old text and image types.</li>
        <li><b>Several calls in one RPC message</b> are separated by a marker: BATCH (run the call before it) or NO-EXEC (don’t run the call before it; the server returns an error for it and continues). The driver uses only BATCH (${D(40)}).</li>
        <li><b>Large values in any request</b> can be sent in chunks without knowing their length in advance, and bulk load’s rows are a stream. Both are streamed requests (${D(41)}), and both are built.</li>
      </ul>

      ${source('§3.1.5 (figures 3–9), §3.2.5, §2.2.1, §2.2.6.1–§2.2.6.9, §2.2.7.12, §2.2.7.22, §4.19')}`,
  });
})();
