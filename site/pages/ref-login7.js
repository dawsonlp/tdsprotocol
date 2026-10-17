/* Reference: LOGIN7 (log in). */
(function () {
  const { T, L, D, grid, table, source } = window.TDS;

  window.TDS.page({
    id: 'ref/login7', group: 'Reference', kind: 'reference',
    title: 'LOGIN7 (log in)',
    where: 'The <i>log in</i> step of the connect conversation. Its body is a <b>structure</b>. Its packet type is <code>10</code>.',
    outcome: 'read or build a login message.',
    body: () => `
      <h2>Purpose</h2>
      <p>The client says who it is, how to authenticate it, and how it wants the session set up: database, language, packet size and options.</p>

      <h2>Shape</h2>
      <p>The body has four parts, in this order:</p>
      <ol>
        <li>a <b>fixed part</b> of 36 bytes;</li>
        <li>a <b>pointer table</b> of <i>(offset, length)</i> pairs that point into the data part;</li>
        <li>a <b>data part</b> holding UTF-16LE strings, packed back to back;</li>
        <li>an optional <b>feature list</b> (7.4).</li>
      </ol>
      <p>Hover over any pointer to see where it points.</p>
      ${grid('login7', { title: 'A login, part by part' })}

      <h3>Flags</h3>
      <p>In each flag set, the first bit listed is the lowest bit.</p>
      ${table(['Set', 'Bits, low → high'], [
        ['flags 1', 'byte order (0 = little-endian) · character set (0 = ASCII) · float format, 2 bits · bulk-load off · <b>report database changes</b> · <b>initial database must succeed</b> · <b>report language changes</b>'],
        ['flags 2', '<b>initial language must succeed</b> · ODBC client · 2 reserved · user type, 3 bits · Windows auth'],
        ['type flags', 'SQL dialect, 4 bits · OLE DB client · <b>read-only intent</b> · 2 reserved'],
        ['flags 3', 'change password · binary XML · user instance · unknown-collation handling · <b>feature list present</b> · 3 reserved'],
      ])}

      <p id="flags"><b>The ODBC flag</b> (fODBC, flags 2) chooses the settings a session starts with. When it is set, the server starts the session with ODBC’s defaults: ANSI_NULLS, ANSI_PADDING, ANSI_WARNINGS, CONCAT_NULL_YIELDS_NULL and QUOTED_IDENTIFIER on, no implicit transactions, and unlimited TEXTSIZE. When it is clear, the server’s own defaults apply: those options are off, and TEXTSIZE is 4,096 bytes. The driver sets it, as ODBC, .NET and JDBC clients do, unless <code>connect(odbc=False)</code> clears it (${D(9)}).</p>

      <h3 id="identity">Who the client is</h3>
      <p>Administrators see these in <code>sys.dm_exec_sessions</code> (${D(9)}):</p>
      <ul>
        <li><i>client process id</i>: the real one (<code>host_process_id</code>);</li>
        <li><i>host name</i>: this machine’s name, or the value of <code>connect(host_name=…)</code> (<code>host_name</code>);</li>
        <li><i>application name</i>: <code>tds (python)</code>, or the value of <code>connect(app_name=…)</code> (<code>program_name</code>);</li>
        <li><i>client library name</i>: <code>tds</code> (<code>client_interface_name</code>).</li>
      </ul>
      <p><i>Language</i> is empty unless <code>connect(language=…)</code> sets it. When it is empty, the session starts in the login’s default language. <i>Read-only intent</i> is set by <code>connect(read_only_intent=True)</code>. It is a hint that an availability group uses for routing, and it doesn’t prevent writes. <i>Server name</i> is the host the driver connects to. After routing, it is the host the application asked for. MS-TDS doesn’t say which name to send; this is to be confirmed on Azure (M17).</p>

      <p><b>How the login carries each way of logging in</b> (${L('ref/conversations', 'Conversations', 'what-each-way-of-logging-in-needs--built-d-54-d-55')}, ${D(55)}):</p>
      <ul>
        <li><i>SQL Server login:</i> user name and password. To change an expired password, set <i>change password</i> in option flags 3, and put the new password at entry <code>56</code>, scrambled in the same way as the password.</li>
        <li><i>Windows login:</i> <i>Windows (integrated) auth</i> set in option flags 2, no user name or password, and the security library’s first token at entry <code>4E</code>, with its length in bytes. If the token is over 65,535 bytes, its length goes in the u32 at <code>5A</code>.</li>
        <li><i>Entra ID:</i> no user name or password, and the federated authentication feature (<code>02</code>) in the feature list. The feature’s first byte is the library number shifted left by one bit. Bit 0 is set when the FEDAUTHREQUIRED value in the hello reply was 1. For a token sent with the login (library <code>01</code>), the first byte is followed by the token’s length (u32), the token in UTF-16LE, and the nonce from the hello reply, if the server sent one. For a token fetched during the login (library <code>02</code>, MS-TDS’s “ADAL”), the first byte is followed by a workflow byte: <code>01</code> password, <code>02</code> integrated, or <code>03</code> for everything else, as Microsoft’s drivers send it.</li>
      </ul>
      <p>These values are credentials. Observability shows only their length, and captures replace them with zeros (${D(12)}).</p>

      <h3 id="feature-list">Feature list (7.4)</h3>
      <p>To send one:</p>
      <ol>
        <li>Set <i>feature list present</i> in flags 3.</li>
        <li>Point the <i>extension</i> entry at a 4-byte offset inside the data part.</li>
        <li>That offset points to the list itself: <i>(feature u8, length u32, data)</i> entries, ending with <code>FF</code>.</li>
      </ol>
      <p><b>The driver sends five by default</b> (${D(8)}): JSON support (version 1), vector support (version 2: float32 and float16), UTF-8 support (version 1), data classification (version 2, with ranks) and session recovery (no data; a recovery login sends the session instead, ${L('ref/connect', 'Connect › Session recovery', 'session-recovery')}). <code>connect(features=…)</code> chooses others. For example, <code>tds.encryption</code> asks for column encryption (${L('ref/always-encrypted', 'Always Encrypted')}). ${L('ref/connect', 'Connect › Options', 'options')} lists the features, what each one changes, and which ones can’t be requested yet. The list goes after the data part, and its length is counted in the login’s total length. Observed: SQL Server 2025 accepts JSON support 1, vector support <b>1</b> (float32 only), UTF-8 support, data classification 2 and session recovery.</p>
      ${table(['Feature', 'Value', 'Feature', 'Value'], [
        ['session recovery', '<code>01</code>', 'UTF-8 support', '<code>0A</code>'],
        ['federated auth', '<code>02</code>', 'Azure DNS caching', '<code>0B</code>'],
        ['column encryption', '<code>04</code>', 'JSON support', '<code>0D</code>'],
        ['global transactions', '<code>05</code>', 'vector support', '<code>0E</code>'],
        ['Azure SQL support', '<code>08</code>', 'enhanced routing', '<code>0F</code>'],
        ['data classification', '<code>09</code>', 'user agent', '<code>10</code>'],
      ], 'compact')}

      <h2>Rules</h2>
      <ul>
        <li><b>Empty strings:</b> set the length to 0, and the offset is ignored. The exception is the host name’s offset, which must point at the start of the data part even when every string is empty.</li>
        <li><b>Limits:</b>
          <ul>
            <li>strings: at most 128 characters each (the attach-file name: 260);</li>
            <li>extension block: at most 255 bytes;</li>
            <li>whole login: at most 128 KB − 1.</li>
          </ul></li>
        <li><b>User name and database</b> are treated as bracket-quoted identifiers, so they must be valid as <code>[name]</code>.</li>
        <li><b>Password scrambling:</b> for each byte of the UTF-16LE password, swap its two 4-bit halves, then XOR the result with <code>A5</code>. For example, <code>a</code> (<code>61 00</code>) becomes <code>B3 A5</code>. This only obscures the password. TLS is what protects it.</li>
        <li><b>Version:</b> the server uses the lower of its own highest version and the client’s. The driver sends 7.4 and checks the version in the reply (${D(2)}).</li>
      </ul>

      <h2>Edge cases</h2>
      <ul>
        <li>In 8.0 the TDS version field is ignored, because the version was agreed in the TLS handshake (ALPN <code>tds/8.0</code>).</li>
        <li>The <i>extension</i> entry is called “unused” in older versions. In 7.4 it is used only when <i>feature list present</i> is set.</li>
      </ul>

      ${source('§2.2.6.4')}`,
  });
})();
