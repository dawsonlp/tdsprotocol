/* Reference: Login Response. */
(function () {
  const { T, L, D, grid, table, source } = window.TDS;

  window.TDS.page({
    id: 'ref/login-response', group: 'Reference', kind: 'reference',
    title: 'Login Response',
    where: 'The server’s answer to <i>log in</i>. Its body is a <b>token stream</b>. Its packet type is <code>04</code>.',
    outcome: 'read a login reply and decide whether the login succeeded, failed or was redirected.',
    body: () => `
      <h2>Purpose</h2>
      <p>The server either accepts the login and describes the new session, rejects it and says why, or redirects the client to another server.</p>

      <h2>Shape</h2>
      <p>A ${T('token stream')}. A login reply contains:</p>
      ${window.TDS.flow([
        { label: 'ENVCHANGE · INFO · ERROR', sub: 'any number, any order' }, { label: 'LOGINACK', sub: 'if accepted' },
        { label: 'FEATUREEXTACK', sub: 'if features were requested' }, { label: 'ENVCHANGE', sub: 'routing, if redirected' },
        { label: 'DONE', kind: 'end', sub: 'always last' },
      ])}
      <p>Only two positions are fixed: <code>DONE</code> comes last, and a routing <code>ENVCHANGE</code> comes after <code>LOGINACK</code>.</p>

      <h3>Text and byte values</h3>
      ${table(['Shape', 'Layout', 'MS-TDS name'], [
        ['short text', 'u8 character count, then UTF-16LE', 'B_VARCHAR'],
        ['long text', 'u16 character count, then UTF-16LE', 'US_VARCHAR'],
        ['short bytes', 'u8 byte count, then bytes', 'B_VARBYTE'],
      ], 'compact')}

      <h3 id="envchange"><code>E3</code> ENVCHANGE: a session setting changed</h3>
      <p>The tag, a u16 length and a u8 kind, then a new and an old value whose shape depends on the kind:</p>
      ${table(['Kind', 'Setting', 'New / old values'], [
        ['1', 'database', 'short text / short text'],
        ['2', 'language', 'short text / short text'],
        ['4', 'packet size', 'short text / short text: a decimal number written as text, such as <code>"4096"</code>'],
        ['7', 'collation', 'short bytes (5) / short bytes'],
        ['13', 'mirroring partner', `short text / empty. The new value is database mirroring’s partner server. The driver keeps it as <code>connection.session.mirroring_partner</code> and never connects to it on its own (${D(58)})`],
        ['20', '<b>routing</b>', 'u16 length, protocol u8 (<code>0</code> = TCP), port u16, server as long text / <code>00 00</code>'],
        ['21', '<b>routing to a database</b>', 'as 20, plus the database as long text / <code>00 00</code>'],
      ], 'compact')}

      <h3 id="info-error"><code>AB</code> INFO and <code>AA</code> ERROR: a message from the server</h3>
      <p>The two tokens share one layout:</p>
      <ul>
        <li>tag and u16 length;</li>
        <li>number i32, state u8, class u8 (below 10 is informational);</li>
        <li>message as long text, server name and procedure as short text;</li>
        <li>line i32.</li>
      </ul>

      <h3 id="loginack"><code>AD</code> LOGINACK: the login is accepted</h3>
      <p>Tag and u16 length, then:</p>
      <ul>
        <li>interface u8 (<code>1</code> = T-SQL);</li>
        <li>TDS version, 4 bytes (<code>74 00 00 04</code> = 7.4);</li>
        <li>server program as short text;</li>
        <li>server version: major, minor, build (2 bytes).</li>
      </ul>

      <h3 id="featureextack"><code>AE</code> FEATUREEXTACK: requested features accepted</h3>
      <p><i>(feature u8, length u32, data)</i> entries ending in <code>FF</code>. There is <b>no overall length</b>. The reader finds the end by walking the entries. The client keeps the accepted features as <code>connection.features</code>. SQL Server 2025 was observed to return JSON support <code>01</code> and vector support <code>01</code>.</p>

      <h3 id="done"><code>FD</code> DONE: end of the reply</h3>
      <p>Tag, then:</p>
      <ul>
        <li>status u16: <code>00</code> final · <code>01</code> more follows · <code>02</code> error · <code>10</code> row count valid · <code>20</code> cancel acknowledged · <code>100</code> severe error;</li>
        <li>current command u16;</li>
        <li>row count u64.</li>
      </ul>

      <h2>Rules</h2>
      <ul>
        <li><b>Success means a LOGINACK is present.</b> If there is none, the login failed, the ERROR tokens say why, and the client closes the connection.</li>
        <li><b>Version check:</b> on a 7.4 connection, LOGINACK must report 7.4. Anything lower fails, and the error names the version the server sent (${D(2)}).</li>
        <li><b>Apply every ENVCHANGE</b> to the ${T('session state')}. The new packet size takes effect from the <b>next</b> message.</li>
        <li><b>Routing:</b> if a routing ENVCHANGE follows LOGINACK, read the rest of the reply up to DONE. Then discard everything else in the reply, close the connection, and connect to the named server instead. If the routing names a database, use that database on the new server. The driver does this once, automatically, unless <code>connect(follow_routing=False)</code> turns it off (${D(11)}).</li>
      </ul>

      <h2>Example</h2>
      ${grid('login-reply')}

      <h2>Edge cases</h2>
      <ul>
        <li>The server program name may end with two NUL characters (MS-TDS’s own sample does). Trim them.</li>
        <li>In 8.0, LOGINACK reports 7.4 (<code>74 00 00 04</code>); version 8.0 itself was agreed by ALPN during the TLS handshake. Observed from SQL Server 2025 (17.0.5015).</li>
      </ul>

      ${source('§2.2.7.6, §2.2.7.9–§2.2.7.11, §2.2.7.13–§2.2.7.14, §3.2.5.4, §3.2.5.10')}`,
  });
})();
