/* Reference: Browser (MC-SQLR). */
(function () {
  const { L, D, grid, table, source } = window.TDS;

  window.TDS.page({
    id: 'ref/browser', group: 'Reference', kind: 'reference',
    title: 'Browser',
    where: 'Before connecting, and outside TDS. The SQL Server Browser answers on UDP port 1434, saying where a machine’s instances listen. The client then connects with TDS as usual.',
    outcome: 'find a named instance’s port, list a machine’s or a network’s instances, or find an instance’s DAC port, and read or build the datagrams that do it.',
    body: () => `
      <h2>Purpose</h2>
      <p>A default instance listens on TCP 1433. A named instance listens on a port of its own, often a new one each time it starts, so a client that knows only the instance’s name must ask for it.
      The Browser is the Windows service that knows these ports. Its protocol is MC-SQLR, the SQL Server Resolution Protocol, a separate Microsoft specification beside MS-TDS (<a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-sqlr/">Microsoft Learn</a>).</p>

      <h2>Shape</h2>
      <p>One request datagram; one reply datagram from each machine that answers. Integers are little-endian. Text is in the code page the client and server share.</p>
      ${table(['First byte', 'Request', 'Then', 'Sent to', 'Answered with'], [
        ['<code>02</code>', 'every instance on the network (CLNT_BCAST_EX)', '—', 'a broadcast address (IPv4) or multicast (IPv6)', 'each machine’s instances, as text'],
        ['<code>03</code>', 'every instance on one machine (CLNT_UCAST_EX)', '—', 'the machine', 'its instances, as text'],
        ['<code>04</code>', 'one instance (CLNT_UCAST_INST)', 'the instance name, ended by <code>00</code> (at most 32 bytes)', 'the machine', 'that instance, as text'],
        ['<code>0F</code>', 'one instance’s DAC port (CLNT_UCAST_DAC)', 'protocol version <code>01</code>, then the instance name, ended by <code>00</code>', 'the machine', 'the DAC port'],
      ], 'compact')}
      <p>Every reply (SVR_RESP) starts with <code>05</code>:</p>
      ${table(['Reply to', 'Bytes'], [
        ['<code>02</code>, <code>03</code>, <code>04</code>', '<code>05</code>, the text’s length (u16), the text'],
        ['<code>0F</code>', '<code>05</code>, the reply’s whole length (u16, always <code>06 00</code>), protocol version <code>01</code>, the DAC port (u16)'],
      ], 'compact')}
      <p>The text describes one or more instances. Each is a list of <code>;</code>-separated name–value pairs, ending in <code>;;</code>:</p>
      <pre>ServerName;ILSUNG1;InstanceName;YUKONSTD;IsClustered;No;Version;9.00.1399.06;tcp;57137;;</pre>
      <p>The first four pairs are always <i>ServerName</i>, <i>InstanceName</i>, <i>IsClustered</i> (<code>Yes</code> or <code>No</code>) and <i>Version</i>. Then come the endpoints the instance listens on, in any order, each at most once:</p>
      ${table(['Name', 'Value'], [
        ['<code>tcp</code>', 'the TCP port, in decimal'],
        ['<code>np</code>', 'the named pipe, such as <code>\\\\ILSUNG1\\pipe\\sql\\query</code>'],
        ['<code>via</code>', 'a NetBIOS name, then <code>,nic:port</code> pairs (VIA, retired)'],
        ['<code>rpc</code>', 'a computer name (multiprotocol, retired)'],
        ['<code>spx</code>', 'a service name (SPX, retired)'],
        ['<code>adsp</code>', 'an AppleTalk object name (retired)'],
        ['<code>bv</code>', 'Banyan VINES item, group and organization names, several <code>;</code>-separated parts (retired)'],
      ], 'compact')}

      <h2>Rules</h2>
      <ul>
        <li><b>The Browser sends no reply when it has no answer.</b> A request it doesn’t understand, or for an instance it doesn’t have, is ignored, because MC-SQLR has no negative reply. The client waits until its timer ends, and can’t distinguish those cases from a machine with no Browser.</li>
        <li><b>The client’s timer:</b> MC-SQLR suggests 1 second for an instance or DAC request, and leaves the others to the client. The driver waits 1000 ms for every request unless <code>timeout_ms=…</code> says otherwise (${D(59)}).</li>
        <li><b>A broadcast collects replies until the timer ends,</b> because every machine that receives it may answer. A reply that can’t be read is ignored, as MC-SQLR requires; for a request sent to one machine, it is an error.</li>
        <li><b>Words aren’t case-sensitive:</b> <code>ServerName</code>, <code>SERVERNAME</code> and <code>servername</code> are the same.</li>
        <li><b>The DAC reply’s length is counted differently.</b> It is the length of the whole reply (6), whereas every other reply’s length counts only the text after it.</li>
        <li><b>Text is in a shared code page, never named on the wire.</b> MC-SQLR assumes the client’s and the server’s are the same. The driver uses ASCII unless told to use another code page (${D(59)}). A name that ASCII can’t encode is refused before it is sent, and a reply that ASCII can’t decode is reported with the byte that failed. The driver never guesses. ${L('ref/browser', 'Another code page', 'another-code-page')} says how to use one.</li>
        <li><b>Limits:</b> an instance name sent is at most 32 bytes; a longer one is refused. A reply’s text is at most 1,024 bytes per instance; MC-SQLR says a client <i>should</i> reject an endpoint value over 255 bytes. The driver doesn’t reject it, and shows what arrived.</li>
      </ul>

      <h2>Example</h2>
      <p>Asking a machine for its instance YUKONSTD, and the reply:</p>
      ${grid('sqlr-instance-request')}
      ${grid('sqlr-instance-reply')}
      <p>The client then connects with TDS to ILSUNG1, port 57137. Asking for YUKONSTD’s DAC port: port <code>0xDF32</code>, 57138.</p>
      ${grid('sqlr-dac-request')}
      ${grid('sqlr-dac-reply')}
      <p>In code:</p>
      <pre>instance = await tds.browser.instance("db.example.com", "SALES")     # one instance; .tcp_port, .protocols, .address
found = await tds.browser.machine("db.example.com")                  # every instance on that machine
found = await tds.browser.broadcast()                                # every instance that answers 255.255.255.255
port = await tds.browser.dac_port("db.example.com", "SALES")         # the DAC port</pre>
      <p>A failure is a <code>BrowserError</code> that names the request, the machine and the port, and what may explain it: no reply in time, nothing listening (the machine refused the port), or a reply that can’t be read, with its bytes.</p>
      <p>Every call takes <code>port=</code> (default 1434), <code>timeout_ms=</code> (default 1000) and <code>encoding=</code> (default <code>"ascii"</code>).</p>
      <p><b>Then connect.</b> The Browser gives a port, and connecting to it is the application’s next step: <code>tds.connect(host, instance.tcp_port, …)</code>. The driver doesn’t combine the two steps. A connector that combines them is a convenience, in a layer around the driver (${D(39)}, ${D(59)}).</p>

      <h3 id="another-code-page">Another code page</h3>
      <p>The Browser runs on Windows, and writes its text in the machine’s ANSI code page. To find it, run this in PowerShell on that machine:</p>
      <pre>(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage).ACP      # for example, 1252</pre>
      <p>Then pass the matching Python codec, which is <code>cp</code> followed by the number:</p>
      ${table(['ACP', 'Used for', '<code>encoding=</code>'], [
        ['1252', 'Western European languages', '<code>"cp1252"</code>'],
        ['1250', 'Central European', '<code>"cp1250"</code>'],
        ['1251', 'Cyrillic', '<code>"cp1251"</code>'],
        ['932', 'Japanese', '<code>"cp932"</code>'],
        ['936', 'Simplified Chinese', '<code>"cp936"</code>'],
        ['949', 'Korean', '<code>"cp949"</code>'],
        ['950', 'Traditional Chinese', '<code>"cp950"</code>'],
      ], 'compact')}
      <pre>instance = await tds.browser.instance("db.example.com", "VERKÄUFE", encoding="cp1252")</pre>
      <p>ASCII is the same in each of these code pages, so ASCII names work with any of them. A name with other characters needs the right code page. With the wrong one, a character may be refused before sending (<i>can’t be written in…</i>), or a byte of a reply may fail to decode (<i>the text isn’t ascii: byte 0xe9…</i>). Worse, both code pages may contain the bytes but map them to different characters, and nothing can detect it. The Browser then doesn’t recognize the name, and doesn’t answer.</p>

      <h2>Edge cases</h2>
      <ul>
        <li><b>The default instance is named <code>MSSQLSERVER</code>.</b> Ask for it by that name.</li>
        <li><b>SQL Server on Linux has no Browser.</b> A Linux server, like the test container, is reached by its port. The Browser was tested live in M17, on Windows.</li>
        <li><b>A firewall usually blocks UDP 1434.</b> When it does, every request goes unanswered, and the error says so.</li>
        <li><b>Knowing the DAC port doesn’t mean the DAC accepts the connection.</b> From another machine, the DAC needs <i>remote admin connections</i> on, as in the test container (${L('ref/connect', 'Connect', 'edge-cases')}).</li>
      </ul>
      <p><b>What MC-SQLR doesn’t state clearly.</b></p>
      <ul>
        <li><b>Banyan VINES:</b> its grammar names the item and group twice (<code>bv;item;group;item;group;org</code>). The driver takes every part up to the next endpoint’s name as the value, as sent.</li>
        <li><b>IPv6:</b> MC-SQLR sends the broadcast request by multicast over IPv6, but names no multicast group. The driver broadcasts over IPv4 only.</li>
      </ul>

      ${source('§2.1, §2.2.1–§2.2.6, §3.1.5.2, §3.2.2, §3.2.5, §4', 'MC-SQLR')}`,
  });
})();
