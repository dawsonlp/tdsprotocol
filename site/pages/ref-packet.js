/* Reference: Packet. Template: purpose → shape → rules → example → edge cases → source. */
(function () {
  const { T, L, grid, table, source } = window.TDS;

  window.TDS.page({
    id: 'ref/packet', group: 'Reference', num: '3', kind: 'reference',
    title: 'Packet',
    where: 'connection › <b>packet</b> › message.',
    outcome: 'read or build any packet header, and split a message into packets or join packets back into one.',
    body: () => `
      <h2>Purpose</h2>
      <p>A ${T('packet')} is the unit written to the wire. Its header tells the receiver which kind of ${T('message')}
      the packet belongs to, whether more packets follow, and where this packet ends.</p>

      <h2>Shape</h2>
      <p>The header is always eight bytes. Hover over each field to see its meaning.</p>
      ${grid('packet-header', { cols: 8, title: 'Packet header' })}

      <h3>Types</h3>
      ${table(['Value', 'Message', 'Sent by'], [
        ['<code>01</code>', 'SQL batch', 'client'],
        ['<code>03</code>', 'remote procedure call', 'client'],
        ['<code>04</code>', '<b>every server message</b>', 'server'],
        ['<code>06</code>', 'cancel', 'client (header only, no payload)'],
        ['<code>07</code>', 'bulk load data', 'client'],
        ['<code>08</code>', 'federated auth token', 'client'],
        ['<code>0E</code>', 'transaction manager request', 'client'],
        ['<code>10</code>', 'login', 'client'],
        ['<code>11</code>', 'Windows auth continuation', 'client'],
        ['<code>12</code>', 'hello; in 7.4 it also carries the TLS handshake', 'client, and server during the handshake'],
      ], 'compact')}

      <h3>Status flags</h3>
      ${table(['Bit', 'Meaning'], [
        ['<code>01</code>', '<b>end</b>: the last packet of the message'],
        ['<code>02</code>', 'ignore: abandon this partly sent message (sent together with <code>01</code>)'],
        ['<code>08</code>', 'reset the session before running this request (first packet only)'],
        ['<code>10</code>', 'as <code>08</code>, but keep the current transaction (first packet only)'],
      ], 'compact')}

      <h2>Rules</h2>
      <ul>
        <li><b>One message, one or more packets.</b> All of a message’s packets share its type, and only the last has <i>end</i> set.</li>
        <li><b>A new message always starts a new packet.</b></li>
        <li><b>Packet size</b> is the maximum packet length. It is 4096 until the server announces a new value in the login reply, and is always between 512 and 32767.</li>
        <li><b>Splitting:</b> every client packet except the last in a message is exactly the packet size.</li>
        <li><b>Unknown or unexpected type:</b> close the connection.</li>
      </ul>

      <h2>Example</h2>
      <p>Every message in the ${L('example', 'Worked Example')} starts with one of these headers.</p>

      <h2 id="edge-cases">Edge cases</h2>
      <ul>
        <li><b>Packet number start value:</b> implementations start at 0 or 1. Either is valid.</li>
        <li><b>TLS in 7.4:</b> during the handshake, TLS records are the payload of type <code>12</code> packets. After the handshake, the packets themselves, headers included, travel inside TLS.</li>
        <li><b>Encrypt packet by packet:</b> each TLS record must carry whole packets. If a multi-packet message is encrypted in one piece, TLS splits it into records at arbitrary points, and SQL Server closes the connection. MS-TDS doesn’t say this. It was observed with SQL Server 2025, and Microsoft’s drivers write packets the same way.</li>
      </ul>

      ${source('§2.2.3')}`,
  });
})();
