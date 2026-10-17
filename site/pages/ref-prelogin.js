/* Reference: PRELOGIN (hello). */
(function () {
  const { T, L, D, grid, table, source } = window.TDS;

  window.TDS.page({
    id: 'ref/prelogin', group: 'Reference', kind: 'reference',
    title: 'PRELOGIN (hello)',
    where: 'The first message of the <i>connect</i> conversation. Its body is a <b>structure</b>. Its packet type is <code>12</code>, and the server’s reply has packet type <code>04</code>.',
    outcome: 'read or build a hello or a hello reply, and determine the encryption outcome.',
    body: () => `
      <h2>Purpose</h2>
      <p>Before logging in, the two sides exchange versions and agree on encryption. The client also names the server instance it expects.</p>

      <h2>Shape</h2>
      <p>A <b>directory</b> of <i>(option, offset, length)</i> entries ending in a single <code>FF</code>, then the <b>data</b> the entries point to.
      Offsets count from the start of the ${T('body')}, and both offsets and lengths are big-endian.</p>
      ${table(['Value', 'Option', 'Value layout', 'Notes', 'MS-TDS name'], [
        ['<code>00</code>', 'version', 'major u8, minor u8, build u16 BE, sub-build u16', '<b>Must be first</b>', 'VERSION'],
        ['<code>01</code>', 'encryption', 'u8: <code>00</code> off · <code>01</code> on · <code>02</code> not supported · <code>03</code> required', 'Ignored in 8.0', 'ENCRYPTION'],
        ['<code>02</code>', 'instance', 'client: instance name + <code>00</code>; server: <code>00</code> match · <code>01</code> mismatch', '', 'INSTOPT'],
        ['<code>03</code>', 'thread id', 'u32 (client); empty from the server', 'Debugging only', 'THREADID'],
        ['<code>04</code>', 'MARS', 'u8: <code>00</code> off · <code>01</code> on', '', 'MARS'],
        ['<code>05</code>', 'trace id', '16-byte connection id, 16-byte activity id, u32 sequence', 'Optional', 'TRACEID'],
        ['<code>06</code>', 'fed auth required', 'u8', 'Only for choosing between Windows and federated auth', 'FEDAUTHREQUIRED'],
        ['<code>07</code>', 'nonce', '32 bytes', 'Only for some federated auth', 'NONCEOPT'],
        ['<code>FF</code>', 'end of directory', '—', '<b>Must be last</b>', 'TERMINATOR'],
      ], 'compact')}

      <h2>Rules</h2>
      <ul>
        <li><b>Version first, end marker last.</b> A server closes the connection if version isn’t the first option.</li>
        <li><b>Instance check.</b> If the reply’s instance value is <code>01</code>, the client reached the wrong instance and should close the connection.</li>
        <li><b>After the reply (7.4):</b> if encryption was agreed, the TLS handshake follows immediately, carried in type <code>12</code> packets. In 8.0, TLS is already established, so the encryption option is ignored.</li>
      </ul>
      <h3 id="encryption-outcome">Encryption outcome (7.4)</h3>
      ${table(['Client says', 'Server says', 'Result'], [
        ['on', 'on / required', '<b>whole connection encrypted</b>'],
        ['on', 'not supported', 'server closes the connection'],
        ['off', 'off', 'only the login packet is encrypted'],
        ['off', 'required', 'whole connection encrypted'],
        ['off / not supported', 'not supported', 'no encryption'],
        ['not supported', 'required', 'server closes the connection'],
      ], 'compact')}
      <p>The driver accepts only an outcome that encrypts the whole connection. Any other outcome fails, with an explanation (${D(10)}).</p>

      <h2>Example</h2>
      ${grid('prelogin-request')}

      <h2>Edge cases</h2>
      <ul>
        <li>Options the receiver doesn’t know about are skipped using their offset and length.</li>
        <li>The thread id is little-endian, unlike the rest of PRELOGIN.</li>
        <li>A client asking for certificate login adds <code>80</code> to its encryption value. The driver doesn’t offer certificate login.</li>
      </ul>

      ${source('§2.2.6.5, §3.2.5.2')}`,
  });
})();
