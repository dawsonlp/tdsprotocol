/* Reference: Token Stream. */
(function () {
  const { T, L, grid, table, source } = window.TDS;
  const RULES = {
    fixed: 'fixed', u16: 'length-prefixed (u16)', u32: 'length-prefixed (u32)', counted: 'counted', walked: 'walked',
  };
  const tags = [
    ['81', 'COLMETADATA', 'counted', 'results'], ['88', 'ALTMETADATA', 'counted', 'results with COMPUTE, which SQL Server no longer supports'],
    ['A3', 'DATACLASSIFICATION', 'walked', 'results, when the login asked for data classification'], ['A4', 'TABNAME', 'u16', 'results in browse mode, and from server cursors'], ['A5', 'COLINFO', 'u16', 'results in browse mode, and from server cursors'],
    ['A9', 'ORDER', 'u16', 'results'], ['AA', 'ERROR', 'u16', 'any reply'], ['AB', 'INFO', 'u16', 'any reply'],
    ['AC', 'RETURNVALUE', 'walked', 'procedure results'], ['AD', 'LOGINACK', 'u16', 'login reply'],
    ['AE', 'FEATUREEXTACK', 'walked', 'login reply'], ['D1', 'ROW', 'walked', 'results'], ['D2', 'NBCROW', 'walked', 'results'],
    ['D3', 'ALTROW', 'walked', 'as ALTMETADATA'], ['E3', 'ENVCHANGE', 'u16', 'any reply'], ['E4', 'SESSIONSTATE', 'u32', 'any reply, when the login asked for session recovery'],
    ['ED', 'SSPI', 'u16', 'login reply (Windows auth)'], ['EE', 'FEDAUTHINFO', 'u32', 'login reply (federated auth)'],
    ['79', 'RETURNSTATUS', 'fixed', 'procedure results (4 bytes)'],
    ['FD', 'DONE', 'fixed', 'any reply, always last (12 bytes)'], ['FE', 'DONEPROC', 'fixed', 'procedure results (12 bytes)'],
    ['FF', 'DONEINPROC', 'fixed', 'procedure results (12 bytes)'],
  ];

  window.TDS.page({
    id: 'ref/token-stream', group: 'Reference', kind: 'reference',
    title: 'Token Stream',
    where: 'message › <b>body</b>, when the body is a token stream › token › field.',
    outcome: 'read any token stream: find where each token ends, and know which tokens can appear.',
    body: () => `
      <h2>Purpose</h2>
      <p>Most server messages are ${T('token stream', 'token streams')}: ${T('token', 'tokens')} one after another, with no separators.
      To read the next token, a reader must know where the current one ends. Each token has its own rule for that.</p>

      <h2>Shape</h2>
      <p>A 1-byte <b>tag</b>, then a body whose end is found by one of four <b>length rules</b>:</p>
      ${table(['Rule', 'How the body’s end is found', 'Tokens'], [
        ['<b>fixed</b>', 'The body is always the same size.', 'DONE, DONEPROC, DONEINPROC (12 bytes) · RETURNSTATUS (4)'],
        ['<b>length-prefixed</b>', 'A u16 (or u32) after the tag gives the body size.', 'ENVCHANGE, ERROR, INFO, LOGINACK, ORDER, TABNAME, COLINFO, SSPI · <i>u32:</i> SESSIONSTATE, FEDAUTHINFO'],
        ['<b>counted</b>', 'A u16 count of columns follows, and each column is walked.', 'COLMETADATA, ALTMETADATA'],
        ['<b>walked</b>', 'There is no size field. The body is read field by field, up to a terminator or as the column metadata says.', 'FEATUREEXTACK, DATACLASSIFICATION, RETURNVALUE · <i>against the last COLMETADATA:</i> ROW, NBCROW · <i>against the ALTMETADATA with its id:</i> ALTROW'],
      ])}

      <h3>Tags</h3>
      ${table(['Tag', 'Token', 'Rule', 'Seen in'], tags.map(([t, n, r, s]) => [`<code>${t}</code>`, n, RULES[r], s]), 'compact')}

      <h2>Rules</h2>
      <ul>
        <li><b>Each definition declares its length rule.</b> MS-TDS says certain bits of the tag encode its length rule, but several tags contradict that:
          <ul>
            <li>DONE’s bits claim 8 bytes, but it has been 12 since TDS 7.2.</li>
            <li>FEATUREEXTACK, DATACLASSIFICATION and RETURNVALUE sit in the length-prefixed group, but have no length field.</li>
          </ul>
          So the bits are never used. Each token’s definition states its rule.</li>
        <li><b>An unknown tag ends the connection.</b> Without its rule, there is no way to find where the token ends, so the message is malformed. The driver defines every tag TDS 7.4 defines (M11). OFFSET (<code>78</code>) was removed in TDS 7.2, so a 7.4 server never sends it.</li>
        <li><b>A reply ends at a DONE-family token whose “more” bit is clear.</b> See ${L('ref/login-response', 'Login Response', 'done')}.</li>
      </ul>

      <h2>Example</h2>
      <p>The login reply from the Worked Example uses two of the rules: length-prefixed (ENVCHANGE, INFO, LOGINACK) and fixed (DONE). Hover over a tag, then over its length.</p>
      ${grid('login-reply', { title: 'A token stream: the login reply' })}

      <h2>Edge cases</h2>
      <ul><li>TVP_ROW (<code>01</code>) appears only inside client procedure-call requests, never from the server.</li></ul>
      <p><b>Where SQL Server differs from MS-TDS.</b> Observed from SQL Server 2025 (17.0.5015).</p>
      <ul><li><b>A <i>promote transaction</i> ENVCHANGE runs past its length.</b> MS-TDS says the length is that of everything after it. SQL Server writes <code>E3 01 00 0F</code>: a length of 1, covering only the kind. Then come the coordinator’s token (a u32 length, then that many bytes) and the empty old value (<code>00</code>). A reader that trusts the length reads the token’s first byte as the next tag. The driver’s ENVCHANGE definition reads this kind by its fields, not its length.</li></ul>

      ${source('§2.2.4, §2.2.5.8, §2.2.7')}`,
  });
})();
