/* samples.js — real bytes, split into fields. Only byte counts are given here:
   offsets are computed, values are decoded, and meanings come from fields.js.
   Bytes are from MS-TDS §4 unless marked constructed. */
(function () {
  const TDS = window.TDS;
  const S = TDS.sample;

  const header = () => ({
    cat: 'header', label: 'Packet header',
    fields: [{ f: 'packet.type', n: 1 }, { f: 'packet.status', n: 1 }, { f: 'packet.length', n: 2 },
      { f: 'packet.spid', n: 2 }, { f: 'packet.id', n: 1 }, { f: 'packet.window', n: 1 }],
  });

  /* A PRELOGIN directory entry: option, offset, length. All three point at the value. */
  const entry = (name, target, ms = '') => [
    { f: 'pl.option', n: 1, label: `${name} · option`, cell: name, brk: true, points: target },
    { f: 'pl.offset', n: 2, label: `${name} · offset`, cell: 'offset', points: target },
    { f: 'pl.length', n: 2, label: `${name} · length`, cell: 'length', points: target, note: target ? undefined : 'Length 0: this option has no value.' },
  ];

  /* A LOGIN7 pointer-table entry: offset then length. */
  const ptr = (name, ms, target, unit = 'l7.cch') => [
    { f: 'l7.ib', n: 2, label: `${name} · offset`, cell: name, brk: true, ms: `ib${ms}`, points: target, note: target ? undefined : 'Empty: length is 0, so this offset is ignored.' },
    { f: unit, n: 2, label: `${name} · length`, cell: 'length', ms: `${unit === 'l7.cb' ? 'cb' : 'cch'}${ms}`, points: target },
  ];

  /* ---------------------------------------------------------------- */

  S('packet-header', {
    title: 'A packet header (the hello’s first 8 bytes)', note: 'MS-TDS §4.1',
    hex: '12 01 00 2F 00 00 01 00',
    cats: ['header'],
    parts: [header()],
  });

  S('prelogin-request', {
    title: '① Hello (PRELOGIN) from the client', note: 'MS-TDS §4.1',
    hex: `12 01 00 2F 00 00 01 00 00 00 1A 00 06 01 00 20 00 01 02 00 21 00 01 03
          00 22 00 04 04 00 26 00 01 FF 09 00 00 00 00 00 01 00 B8 0D 00 00 01`,
    cats: ['header', 'directory', 'data'],
    parts: [
      header(),
      { cat: 'directory', label: 'Directory', fields: [
        ...entry('version', 'v-version'), ...entry('encryption', 'v-enc'), ...entry('instance', 'v-inst'),
        ...entry('thread id', 'v-thread'), ...entry('MARS', 'v-mars'), { f: 'pl.end', n: 1 } ] },
      { cat: 'data', label: 'Data', fields: [
        { f: 'pl.version', n: 6, id: 'v-version', sender: 'client', note: 'Client library version 9.0 (a driver from the time of SQL Server 2005).' },
        { f: 'pl.encryption', n: 1, id: 'v-enc' },
        { f: 'pl.instance', n: 1, id: 'v-inst', value: 'default instance (empty name)' },
        { f: 'pl.threadid', n: 4, id: 'v-thread' },
        { f: 'pl.mars', n: 1, id: 'v-mars' } ] },
    ],
  });

  S('prelogin-reply', {
    title: '② Hello reply from the server', note: 'constructed: MS-TDS has no sample reply',
    hex: `04 01 00 2B 00 34 01 00 00 00 1A 00 06 01 00 20 00 01 02 00 21 00 01 03
          00 22 00 00 04 00 22 00 01 FF 10 00 03 E8 00 00 01 00 00`,
    cats: ['header', 'directory', 'data'],
    parts: [
      header(),
      { cat: 'directory', label: 'Directory', fields: [
        ...entry('version', 'r-version'), ...entry('encryption', 'r-enc'), ...entry('instance', 'r-inst'),
        ...entry('thread id', null), ...entry('MARS', 'r-mars'), { f: 'pl.end', n: 1 } ] },
      { cat: 'data', label: 'Data', fields: [
        { f: 'pl.version', n: 6, id: 'r-version', sender: 'server' },
        { f: 'pl.encryption', n: 1, id: 'r-enc', note: 'Both sides sent “on”, so TLS follows.' },
        { f: 'pl.instance', n: 1, id: 'r-inst', value: 'match: this is the instance asked for' },
        { f: 'pl.mars', n: 1, id: 'r-mars' } ] },
    ],
  });

  S('tls-in-prelogin', {
    title: '③ Secure: a TLS record inside a hello packet', note: 'MS-TDS §2.2.6.5 · record cut off',
    hex: '12 01 00 4E 00 00 00 00 16 03 01 00',
    cats: ['header', 'tls'],
    parts: [header(), { cat: 'tls', label: 'TLS record', fields: [{ f: 'tls.record', n: 4 }] }],
  });

  S('login7', {
    title: '④ Log in (LOGIN7)', note: 'MS-TDS §4.2 · shown decrypted',
    hex: `10 01 00 90 00 00 01 00 88 00 00 00 02 00 09 72
          00 10 00 00 00 00 00 07 00 01 00 00 00 00 00 00
          E0 03 00 00 00 00 00 00 09 04 00 00 5E 00 08 00
          6E 00 02 00 72 00 00 00 72 00 07 00 80 00 00 00
          80 00 00 00 80 00 04 00 88 00 00 00 88 00 00 00
          00 50 8B E2 B7 8F 88 00 00 00 88 00 00 00 88 00
          00 00 00 00 00 00 6C 00 70 00 64 00 74 00 65 00
          73 00 74 00 31 00 73 00 61 00 4F 00 53 00 51 00
          4C 00 2D 00 33 00 32 00 4F 00 44 00 42 00 43 00`,
    cats: ['header', 'fixed', 'pointers', 'datapart'],
    parts: [
      header(),
      { cat: 'fixed', label: 'Fixed part', fields: [
        { f: 'l7.length', n: 4 }, { f: 'l7.tdsversion', n: 4, note: 'This sample is from a TDS 7.2 client. The driver sends 04 00 00 74 (7.4).' },
        { f: 'l7.packetsize', n: 4 }, { f: 'l7.progver', n: 4 }, { f: 'l7.pid', n: 4 }, { f: 'l7.connid', n: 4 },
        { f: 'l7.flags1', n: 1 }, { f: 'l7.flags2', n: 1 }, { f: 'l7.typeflags', n: 1 }, { f: 'l7.flags3', n: 1 },
        { f: 'l7.timezone', n: 4 }, { f: 'l7.lcid', n: 4 } ] },
      { cat: 'pointers', label: 'Pointer table', fields: [
        ...ptr('host name', 'HostName', 'd-host'), ...ptr('user name', 'UserName', 'd-user'),
        ...ptr('password', 'Password', null), ...ptr('app name', 'AppName', 'd-app'),
        ...ptr('server name', 'ServerName', null), ...ptr('extension', 'Extension', null, 'l7.cb'),
        ...ptr('library name', 'CltIntName', 'd-lib'), ...ptr('language', 'Language', null),
        ...ptr('database', 'Database', null),
        { f: 'l7.clientid', n: 6 },
        ...ptr('Windows auth', 'SSPI', null, 'l7.cb'), ...ptr('attach file', 'AtchDBFile', null),
        ...ptr('new password', 'ChangePassword', null),
        { f: 'l7.sspilong', n: 4 } ] },
      { cat: 'datapart', label: 'Data part', fields: [
        { f: 'l7.text', n: 16, id: 'd-host', label: 'host name' },
        { f: 'l7.text', n: 4, id: 'd-user', label: 'user name' },
        { f: 'l7.text', n: 14, id: 'd-app', label: 'app name' },
        { f: 'l7.text', n: 8, id: 'd-lib', label: 'library name' } ] },
    ],
  });

  /* Token helpers for the login reply. */
  const tag = () => ({ f: 'tok.tag', n: 1, brk: true });
  const len = () => ({ f: 'tok.len', n: 2 });
  const bvar = (name, chars) => (chars
    ? [{ f: 'b.count', n: 1, label: `${name} · count`, cell: 'count' }, { f: 'tok.text', n: chars * 2, label: name }]
    : [{ f: 'b.count', n: 1, label: `${name} · count`, cell: 'count' }]);
  const message = (chars) => [tag(), len(), { f: 'msg.number', n: 4 }, { f: 'msg.state', n: 1 }, { f: 'msg.class', n: 1 },
    { f: 'us.count', n: 2, label: 'message · count', cell: 'count' }, { f: 'tok.text', n: chars * 2, label: 'message' },
    ...bvar('server name', 0), ...bvar('procedure', 0), { f: 'msg.line', n: 4 }];

  S('login-reply', {
    title: '⑤ Login reply from the server', note: 'MS-TDS §4.4 · shown decrypted',
    hex: `04 01 01 61 00 00 01 00 E3 1B 00 01 06 6D 00 61
          00 73 00 74 00 65 00 72 00 06 6D 00 61 00 73 00
          74 00 65 00 72 00 AB 58 00 45 16 00 00 02 00 25
          00 43 00 68 00 61 00 6E 00 67 00 65 00 64 00 20
          00 64 00 61 00 74 00 61 00 62 00 61 00 73 00 65
          00 20 00 63 00 6F 00 6E 00 74 00 65 00 78 00 74
          00 20 00 74 00 6F 00 20 00 27 00 6D 00 61 00 73
          00 74 00 65 00 72 00 27 00 2E 00 00 00 00 00 00
          00 E3 08 00 07 05 09 04 D0 00 34 00 E3 17 00 02
          0A 75 00 73 00 5F 00 65 00 6E 00 67 00 6C 00 69
          00 73 00 68 00 00 E3 13 00 04 04 34 00 30 00 39
          00 36 00 04 34 00 30 00 39 00 36 00 AB 5C 00 47
          16 00 00 01 00 27 00 43 00 68 00 61 00 6E 00 67
          00 65 00 64 00 20 00 6C 00 61 00 6E 00 67 00 75
          00 61 00 67 00 65 00 20 00 73 00 65 00 74 00 74
          00 69 00 6E 00 67 00 20 00 74 00 6F 00 20 00 75
          00 73 00 5F 00 65 00 6E 00 67 00 6C 00 69 00 73
          00 68 00 2E 00 00 00 00 00 00 00 AD 36 00 01 72
          09 00 02 16 4D 00 69 00 63 00 72 00 6F 00 73 00
          6F 00 66 00 74 00 20 00 53 00 51 00 4C 00 20 00
          53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00
          00 00 00 00 FD 00 00 00 00 00 00 00 00 00 00 00
          00`,
    cats: ['header', 'envchange', 'info', 'loginack', 'done'],
    parts: [
      header(),
      { cat: 'envchange', label: 'ENVCHANGE', summary: 'database → master',
        fields: [tag(), len(), { f: 'env.kind', n: 1 }, ...bvar('new value', 6), ...bvar('old value', 6)] },
      { cat: 'info', label: 'INFO', summary: '5701 · Changed database context to ‘master’.', fields: message(37) },
      { cat: 'envchange', label: 'ENVCHANGE', summary: 'collation → en-US, case-insensitive, sort 52',
        fields: [tag(), len(), { f: 'env.kind', n: 1 }, { f: 'bb.count', n: 1, label: 'new value · count', cell: 'count' },
          { f: 'env.collation', n: 5, label: 'new value' }, { f: 'bb.count', n: 1, label: 'old value · count', cell: 'count' }] },
      { cat: 'envchange', label: 'ENVCHANGE', summary: 'language → us_english',
        fields: [tag(), len(), { f: 'env.kind', n: 1 }, ...bvar('new value', 10), ...bvar('old value', 0)] },
      { cat: 'envchange', label: 'ENVCHANGE', summary: 'packet size 4096 → 4096',
        fields: [tag(), len(), { f: 'env.kind', n: 1 }, ...bvar('new value', 4), ...bvar('old value', 4)] },
      { cat: 'info', label: 'INFO', summary: '5703 · Changed language setting to us_english.', fields: message(39) },
      { cat: 'loginack', label: 'LOGINACK', summary: 'login accepted · T-SQL · TDS 7.2 · Microsoft SQL Server',
        fields: [tag(), len(), { f: 'ack.interface', n: 1 }, { f: 'ack.tdsversion', n: 4, note: 'This sample server uses 7.2. The driver would refuse it.' },
          { f: 'b.count', n: 1, label: 'server program · count' },
          { f: 'tok.text', n: 44, label: 'server program', note: 'Ends with two NUL characters; trim them.' },
          { f: 'ack.progver', n: 4, note: 'MS-TDS’s example leaves this as zero, as the example in §4.17 does. The example in §4.5 carries 0B 00 08 CB (11.0.2251, SQL Server 2012), and the example in §4.21 carries 0C 00 03 E8 (12.0.1000, SQL Server 2014).' }] },
      { cat: 'done', label: 'DONE', summary: 'final · 0 rows',
        fields: [tag(), { f: 'done.status', n: 2 }, { f: 'done.curcmd', n: 2 }, { f: 'done.rowcount', n: 8 }] },
    ],
  });
  /* ---------- Browser (MC-SQLR): bare UDP datagrams, no packet header ---------- */

  S('sqlr-instance-request', {
    title: 'Asking for the instance YUKONSTD', note: 'MC-SQLR §4.2', noHeader: true,
    hex: '04 59 55 4B 4F 4E 53 54 44 00',
    cats: ['request'],
    parts: [{ cat: 'request', label: 'CLNT_UCAST_INST', fields: [{ f: 'sqlr.message', n: 1 }, { f: 'sqlr.instance', n: 9 }] }],
  });

  S('sqlr-instance-reply', {
    title: 'Where YUKONSTD listens', note: 'MC-SQLR §4.2', noHeader: true,
    hex: `05 58 00 53 65 72 76 65 72 4E 61 6D 65 3B 49 4C 53 55 4E 47 31 3B 49 6E 73 74 61 6E 63 65 4E 61 6D 65 3B
          59 55 4B 4F 4E 53 54 44 3B 49 73 43 6C 75 73 74 65 72 65 64 3B 4E 6F 3B 56 65 72 73 69 6F 6E 3B 39 2E
          30 30 2E 31 33 39 39 2E 30 36 3B 74 63 70 3B 35 37 31 33 37 3B 3B`,
    cats: ['reply'],
    parts: [{ cat: 'reply', label: 'SVR_RESP', fields: [{ f: 'sqlr.message', n: 1 }, { f: 'sqlr.size', n: 2 },
      { f: 'sqlr.text', n: 88, note: 'tcp;57137: connect with TDS to port 57137.' }] }],
  });

  S('sqlr-dac-request', {
    title: 'Asking for YUKONSTD’s DAC port', note: 'MC-SQLR §4.3', noHeader: true,
    hex: '0F 01 59 55 4B 4F 4E 53 54 44 00',
    cats: ['request'],
    parts: [{ cat: 'request', label: 'CLNT_UCAST_DAC', fields: [{ f: 'sqlr.message', n: 1 }, { f: 'sqlr.version', n: 1 }, { f: 'sqlr.instance', n: 9 }] }],
  });

  S('sqlr-dac-reply', {
    title: 'YUKONSTD’s DAC port', note: 'MC-SQLR §4.3', noHeader: true,
    hex: '05 06 00 01 32 DF',
    cats: ['reply'],
    parts: [{ cat: 'reply', label: 'SVR_RESP (DAC)', fields: [{ f: 'sqlr.message', n: 1 }, { f: 'sqlr.dacsize', n: 2 },
      { f: 'sqlr.version', n: 1 }, { f: 'sqlr.port', n: 2 }] }],
  });
})();
