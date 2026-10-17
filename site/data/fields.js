/* fields.js — every field's meaning, written once. Samples refer to these by id.
   Each entry: label, meaning, type, ms (MS-TDS name), ref (reference page), show (bytes -> value). */
(function () {
  const TDS = window.TDS;
  const F = TDS.field;
  const { num, enumOf = TDS.fmt.enum, text, flags, hex, dec, hx } = TDS.fmt;

  /* ---------- categories (legend labels) ---------- */
  Object.assign(TDS.categories, {
    header: 'Packet header', directory: 'Directory', data: 'Data',
    fixed: 'Fixed part', pointers: 'Pointer table', datapart: 'Data part',
    tls: 'TLS record',
    envchange: 'ENVCHANGE', info: 'INFO', loginack: 'LOGINACK', done: 'DONE',
  });

  /* ---------- packet header ---------- */
  const PACKET_TYPES = { 0x01: 'SQL batch', 0x03: 'remote procedure call', 0x04: 'server message', 0x06: 'cancel', 0x07: 'bulk load data',
    0x08: 'federated auth token', 0x0e: 'transaction manager request', 0x10: 'login (LOGIN7)', 0x11: 'Windows auth continuation', 0x12: 'hello (PRELOGIN)' };
  F('packet.type', { label: 'type', type: 'u8', ms: 'Type', ref: 'ref/packet', meaning: 'Which kind of message this packet belongs to.', show: enumOf('u8', PACKET_TYPES) });
  F('packet.status', { label: 'status', type: 'flags', ms: 'Status', ref: 'ref/packet', meaning: 'Flags. 01 marks the last packet of the message.',
    show: (b) => (b[0] === 0 ? 'more packets follow' : flags([[0x01, 'last packet'], [0x02, 'ignore'], [0x08, 'reset session'], [0x10, 'reset, keep transaction']])(b)) });
  F('packet.length', { label: 'length', type: 'u16, big-endian', ms: 'Length', ref: 'ref/packet', meaning: 'Length of this whole packet, header included. Big-endian.', show: num('u16be', 'bytes') });
  F('packet.spid', { label: 'session id', type: 'u16, big-endian', ms: 'SPID', ref: 'ref/packet', meaning: "The server's id for this session. The client sends 00 00.",
    show: num('u16be', (v) => (v === 0 ? '0 (none yet)' : `session ${v}`)) });
  F('packet.id', { label: 'packet #', type: 'u8', ms: 'PacketID', ref: 'ref/packet', meaning: 'Increases by 1 for each packet and wraps at 256. Receivers ignore it.', show: num('u8') });
  F('packet.window', { label: 'unused', type: 'u8', ms: 'Window', ref: 'ref/packet', meaning: 'Always 00.', show: () => 'unused' });

  /* ---------- PRELOGIN ---------- */
  const PL_OPTIONS = { 0: 'version', 1: 'encryption', 2: 'instance', 3: 'thread id', 4: 'MARS', 5: 'trace id', 6: 'fed auth required', 7: 'nonce', 0xff: 'end' };
  F('pl.option', { label: 'option', type: 'u8', ms: 'PL_OPTION_TOKEN', ref: 'ref/prelogin', meaning: 'Which option this directory entry describes.', show: enumOf('u8', PL_OPTIONS) });
  F('pl.offset', { label: 'offset', type: 'u16, big-endian', ms: 'PL_OFFSET', ref: 'ref/prelogin',
    meaning: "Where the option's value starts, counted from the start of the body (just after the packet header). Big-endian.",
    show: num('u16be', (v) => `${hx(v)} in body`) });
  F('pl.length', { label: 'length', type: 'u16, big-endian', ms: 'PL_OPTION_LENGTH', ref: 'ref/prelogin', meaning: "Length of the option's value, in bytes. Big-endian.", show: num('u16be', (v) => `${v} byte${v === 1 ? '' : 's'}`) });
  F('pl.end', { label: 'end', type: 'u8', ms: 'TERMINATOR', ref: 'ref/prelogin', meaning: 'Ends the directory. It has no offset or length.', show: () => 'end of directory' });
  /* A version number: what each byte holds, and what the number names. From SQL Server, its release (the major
     version, and the minor for 2008 R2); from a client, its library's own version, which the server ignores. */
  const RELEASES = [[17, 0, 'SQL Server 2025'], [16, 0, 'SQL Server 2022'], [15, 0, 'SQL Server 2019'],
    [14, 0, 'SQL Server 2017'], [13, 0, 'SQL Server 2016'], [12, 0, 'SQL Server 2014'], [11, 0, 'SQL Server 2012'],
    [10, 50, 'SQL Server 2008 R2'], [10, 0, 'SQL Server 2008'], [9, 0, 'SQL Server 2005']];
  const releaseOf = (major, minor) => RELEASES.findIndex(([M, m]) => M === major && (major !== 10 || m === minor));
  const versionText = (b) => `${b[0]}.${b[1]}.${(b[2] << 8) | b[3]}`;
  const showVersion = (b, def) => {
    const r = releaseOf(b[0], b[1]);
    if (def.sender === 'client') return `${versionText(b)} · the client library’s`;
    return r < 0 || def.sender !== 'server' ? versionText(b) : `${versionText(b)} · ${RELEASES[r][2]}`;
  };
  const versionDetail = (b, def) => {
    const h = (x) => TDS.hexOf(x);
    const parts = [[h(b.slice(0, 1)), 'major', String(b[0]), ''], [h(b.slice(1, 2)), 'minor', String(b[1]), ''],
      [h(b.slice(2, 4)), 'build', String((b[2] << 8) | b[3]), 'big-endian']];
    if (b.length === 6) parts.push([h(b.slice(4, 6)), 'sub-build', String(b[4] | (b[5] << 8)), 'little-endian']);
    const r = releaseOf(b[0], b[1]);
    const sections = [{ parts }];
    const releases = { title: 'SQL Server’s major versions', rows: RELEASES.map(([M, m, name]) => [M === 10 ? `${M}.${m}` : String(M), name]), on: r };
    if (def.sender === 'client') {
      sections.push({ text: 'From the client, this is the client library’s own version, not SQL Server’s. It is informational, and the server ignores it. The driver sends 0.1.0.' });
    } else if (def.sender === 'server') {
      sections.push({ text: r < 0 ? `From the server, this is SQL Server’s own version. Major version ${b[0]} matches no release.`
        : `From the server, this is SQL Server’s own version. Major version ${b[0]}${b[0] === 10 ? `.${b[1]}` : ''} is ${RELEASES[r][2]}. The build identifies the installed update (the release itself, a cumulative update or a security fix), as Microsoft’s list of builds shows it.` }, releases);
    } else {
      sections.push({ text: 'The sender decides whose version this is. From the server, it is SQL Server’s own release. From the client, it is the client library’s version, which the server ignores.' }, releases);
    }
    sections.push({ text: 'This is not the TDS version. LOGINACK carries the TDS version in a separate field.' });
    return sections;
  };

  F('pl.version', { label: 'version', type: '6 bytes', ms: 'VERSION', ref: 'ref/prelogin',
    meaning: "The sender's version: major, minor, build (2 bytes, big-endian), then a 2-byte sub-build (little-endian).",
    show: showVersion, detail: versionDetail });
  F('pl.encryption', { label: 'encryption', type: 'u8', ms: 'B_FENCRYPTION', ref: 'ref/prelogin', meaning: "The sender's encryption setting. Together, the two sides' values decide the outcome.",
    show: enumOf('u8', { 0: 'off', 1: 'on', 2: 'not supported', 3: 'required' }) });
  F('pl.instance', { label: 'instance', ms: 'B_INSTVALIDITY', ref: 'ref/prelogin',
    meaning: 'From the client: the instance name, zero-terminated (a single 00 means the default instance). From the server: 00 = match (the right instance), 01 = mismatch (the wrong instance).' });
  F('pl.threadid', { label: 'thread id', type: 'u32, little-endian', ms: 'UL_THREADID', ref: 'ref/prelogin', meaning: "The client's thread id, for debugging only. Little-endian, unlike the rest of PRELOGIN.", show: num('u32le') });
  F('pl.mars', { label: 'MARS', type: 'u8', ms: 'B_MARS', ref: 'ref/prelogin', meaning: 'Whether the sender wants MARS: several serial channels on one connection.', show: enumOf('u8', { 0: 'off', 1: 'on' }) });

  /* ---------- TLS (as carried in 7.4) ---------- */
  F('tls.record', { label: 'TLS record', ms: 'SSL_PAYLOAD', ref: 'ref/prelogin',
    meaning: 'The start of a TLS record carried as the payload of a hello packet: 16 = handshake, then the TLS version. The rest is cut off here.',
    show: () => 'TLS handshake record (cut off)' });

  /* ---------- LOGIN7 ---------- */
  F('l7.length', { label: 'length', type: 'u32', ms: 'Length', ref: 'ref/login7', meaning: 'Length of the whole login body.', show: num('u32le', 'bytes') });
  F('l7.tdsversion', { label: 'TDS version', type: '4 bytes', ms: 'TDSVersion', ref: 'ref/login7',
    meaning: 'The highest TDS version the client supports. The last byte holds it: 74 means 7.4. The driver sends 04 00 00 74.',
    show: (b) => `TDS ${b[3] >> 4}.${b[3] & 0xf}` });
  F('l7.packetsize', { label: 'packet size', type: 'u32', ms: 'PacketSize', ref: 'ref/login7', meaning: 'The packet size the client asks for. The server confirms or changes it with an announcement.', show: num('u32le', 'bytes') });
  F('l7.progver', { label: 'library version', type: 'u32', ms: 'ClientProgVer', ref: 'ref/login7', meaning: 'Version of the client library. Informational.', show: hex() });
  F('l7.pid', { label: 'process id', type: 'u32', ms: 'ClientPID', ref: 'ref/login7', meaning: "The client's process id. Informational.", show: num('u32le') });
  F('l7.connid', { label: 'connection id', type: 'u32', ms: 'ConnectionID', ref: 'ref/login7', meaning: 'Normally 0.', show: num('u32le') });
  F('l7.flags1', { label: 'flags 1', type: '8 flags', ms: 'OptionFlags1', ref: 'ref/login7',
    meaning: 'Lowest bit first: byte order · character set · float format (2 bits) · bulk-load off · report database changes · initial database must succeed · report language changes.',
    show: flags([[0x01, 'big-endian client'], [0x02, 'EBCDIC'], [0x10, 'bulk-load off'], [0x20, 'report database changes'], [0x40, 'initial database must succeed'], [0x80, 'report language changes']]) });
  F('l7.flags2', { label: 'flags 2', type: '8 flags', ms: 'OptionFlags2', ref: 'ref/login7',
    meaning: 'Lowest bit first: initial language must succeed · ODBC client · 2 reserved · user type (3 bits) · Windows auth.',
    show: flags([[0x01, 'initial language must succeed'], [0x02, 'ODBC client'], [0x80, 'Windows auth']]) });
  F('l7.typeflags', { label: 'type flags', type: '8 flags', ms: 'TypeFlags', ref: 'ref/login7',
    meaning: 'Lowest bits first: SQL dialect (4 bits, 0 = default) · OLE DB client · read-only intent · 2 reserved.',
    show: (b) => (b[0] === 0 ? 'default dialect' : flags([[0x01, 'T-SQL dialect'], [0x10, 'OLE DB client'], [0x20, 'read-only intent']])(b)) });
  F('l7.flags3', { label: 'flags 3', type: '8 flags', ms: 'OptionFlags3', ref: 'ref/login7',
    meaning: 'Lowest bit first: change password · binary XML · user instance · unknown-collation handling · feature list present · 3 reserved.',
    show: flags([[0x01, 'change password'], [0x02, 'binary XML'], [0x04, 'user instance'], [0x08, 'unknown-collation handling'], [0x10, 'feature list present']]) });
  F('l7.timezone', { label: 'time zone', type: 'i32', ms: 'ClientTimeZone', ref: 'ref/login7', meaning: 'Unused; set to 0.', show: num('i32le') });
  F('l7.lcid', { label: 'locale', type: 'u32', ms: 'ClientLCID', ref: 'ref/login7', meaning: "The client's locale id. Servers ignore it.",
    show: (b) => { const v = dec.u32le(b); return `${hx(v, 4)}${v === 0x409 ? ' · en-US' : ''}`; } });
  F('l7.ib', { label: 'offset', type: 'u16', ref: 'ref/login7', meaning: 'Where this value starts, counted from the start of the body.', show: num('u16le', (v) => `${hx(v)} in body`) });
  F('l7.cch', { label: 'length', type: 'u16', ref: 'ref/login7', meaning: 'Length of the value, in characters (each 2 bytes, UTF-16LE). 0 means empty, and the offset is then ignored.',
    show: num('u16le', (v) => (v === 0 ? '0 · empty' : `${v} characters`)) });
  F('l7.cb', { label: 'length', type: 'u16', ref: 'ref/login7', meaning: 'Length of the value, in bytes. 0 means not used.', show: num('u16le', (v) => (v === 0 ? '0 · not used' : `${v} bytes`)) });
  F('l7.clientid', { label: 'client id', type: '6 bytes', ms: 'ClientID', ref: 'ref/login7', meaning: 'A MAC address, stored inline (not a pointer). Informational.',
    show: (b) => b.map(TDS.hex2).join(':') });
  F('l7.sspilong', { label: 'large auth length', type: 'u32', ms: 'cbSSPILong', ref: 'ref/login7', meaning: 'Used only when Windows auth data is too big for its 2-byte length.', show: num('u32le', 'bytes') });
  F('l7.text', { label: 'text', type: 'UTF-16LE', ref: 'ref/login7', text: 'utf16', meaning: 'A UTF-16LE string, found through its entry in the pointer table.', show: text() });

  /* ---------- tokens ---------- */
  const TAGS = { 0xe3: 'ENVCHANGE', 0xab: 'INFO', 0xaa: 'ERROR', 0xad: 'LOGINACK', 0xae: 'FEATUREEXTACK', 0xfd: 'DONE', 0xfe: 'DONEPROC', 0xff: 'DONEINPROC' };
  F('tok.tag', { label: 'tag', type: 'u8', ms: 'TokenType', ref: 'ref/token-stream', meaning: 'Which token this is. The tag decides how the rest of the token is read.', show: enumOf('u8', TAGS) });
  F('tok.len', { label: 'length', type: 'u16', ms: 'Length', ref: 'ref/token-stream', meaning: 'How many bytes of this token follow.', show: num('u16le', 'bytes follow') });
  F('b.count', { label: 'count', type: 'u8', ms: 'B_VARCHAR length', ref: 'ref/login-response', meaning: 'Length of the text that follows, in characters (each 2 bytes).',
    show: num('u8', (v) => (v === 0 ? '0 · empty' : `${v} characters`)) });
  F('us.count', { label: 'count', type: 'u16', ms: 'US_VARCHAR length', ref: 'ref/login-response', meaning: 'Length of the text that follows, in characters (each 2 bytes).', show: num('u16le', (v) => `${v} characters`) });
  F('bb.count', { label: 'count', type: 'u8', ms: 'B_VARBYTE length', ref: 'ref/login-response', meaning: 'Length of the bytes that follow.', show: num('u8', (v) => (v === 0 ? '0 · empty' : `${v} bytes`)) });
  F('tok.text', { label: 'text', type: 'UTF-16LE', ref: 'ref/login-response', text: 'utf16', meaning: 'Text in UTF-16LE.', show: text() });

  F('env.kind', { label: 'kind', type: 'u8', ms: 'Type', ref: 'ref/login-response', meaning: 'Which session setting changed.',
    show: enumOf('u8', { 1: 'database', 2: 'language', 4: 'packet size', 7: 'collation', 13: 'mirroring partner', 20: 'routing', 21: 'routing to a database' }) });
  F('env.collation', { label: 'collation', type: '5 bytes', ms: 'COLLATION', ref: 'ref/login-response',
    meaning: 'Locale id (20 bits), comparison flags (8 bits), version (4 bits), then a sort id byte.',
    show: (b) => {
      const v = dec.u32le(b.slice(0, 4));
      const lcid = v & 0xfffff, fl = (v >>> 20) & 0xff;
      const f = [fl & 1 && 'ignore case', fl & 2 && 'ignore accents', fl & 4 && 'ignore kana', fl & 8 && 'ignore width'].filter(Boolean);
      return `locale ${hx(lcid, 4)}${lcid === 0x409 ? ' (en-US)' : ''} · ${f.join(', ') || 'no flags'} · sort ${b[4]}`;
    } });

  F('msg.number', { label: 'number', type: 'i32', ms: 'Number', ref: 'ref/login-response', meaning: 'The message number.', show: num('i32le') });
  F('msg.state', { label: 'state', type: 'u8', ms: 'State', ref: 'ref/login-response', meaning: 'Adds detail to the number. It is mainly useful to technical support.', show: num('u8') });
  F('msg.class', { label: 'class', type: 'u8', ms: 'Class', ref: 'ref/login-response', meaning: 'Severity. Below 10 is informational.',
    show: num('u8', (v) => `${v} · ${v < 10 ? 'informational' : 'error'}`) });
  F('msg.line', { label: 'line', type: 'i32', ms: 'LineNumber', ref: 'ref/login-response', meaning: 'Line in the batch or procedure that produced the message; 0 if none.', show: num('i32le') });

  F('ack.interface', { label: 'interface', type: 'u8', ms: 'Interface', ref: 'ref/login-response', meaning: 'Which language interface the server accepted.', show: enumOf('u8', { 0: 'default', 1: 'T-SQL' }) });
  F('ack.tdsversion', { label: 'TDS version', type: '4 bytes', ms: 'TDSVersion', ref: 'ref/login-response',
    meaning: 'The TDS version the server will use. The first byte carries it: 74 means 7.4. The driver requires 7.4.', show: (b) => `TDS ${b[0] >> 4}.${b[0] & 0xf}` });
  F('ack.progver', { label: 'server version', type: '4 bytes', ms: 'ProgVersion', ref: 'ref/login-response', meaning: 'SQL Server’s version: major, minor, then the build (2 bytes, big-endian).',
    sender: 'server', show: showVersion, detail: versionDetail });

  F('done.status', { label: 'status', type: 'u16 flags', ms: 'Status', ref: 'ref/login-response', meaning: 'Flags. When "more" is clear, this token ends the reply.',
    show: (b) => {
      const v = dec.u16le(b);
      const names = [[0x01, 'more follows'], [0x02, 'error'], [0x04, 'in transaction'], [0x10, 'row count valid'], [0x20, 'cancel acknowledged'], [0x100, 'severe error']]
        .filter(([m]) => v & m).map(([, n]) => n);
      return names.length ? names.join(' · ') : 'final';
    } });
  F('done.curcmd', { label: 'current command', type: 'u16', ms: 'CurCmd', ref: 'ref/login-response', meaning: 'Set by the server; the client does not interpret it.', show: num('u16le') });
  F('done.rowcount', { label: 'row count', type: 'u64', ms: 'DoneRowCount', ref: 'ref/login-response', meaning: 'Rows affected. Valid only when the status says "row count valid".',
    show: (b) => `${dec.u64le(b)} rows` });
  /* ---------- Browser (MC-SQLR): not TDS; UDP 1434 ---------- */
  Object.assign(TDS.categories, { request: 'Request', reply: 'Reply' });
  const SQLR = { 0x02: 'every instance on the network', 0x03: 'every instance on one machine', 0x04: 'one instance',
    0x05: 'reply (SVR_RESP)', 0x0f: 'one instance’s DAC port' };
  const ascii = (b) => `“${String.fromCharCode(...b).replace(/\u0000/g, '␀')}”`;
  F('sqlr.message', { label: 'message', type: 'u8', ms: 'CLNT_… / SVR_RESP', spec: 'MC-SQLR', ref: 'ref/browser', meaning: 'Which request this is, or 05 for a reply.', show: enumOf('u8', SQLR) });
  F('sqlr.version', { label: 'protocol version', type: 'u8', ms: 'PROTOCOLVERSION', spec: 'MC-SQLR', ref: 'ref/browser', meaning: 'Always 01. Only DAC requests and replies carry it.', show: num('u8') });
  F('sqlr.instance', { label: 'instance', text: 'ascii', type: 'text, ended by 00', ms: 'INSTANCENAME', spec: 'MC-SQLR', ref: 'ref/browser',
    meaning: 'The instance’s name, in the code page that the client and server share, ended by a zero byte. At most 32 bytes come before the zero.', show: ascii });
  F('sqlr.size', { label: 'size', type: 'u16', ms: 'RESP_SIZE', spec: 'MC-SQLR', ref: 'ref/browser', meaning: 'How many bytes of text follow.', show: num('u16le', 'bytes') });
  F('sqlr.dacsize', { label: 'size', type: 'u16', ms: 'RESP_SIZE', spec: 'MC-SQLR', ref: 'ref/browser', meaning: 'In a DAC reply, the whole reply’s length: always 6.', show: num('u16le', 'bytes') });
  F('sqlr.text', { label: 'text', text: 'ascii', type: 'text', ms: 'RESP_DATA', spec: 'MC-SQLR', ref: 'ref/browser',
    meaning: 'Each instance is a list of name–value pairs separated by ;, ending in ;;. ServerName, InstanceName, IsClustered and Version come first, then each endpoint.', show: ascii });
  F('sqlr.port', { label: 'DAC port', type: 'u16', ms: 'TCP_DAC_PORT', spec: 'MC-SQLR', ref: 'ref/browser', meaning: 'The TCP port the dedicated administrator connection listens on.', show: num('u16le') });
})();
