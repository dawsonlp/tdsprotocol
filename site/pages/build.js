/* Building the Client — a view of docs/design/B-building-the-client.md (the record, D-29). */
(function () {
  const { L, D, table, callout, badge } = window.TDS;

  window.TDS.page({
    id: 'build', group: 'Design', num: 'B', kind: 'explanation',
    title: 'Building the Client',
    where: 'Between the design and the code: how the agreed design becomes code, in what order, and how each step is checked.',
    outcome: 'say which file each part of the design lives in, what each milestone builds, and how to tell that it’s done.',
    body: () => `
      ${callout('notice', 'Agreed, 2026-10-16', 'This plan, and the decisions it builds on (linked inline), are agreed. Implementation follows the milestones in order.')}

      <h2 id="1-where-the-code-stands">1 · Where the code stands</h2>
      ${table(['Agreed design', 'Code before M1', 'Change'], [
        [`Connections, serial channels, MARS, pool (${D(17)}–${D(24)}, ${D(31)}, ${D(36)})`, 'built, and tested against the live server', 'none'],
        [`One primitive, <code>exchange(request)</code> (${D(33)})`, '<code>exchange(sql: str)</code>; the core assumes every request is a SQL batch', 'request objects; the core never knows the kind of request'],
        [`Streaming responses, and the response as a record (${D(34)}, ${D(42)})`, 'the whole message is read into <code>Result</code> lists', 'the live <code>Response</code>, <code>FetchedResponse</code>, the record and its views, errors raised at the end'],
        [`Cancel (${D(34)})`, 'none', 'Attention, from any task'],
        [`<code>Call</code> (${D(40)})`, 'none', 'RPC requests and <code>returns()</code>'],
        [`The type vocabulary (${D(43)})`, 'int, bit and nvarchar, read only', 'every type, both directions, in milestones'],
        [`“The core never buffers without limit” (${L('client', 'The Client §2', '2-core-and-shells')})`, 'unbounded channel inboxes; MARS ACKs sent on arrival', 'backpressure'],
        [`Streamed requests (${D(41)})`, 'none', 'M4'],
      ])}

      <h2 id="2-where-the-code-lives">2 · Where the code lives ${badge('Agreed')} ${D(45)}</h2>
      ${table(['File', 'Holds', 'Kind', 'Mirrored by'], [
        ['<code>tds/requests.py</code>', 'the headers every request carries; <code>Batch</code>; <code>Call</code>, <code>Calls</code>, <code>Param</code>, <code>Builtin</code>, <code>CallOptions</code>, <code>DEFAULT</code>', 'teaching surface', 'Reference › Requests <i>(new)</i>'],
        ['<code>tds/types.py</code>', 'the vocabulary: each SQL Server type’s description on the wire (TYPE_INFO), value layout and checks', 'teaching surface', 'Reference › Data Types <i>(new)</i>'],
        ['<code>tds/collations.py</code>', `locale id → code page, sort id → code page; generated from the server (${D(44)})`, 'teaching surface: a definition table', 'Data Types › Collations'],
        ['<code>tds/tokens.py</code>', 'adds RETURNVALUE, RETURNSTATUS, NBCROW, ORDER', 'teaching surface', `${L('ref/token-stream', 'Token Stream')}, ${L('ref/response', 'Request Response')}`],
        ['<code>tds/response.py</code>', 'the record’s items, its views, the reading state machine, <code>Unread</code>, <code>FetchedResponse</code>, <code>ServerError</code>, <code>Cancelled</code>. No I/O.', 'teaching surface', `${L('ref/response', 'Request Response')}, ${L('client', 'The Client §4', '4-exchanges-and-responses')}`],
        ['<code>tds/connection/core.py</code>', '<code>exchange(request)</code>, packets delivered per channel, cancel, MARS credit returned as packets are consumed', 'procedures (surface) and machinery', `${L('ref/connect', 'Connect')}, ${L('ref/conversations', 'Conversations')}`],
        ['<code>tds/connection/shell.py</code>', 'the live <code>Response</code> (asyncio), bounded inboxes', 'machinery', '—'],
        ['<code>tds/wire.py</code>', 'incremental token decoding; writing TYPE_INFO', 'machinery', '—'],
        ['<code>tools/generate_collations.py</code>', 'writes <code>collations.py</code> from a live server', 'tool', '—'],
      ], 'compact')}
      <p><code>batch.py</code> and <code>datatypes.py</code> are removed. Their contents move into <code>requests.py</code> and <code>types.py</code>.</p>

      <h2 id="3-the-components">3 · The components</h2>
      <h3>Requests</h3>
      <ul>
        <li><b>A request knows its packet type</b> and encodes its own body from a small context: the transaction descriptor, the number of outstanding requests, and the session’s collation. The core asks for exactly that and nothing more, so it never branches on the kind of request (${D(33)}).</li>
        <li><b><code>Batch(sql)</code>:</b> the headers, then the SQL text.</li>
        <li><b><code>Call(target, *params, options=…)</code>:</b> the target is a name (a length and text) or a <code>Builtin</code> (<code>FFFF</code> followed by its number); the <code>CallOptions</code> flags follow; then each <code>Param</code>: its name, its status flags (<i>by reference</i> when <code>output=True</code>, <i>default value</i> when the value is <code>tds.DEFAULT</code>), the type’s description on the wire, then the value (${D(40)}).</li>
        <li><b><code>Calls(…)</code>:</b> the headers once, then the calls separated by the BATCH marker (<code>FF</code>).</li>
        <li><b>Values are checked when the request is built.</b> A value that doesn’t fit its declared type fails before any byte is sent.</li>
      </ul>
      <h3>Types and collations</h3>
      <ul>
        <li><b>One object per SQL Server type:</b> <code>types.int</code>, <code>types.nvarchar(50)</code>, <code>types.decimal(10, 2)</code>, <code>types.datetime2(7)</code>, … A column’s type is the same object, with nullability on the column (${D(40)}).</li>
        <li><b>Each type knows</b> its description on the wire and its value layout, both read and written, and its check: range, length, precision and scale.</li>
        <li><b>Wire codes:</b> parameters use the nullable codes; columns arrive in either the nullable or the fixed-size code, and both map to the same type; the code itself stays visible at the full observability level.</li>
        <li><b>Every value round-trips exactly (${D(48)}).</b> Select → insert → select compares equal, on the server and in Python. A value goes back with its column’s type, which carries collation, precision, scale and length.</li>
        <li><b>Refuse rather than round.</b> A value that doesn’t fit its declared type exactly is refused before sending: too much scale, too long, finer time precision than declared, or a character the column’s code page can’t hold.</li>
      </ul>
      <p><b>Values</b> ${badge('Agreed')} ${D(48)}: a Python type is used only where it holds every value of the SQL type exactly, at every scale. Otherwise the value is a driver type.</p>
      ${table(['SQL Server type', 'Value', 'Why'], [
        ['<code>tinyint</code> … <code>bigint</code> · <code>bit</code>', '<code>int</code> · <code>bool</code>', 'exact'],
        ['<code>decimal</code>, <code>numeric</code>, <code>money</code>, <code>smallmoney</code>', '<code>decimal.Decimal</code>', 'exact, provided encoding works from the Decimal’s digits. It never goes through <code>float</code> or decimal arithmetic, which rounds at 28 digits. A <code>decimal(38)</code> has 38 digits.'],
        ['<code>float</code>, <code>real</code>', '<code>float</code>', 'exact; a <code>real</code> widens and narrows back exactly, and a float that isn’t exactly a float32 is refused as <code>real</code>'],
        ['<code>date</code> · <code>smalldatetime</code>', '<code>datetime.date</code> · <code>datetime.datetime</code>', 'exact: the same range, and whole minutes'],
        ['<code>time</code>, <code>datetime2</code>, <code>datetimeoffset</code>', 'driver types holding 100 ns ticks, plus the offset', 'Python stops at microseconds'],
        ['<code>datetime</code>', 'a driver type holding 1/300-second ticks', 'microseconds can’t hold a third of a millisecond'],
        ['<code>char</code>, <code>varchar</code>, <code>text</code>', '<code>str</code>, decoded with the server’s byte table', `Python’s codecs refuse bytes SQL Server stores (${D(44)})`],
        ['<code>nchar</code>, <code>nvarchar</code>, <code>ntext</code>', '<code>str</code>, keeping unpaired surrogates', 'SQL Server stores them; Python’s strict UTF-16 decoder rejects them'],
        ['<code>binary</code>, <code>varbinary</code>, <code>image</code>, <code>rowversion</code>', '<code>bytes</code>', 'exact'],
        ['<code>uniqueidentifier</code>', '<code>uuid.UUID</code>', 'exact; its bytes are mixed-endian on the wire, and the definition says so'],
        ['<code>sql_variant</code>', 'the value together with its base type', 'exact'],
        ['<code>vector</code>', 'a driver value: element type and values', 'float32 and float16 widen exactly'],
        ['CLR types', `bytes and the type’s full name (${D(43)})`, 'exact'],
        ['a table (parameters only)', `an iterable or source of tuples, sent with the table type’s columns (${D(49)})`, 'exact: each value as its column’s type'],
        ['<code>xml</code>, <code>json</code>', '<code>str</code>', 'the server normalizes these on insert; the round trip is verified from the first normalized value. <code>json</code> stays text; parsing it belongs to an outer layer.'],
        ['NULL', '<code>None</code>', ''],
      ], 'compact')}
      <p>Each driver time type converts to Python’s types exactly. If it can’t, it refuses, unless the application explicitly asks for rounding.</p>
      <p><b>Collations</b> (${D(44)}):</p>
      <ul>
        <li><b>Which collation applies:</b> a <code>varchar</code> value is decoded with its column’s own collation, and a parameter is encoded with the session’s collation or one given explicitly.</li>
        <li><b>The server’s reading, not Python’s codec.</b> The generated file records every byte sequence SQL Server reads or writes differently: single bytes Python refuses (5 in cp1252, 31 in cp874), whole user-defined areas in the double-byte code pages, and cp932’s duplicate encodings.</li>
        <li><b>Canonical sequences read as characters; any other is carried as escapes,</b> so every value decodes and encodes back to the same bytes. Encoding checks that each character reads back as itself.</li>
        <li><b>UTF-8:</b> without the UTF-8 login feature (${D(8)}), invalid bytes that SQL Server stores arrive with U+FFFD in their place. Those values can’t come back exactly.</li>
        <li><b>Special cases:</b> the UTF-8 flag means UTF-8; code page 0 can’t hold <code>varchar</code>; a collation missing from the file raises an error that names its locale id, sort id and bytes.</li>
      </ul>
      <h3>Tokens</h3>
      <p>RETURNVALUE, RETURNSTATUS, NBCROW and ORDER join the definitions. ORDER was seen on the live server for every <code>ORDER BY</code>. An unknown tag still ends the connection with a clear error.</p>
      <h3>The response</h3>
      <ul>
        <li><b>A pure state machine in <code>response.py</code>.</b> It is fed packet bodies, produces the record’s items (${D(42)}), and keeps the views and applies <code>Unread</code> (${D(34)}). It knows nothing of I/O or of what was requested.</li>
        <li><b>Incremental decoding:</b> a token split by a packet boundary waits for the next packet; <code>wire.py</code> distinguishes “needs more bytes” from “malformed”.</li>
        <li><b>Rows in batches:</b> each read returns every item decodable from what has arrived, keeping per-row overhead low (${L('client', 'The Client §2', '2-core-and-shells')}).</li>
        <li><b>Rows are counted as they pass</b>, and kept only by <code>fetch()</code> or <code>Unread.KEEP</code>.</li>
        <li><b>The end:</b> the response ends at the completion without <i>more follows</i>, and the channel is free. If there were errors, the call that reached the end raises <code>ServerError(errors, FetchedResponse)</code>.</li>
        <li><b>Cancel:</b> <code>response.cancel()</code> sends Attention (packet type <code>06</code>, header only) on the channel. Reading then discards everything up to the completion marked <i>acknowledges a cancel</i>, and the owner’s read raises <code>Cancelled</code>. If the request is still being sent, for example while waiting for MARS window credit, the next packet carries <i>ignore</i> + <i>last</i> instead. This comes in <b>M4</b>, with streamed requests, which share the same abandonment (${D(41)}); until then, a task canceled mid-send leaves its request partly sent, and a pool closes that connection (${D(36)}).</li>
        <li><b>A response dropped while open</b> raises a <code>ResourceWarning</code>. Its channel stays busy, so a pool closes that connection (${D(36)}).</li>
      </ul>
      <h3>Connection core and shell</h3>
      <ul>
        <li><b>Packets go to channels.</b> The packet joiner delivers packets, not whole messages; while connecting, they are still assembled into messages.</li>
        <li><b>Backpressure:</b> under MARS, the client returns window credit as the application consumes packets, so a slow reader on one channel slows only that channel. Without MARS, the reader pauses the socket when the channel’s inbox holds a set number of packets.</li>
        <li><b>The live <code>Response</code></b> in <code>shell.py</code> is a thin async layer over the state machine. The later synchronous shell (for DB-API) reuses the same state machine.</li>
      </ul>
      <h3>Observability</h3>
      <ul>
        <li><b>Outline:</b> one line per response when it ends, with a tally of its tokens. Cancel shows as <code>→ attention</code> and <code>← cancel acknowledged</code>.</li>
        <li><b>Full:</b> each token’s tree as it is decoded.</li>
        <li><b>Levels</b> are left for ${D(12)} to decide.</li>
      </ul>

      <h2 id="4-milestones">4 · Milestones ${badge('Agreed')} ${D(46)}</h2>
      <p>Each milestone uses only what earlier ones built, ends with its tests passing against the live server, and comes with its reference pages. Its checks are in ${L('done-when', 'Done When')}.</p>
      ${table(['Milestone', 'Builds', 'Needs'], [
        ['<b>M1 · Requests and the response record</b>', `<code>Batch</code>, <code>exchange(request)</code>, the streaming response and its record (${D(34)}, ${D(42)}), cancel, backpressure, NBCROW and ORDER`, '—'],
        ['<b>M2 · Every short type</b>', 'all numbers, dates and times, <code>uniqueidentifier</code>, <code>char</code> / <code>varchar</code> / <code>nchar</code> / <code>nvarchar</code> / <code>binary</code> / <code>varbinary</code> up to 8,000 bytes, <code>rowversion</code>, <code>sysname</code>; nullable and fixed-size codes; the collation file', 'M1'],
        ['<b>M3 · Calls</b>', '<code>Call</code> / <code>Calls</code> / <code>Param(output=)</code>, <code>returns()</code>, <code>CallOptions</code>; every M2 type as a parameter', 'M2'],
        ['<b>M4 · Large values, both directions</b>', `the <code>(max)</code> types (<code>types.MAX</code>), <code>xml</code>, and <code>text</code> / <code>ntext</code> / <code>image</code>; <code>result_set.streamed()</code> and <code>ValueStream</code> (${D(47)}); sources in <code>Call</code> and <code>Calls</code>, and abandoning a request mid-send (${D(41)})`, 'M3'],
        ['<b>M5 · <code>sql_variant</code></b>', 'values that carry their own base type', 'M2'],
        ['<b>M6 · <code>json</code> and <code>vector</code></b>', `the login asks for both features (${D(8)}); <code>json</code> (<code>F4</code>); <code>vector</code> (<code>F5</code>) in float32 and float16`, 'M4'],
        ['<b>M7 · CLR types</b>', '<code>hierarchyid</code>, <code>geometry</code>, <code>geography</code> and user CLR types, as bytes plus the type’s full name', 'M4'],
        ['<b>M8 · Table-valued parameters</b>', '<code>F3</code>, parameters only', 'M3'],
        [`<b>M9 · Bulk load</b> (${D(50)}, ${D(52)})`, '<code>BulkInsert</code> and <code>BulkRows</code>, kept together by the channel; rows from a list or a source', 'M4'],
        [`<b>M10 · Transaction manager</b> (${D(51)}, ${D(52)})`, '<code>tds.transactions</code>: begin, commit, roll back, savepoints, promote, propagate, the coordinator’s address', 'M1'],
        [`<b>M11 · Every token the server can send</b> (${D(56)})`, 'a definition for every token MS-TDS 7.4 defines, so no response can end the connection with an unknown tag: browse-mode TABNAME and COLINFO, SESSIONSTATE, DATACLASSIFICATION, ALTMETADATA and ALTROW, SSPI and FEDAUTHINFO', 'M1'],
        [`<b>M12 · Slice 1’s failures, tested</b> (${D(56)})`, 'each way connecting can fail, tested: a server that can’t encrypt, an instance mismatch, a version below 7.4, a malformed reply, the connection timer', '—'],
        [`<b>M13 · TDS 8.0 and the observability levels</b> (${D(56)})`, 'strict encryption: TLS before the hello, ALPN <code>tds/8.0</code>, the certificate validated (D-10); the levels off, outline and full (D-12); replaying a saved conversation offline', 'M12'],
        [`<b>M14 · Connection and login options</b> (${D(56)})`, 'session recovery (SESSIONSTATE); the remaining login features (D-8) and identity flags (D-9): UTF-8 support, data classification, read-only intent, failover partner; the dedicated administrator connection (DAC); routing (D-11), against constructed bytes; a Browser client (MC-SQLR), against constructed bytes', 'M11'],
        [`<b>M15 · Always Encrypted</b> (${D(56)}, ${D(60)})`, 'in the core: every Always Encrypted wire element, with ciphertext shown as it arrives; in <code>tds.encryption</code>: the shared context, describing and encrypting parameters, decrypting values, a local key store; read back exactly what it writes. Enclaves come later, on Azure (M18)', 'M14'],
        [`<b>M16 · The convenience layer and the synchronous shell</b> (${D(56)})`, 'the serial channel’s conveniences (D-37); the bulk-load helper (D-50); the error translator; the synchronous entry point (D-38). DB-API is outside this project (D-25)', 'M10'],
        [`<b>M17 · Other logins, on Azure</b> (${D(56)})`, 'Kerberos, NTLM, federated logins and the SQL login variants (D-54, D-55); routing and the Browser, live; Always Encrypted’s Azure Key Vault and Windows certificate store key stores (D-60); on transient Azure infrastructure', 'M14'],
        [`<b>M18 · Azure-only login features</b> (${D(8)}, ${D(56)})`, 'Azure SQL support (failover partner with read-only intent), Azure DNS caching, enhanced routing (D-11), global transactions; Always Encrypted with enclaves (D-60); on the same transient Azure infrastructure', 'M17'],
      ])}
      <p><b>The scenario that grows with them:</b> a <code>shop</code> schema in a <code>tds_test</code> database. M1–M3 bring products, customers and orders using every short type, with procedures that return outputs. M4 adds <code>varbinary(max)</code> photos, <code>nvarchar(max)</code> descriptions and an old <code>ntext</code> notes column. M5–M7 add an <code>sql_variant</code> attributes table, <code>json</code> details, a <code>vector</code> embedding and a <code>geography</code> store location. M8 adds bulk price updates through a table-valued parameter. M8 is done when all of it round-trips.</p>

      <h2 id="5-how-it-s-tested">5 · How it’s tested</h2>
      <ul>
        <li><b>Core tests, no server.</b> The core is sans-I/O, so a test feeds it bytes and checks what it does: the channel rules, request encoding, and the response state machine. The token sequences on ${L('ref/response', 'Request Response')} were captured from the live server and become fixtures.</li>
        <li><b>Live tests, against the SQL Server 2025 container.</b> Every fact on Request Response, its rules and its edge cases, is a live test. If a new server version behaves differently, a test fails and the page is updated.</li>
        <li><b>Round trips, with values the server generates (${D(48)}).</b> The values: <code>SYSDATETIME()</code>, <code>SYSDATETIMEOFFSET()</code>, <code>GETDATE()</code>, <code>NEWID()</code>, <code>CRYPT_GEN_RANDOM(n)</code>, <code>RAND(CHECKSUM(NEWID()))</code>, every byte under every code page, every UTF-16 code unit including unpaired surrogates, each type’s minimum and maximum, and NULL. The test selects them, inserts them into a second table through a <code>Call</code> with each column’s type, and selects again. It passes when <code>EXCEPT</code> in both directions returns nothing and the values compare equal in Python. This runs from M3, when <code>Call</code> exists, for every type each milestone adds.</li>
        <li><b>The <code>shop</code> scenario</b> grows with each milestone (§4).</li>
        <li><b>The password never appears in output.</b> Live tests take it through the masked <code>Secret</code>, and test output is scanned for it.</li>
      </ul>

      <h2 id="6-after-these-milestones">6 · After these milestones</h2>
      <p>The second sequence is M9–M18 (§4, ${D(52)}, ${D(56)}), checked as ${L('done-when', 'Done When')} lists. The other logins come last, tested on transient Azure infrastructure (${L('ref/conversations', 'Conversations', 'what-each-way-of-logging-in-needs--built-d-54-d-55')}, ${D(54)}). What follows the milestones is in the ${L('roadmap', 'Roadmap')} (${D(63)}).</p>`,
  });
})();
