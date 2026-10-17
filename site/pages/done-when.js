/* Done When — the checks that end this slice. */
(function () {
  const { L, D } = window.TDS;
  const list = (items) => `<ul class="checks">${items.map((i) => `<li>${i}</li>`).join('')}</ul>`;

  window.TDS.page({
    id: 'done-when', group: 'Design', num: '5', kind: 'check',
    title: 'Done When',
    where: 'When each slice and milestone is finished.',
    outcome: 'tell when each slice and milestone is finished, with four kinds of check: what a reader can do, what the client does, what the runtime shows, and how the code reads.',
    body: () => `
      <p>The milestones are planned in ${L('build', 'Building the Client §4', '4-milestones')}.</p>
      <h2>Slice 1 · Connect &amp; log in</h2>
      <p><b>Status: partly built, checked 2026-10-16; updated by M12 and M13.</b> <b>Built and tested:</b> the spec’s samples round-trip (client 1); connecting on 7.4 with whole-connection encryption (2); every clear failure (4, M12); serial channels (6); the password never shown (runtime 5). <b>Built in M13:</b> connecting on 8.0 (3); offline replay (runtime 3); the observability levels (runtime 1, 2 and 4). <b>Not built:</b> routing (5, waits on D-11). <i>Built in M14.</i> <b>Not done:</b> the reader test, and a check of the code against its pages.</p>
      <h3>A reader can… (the documents work)</h3>
      <p>Test by giving the Learn and Reference pages to someone new to TDS, or to an assistant with no other context, together with a login capture that is <b>not</b> on these pages.</p>
      ${list([
        'Split the capture into packets and messages, and name each message.',
        'Label every field of the hello and the login, and say what each one does.',
        'From the login reply alone, say whether the login succeeded and what the session’s database, language and packet size are.',
        'Say what would differ under TDS 8.0.',
      ])}

      <h3 id="the-client-the-behaviour-is-right">The client… (the behavior is right)</h3>
      ${list([
        '<b>Round-trips MS-TDS’s samples:</b> it decodes the hello, login and login-reply samples and re-encodes them byte for byte.',
        '<b>Connects on 7.4</b> to SQL Server 2022 with whole-connection encryption, and reaches <i>ready</i> with the session state the server announced.',
        '<b>Connects on 8.0</b> to SQL Server 2022 in strict mode, offering ALPN <code>tds/8.0</code> and validating the certificate.',
        `<b>Fails clearly</b> in each of these cases, naming the step, what was expected and what arrived:
          <ul>
            <li>a wrong password, with the server’s own message;</li>
            <li>a server that can’t encrypt;</li>
            <li>an instance mismatch;</li>
            <li>a server version below 7.4;</li>
            <li>a malformed reply;</li>
            <li>the connection timer expiring.</li>
          </ul>`,
        `<b>Handles routing</b> as ${D(11)} decides.`,
        `<b>Provides serial channels as agreed.</b> Without MARS, a ready connection opens exactly one. Asking for a second fails without disturbing the first (${D(18)}–${D(23)}).`,
      ])}

      <h3>The runtime shows… (observability is right)</h3>
      ${list([
        'At <b>full</b> level, every byte of the connect conversation can be reached by expanding the view, level by level. Each byte is shown with its field, meaning and reference page, as in the grids on these pages.',
        `The names on screen are the names on these pages and in the code (${D(7)}).`,
        'A saved connect conversation, replayed offline, produces the identical view.',
        `At <b>off</b> level, nothing about individual messages is kept (${D(12)}).`,
        'The password never appears, decoded or as raw bytes, unless it has been explicitly revealed for that session.',
      ])}

      <h3>The code… (reads like these pages)</h3>
      ${list([
        'The PRELOGIN, LOGIN7 and token definitions can be read side by side with their Reference pages, matching field for field, in the same order, with the same names.',
        `The connect procedure reads top to bottom as the steps in ${L('ref/connect', 'Connect')}, and all of it lives in the connection manager (${D(17)}).`,
        `Every definition and procedure carries its MS-TDS section and spec revision, and the engine contains no tag values, field names or message types (${D(27)}).`,
      ])}

      <h2>M1 · Requests and the response record</h2>
      <p><b>Status: built, 2026-10-16.</b> All 108 tests pass: core tests on responses captured from the live server, and live tests. Not yet covered:</p>
      <ul>
        <li><b>The RPC facts on Request Response</b> (calls, outputs and ordinals, refused calls, error 8162) are checked against captured responses in core tests. Their live tests need <code>Call</code>, which comes in M3.</li>
        <li><b>Canceling a request while it is still being sent</b> (the <i>ignore</i> flag) moved to M4, agreed 2026-10-16. Until then, a task canceled mid-send leaves its request partly sent, and a pool closes that connection rather than lending it again (${D(36)}).</li>
      </ul>
      <h3>The client…</h3>
      ${list([
        '<b>Takes request objects:</b> <code>exchange(Batch(sql))</code> returns the open response. <code>exchange(str)</code> is gone, and the command-line tool and tests use <code>Batch</code>.',
        '<b>Reads responses as The Client §4 says:</b> iterate the response, then each result set; <code>fetch()</code> returns a <code>FetchedResponse</code> that can be read again and indexed; <code>finish()</code> skips rows to the end; <code>close()</code> cancels; <code>returns()</code> works with each <code>Unread</code> choice: <code>REFUSE</code> raises, <code>KEEP</code> keeps everything, <code>DISCARD</code> skips rows.',
        `<b>Records what the server did:</b> for every example and rule on ${L('ref/response', 'Request Response')}, live, the record (<code>sequence</code>, <code>completions</code>, <code>messages</code>, <code>errors</code>, result sets with their completions) matches it token for token. This covers counts under <code>NOCOUNT</code>, errors that end a statement or the batch, nested <code>EXEC</code>, and ORDER.`,
        '<b>Raises errors at the end</b> with the whole record. The channel is free, and the record is the same at every observability level.',
        '<b>Cancels from any task:</b> during <code>WAITFOR DELAY</code>, another task’s <code>response.cancel()</code> ends the owner’s read with <code>Cancelled</code>, and the next request on that channel works, with and without MARS.',
        '<b>Streams in bounded memory:</b> a response far larger than the inbox limit is read with memory that stays flat. Under MARS, a channel nobody is reading doesn’t stall another channel.',
        '<b>Warns about dropped responses:</b> a response dropped while open raises a <code>ResourceWarning</code>, and a pool closes that connection.',
      ])}
      <h3>The runtime shows…</h3>
      ${list([
        '<b>Outline:</b> one line per response, with its token counts. Cancel shows as <code>→ attention</code> and <code>← cancel acknowledged</code>.',
        '<b>Full:</b> every token of a response, reachable by expanding the view.',
      ])}
      <h3>The code and docs…</h3>
      ${list([
        '<code>response.py</code> reads side by side with Request Response and The Client §4.',
        `Neither <code>exchange</code> nor the response reader branches on the kind of request (${D(33)}).`,
        'Reference › Requests describes the SQL batch, matching <code>requests.py</code> field for field.',
        'Every observed fact on Request Response has a live test.',
      ])}

      <h2>M2 · Every short type</h2>
      <p><b>Status: built, 2026-10-16.</b> 194 tests pass. Done as listed, with two findings:</p>
      <ul>
        <li><b>UTF-8:</b> when SQL Server has stored invalid bytes, it sends U+FFFD in their place, so those values can’t come back exactly (without the UTF-8 login feature, ${D(8)}). Valid UTF-8 round-trips.</li>
        <li><b>Without the ODBC flag, sessions start with every ANSI option off,</b> which changes overflow, NULL concatenation and <code>char</code> padding. The flag became the named option <code>connect(odbc=…)</code>, on by default since M4’s design (${D(9)}).</li>
      </ul>
      <p>The select → insert → select round trip (${D(48)}) is checked from M3 onward, once <code>Call</code> exists.</p>
      <h3>The client…</h3>
      ${list([
        `<b>Reads every short type in the <code>shop</code> tables</b>, including NULL, in both the nullable and fixed-size codes, giving the values ${D(48)} defines.`,
        '<b>Decodes losslessly:</b> every byte 0x00–0xFF stored under each code page’s collation decodes to the character SQL Server gives it, including the bytes Python’s codecs refuse; <code>nvarchar</code> values with unpaired surrogates decode intact.',
        '<b>Generates its byte tables from the server:</b> the generator compares the double-byte code pages and UTF-8 collations with Python’s codecs, and records every difference in <code>collations.py</code>.',
        '<b>Decodes <code>varchar</code> with each column’s own collation:</b> one column per code page family (Latin1, Cyrillic, Greek, Japanese, Chinese, Korean, Thai) and one UTF-8 collation.',
        '<b>Fails clearly on an unknown collation</b>, naming its locale id, sort id and bytes. This is a core test with constructed bytes.',
        '<b>Encodes and checks every short type:</b> it round-trips through encode and decode in core tests. A value that doesn’t fit its declared type exactly is refused before sending: out of range, too long, too much scale, finer time precision, or a character the code page can’t hold.',
        '<b>Keeps time exact:</b> the driver time types hold 100 ns and 1/300-second ticks, and convert to Python’s types exactly, or refuse unless rounding is asked for.',
      ])}
      <h3>The code and docs…</h3>
      ${list([
        '<code>types.py</code> reads side by side with Reference › Data Types.',
        '<code>collations.py</code> is generated by <code>tools/generate_collations.py</code> and records the server version it came from.',
      ])}

      <h2>M3 · Calls</h2>
      <p><b>Status: built, 2026-10-16.</b> All 228 tests pass. Done as listed. <code>docs/tds-common-structure.md</code> was retired. Findings, now on ${L('ref/requests', 'Requests › Edge cases', 'edge-cases')}:</p>
      <ul>
        <li><b>A declared <code>varchar</code> parameter is in the database’s default collation.</b> A value from a column in another collation is converted when the server receives it. So it goes back exactly only through a parameter declared <code>nvarchar</code>, and even then not the sequences that the server itself writes back differently. Through a <code>varchar</code> procedure parameter, Greek α arrived as <code>a</code>.</li>
        <li><b><code>sp_execute</code> called by number refuses a named handle</b> (error 4002).</li>
        <li><b>The server ignores the <i>no metadata</i> option.</b> The driver reads either form.</li>
      </ul>
      <h3>The client…</h3>
      ${list([
        '<b>Calls procedures by name and by <code>Builtin</code></b>, reading return status, outputs (<code>output=True</code>) and function results as Request Response describes.',
        '<b>Handles <code>Calls</code>:</b> for a refused call, one that ends the batch, and calls that all run, <code>returns()</code> has exactly the entries the server completed.',
        `<b>Round-trips every M2 type exactly, live (${D(48)}):</b> server-generated values are selected, inserted through a <code>Call</code> with each column’s type, and selected again. <code>EXCEPT</code> in both directions returns nothing, and the values compare equal in Python. The values include every byte under every code page, unpaired surrogates, and each type’s minimum and maximum.`,
        '<b>Applies <code>CallOptions</code> as defined.</b> A <code>NO_METADATA</code> call without columns is refused before sending.',
      ])}
      <h3>The code and docs…</h3>
      ${list([
        'Reference › Requests adds the RPC, matching <code>requests.py</code>.',
        `<code>docs/tds-common-structure.md</code> is retired (${D(5)}).`,
      ])}

      <h2>M4 · Large values, both directions</h2>
      <p><b>Status: built, 2026-10-16.</b> All 277 tests pass. Done as listed:</p>
      <ul>
        <li><b>1 GB each way, in bounded memory:</b> read through <code>streamed()</code> in about 10 seconds and sent from a source in about 6, while the process’s memory grew by less than 200 MB.</li>
        <li><b>Every large type round-trips exactly,</b> <code>text</code>, <code>ntext</code> and <code>image</code> included.</li>
        <li><b>Abandoning:</b> the server answers <i>ignore</i> + <i>last</i> with a DONE marked <i>error</i>, and the pool lends the same connection again. <i>Corrected 2026-10-16:</i> a message comes before that DONE (${L('ref/requests', 'Requests', 'edge-cases')}).</li>
      </ul>
      <p>Found while building: a result set with large values <b>waits at its first row</b> until the application chooses how to read it (tuples, <code>streamed()</code>, <code>fetch()</code>, or moving to the next result set). The first row’s bytes arrive with the column metadata, so without that pause a value meant to be streamed would already have been held whole.</p>
      ${list([
        `<b>The streaming design is agreed first</b> (${D(47)}, with ${D(41)}). <i>Agreed 2026-10-16.</i>`,
        `<b>The <code>(max)</code> types, <code>xml</code>, <code>text</code>, <code>ntext</code> and <code>image</code> round-trip exactly</b> (${D(48)}), with server-generated values; for <code>xml</code>, from its first normalized form.`,
        `<b>Both ways of reading work</b> (${D(47)}): tuples hold large values whole; <code>result_set.streamed()</code> provides each large value as a <code>ValueStream</code>, which is read once, while its row is current; moving on discards the unread rest; text is never split inside a character, under every code page.`,
        '<b>A value larger than memory streams both ways with bounded memory.</b> The test uses a 1 GB <code>varbinary(max)</code>, read through <code>streamed()</code> and sent from a source.',
        `<b>Sources work in <code>Call</code> and in <code>Calls</code></b> (${D(41)}), and a whole large value is sent with its length known.`,
        `<b>Large values arrive whole with the ODBC flag</b> (the default), and cut to 4,096 bytes with <code>odbc=False</code>, exactly as the server sends them (${D(9)}).`,
        `<b>Observability never holds a large value whole:</b> its tree shows the chunk count, total length and first bytes (${D(47)}).`,
        `<b>A streamed request whose source fails partway is abandoned whole</b> with the <i>ignore</i> flag. Nothing runs, and the source’s own error is raised (${D(41)}).`,
        '<b>A request canceled while it is still being sent is abandoned the same way.</b> This includes a task canceled while it waits for MARS window credit. The next packet carries <i>ignore</i> + <i>last</i>, the driver reads the server’s answer, the channel is free, and the connection is lent again.',
      ])}

      <h2>M5 · <code>sql_variant</code></h2>
      <p><b>Status: built, 2026-10-16.</b> All 301 tests pass. Every base type round-trips exactly, with the same base type, precision, scale, collation, size and bytes (<code>SQL_VARIANT_PROPERTY</code>). Found while building: the server writes a decimal in the smallest size that holds it. A <code>sql_variant</code> makes this visible, so the driver now does the same.</p>
      ${list([`<b>Every base type a <code>sql_variant</code> can hold round-trips exactly</b> (${D(48)}), and each value reports its base type.`])}

      <h2>M6 · <code>json</code> and <code>vector</code></h2>
      <p><b>Status: built, 2026-10-16.</b> All 312 tests pass. Done as listed, except float16, which this server doesn’t have: it accepts vector support version 1 only, and refuses <code>vector(n, float16)</code>, so the driver’s float16 handling is tested with constructed bytes, not live. Findings, now on ${L('ref/types', 'Data Types')}: <b><code>json</code> arrives as UTF-16LE, but parameters must be UTF-8</b>; a <code>vector</code> column has user type 255.</p>
      ${list([
        `<b>The login asks for JSONSUPPORT and VECTORSUPPORT</b> (${D(8)}), and the server’s acknowledgement is visible in the login reply.`,
        '<b><code>json</code> arrives as <code>json</code>, and <code>vector</code> as <code>vector</code></b>, in float32 and float16. Both round-trip exactly as parameters (D-48).',
      ])}

      <h2>M7 · CLR types</h2>
      <p><b>Status: built, 2026-10-16.</b> All 317 tests pass. Values the server generates round-trip exactly, compared as bytes on the server and in Python:</p>
      ${list([
        '<b><code>hierarchyid</code>, <code>geometry</code> and <code>geography</code>:</b> random paths, buffered shapes over 1,000 bytes, and points.',
        '<b>A user CLR type:</b> <code>dbo.Point</code>, from <code>tests/clr/Point.cs</code>, built with Microsoft’s .NET SDK Docker image (<code>tests/clr/build.sh</code>) and loaded as a trusted assembly. Its values are random points, the extremes of <code>int</code>, and NULL.',
      ])}
      <p>Found while building, now on ${L('ref/types', 'Data Types')}: <b>a CLR column’s type names the database the column belongs to</b> (<code>tempdb.sys.geometry</code> for a temporary table); <b>a fixed-size CLR type is flagged</b>: <code>dbo.Point</code> (.NET’s Native format) has a max size of 9, and its column carries the fixed-length CLR flag (<code>0x100</code>), now <code>ColumnFlags.FIXED_LENGTH_CLR_TYPE</code>.</p>
      ${list(['<b><code>hierarchyid</code>, <code>geometry</code>, <code>geography</code> and a user CLR type</b> arrive as bytes with the type’s full name, and round-trip exactly as parameters (D-48).'])}

      <h2>M8 · Table-valued parameters</h2>
      <p><b>Status: built, 2026-10-16.</b> All 327 tests pass. Done as listed:</p>
      ${list([
        '<b>Every short type, exactly:</b> a table of 203 rows with a column of every short type (server-generated values, each type’s limits, and NULL) reaches a procedure and is stored exactly, from a list and from a source.',
        '<b>The <code>shop</code> scenario round-trips:</b> customers, products, attributes and stores, with every type M1–M7 built, go back exactly, compared as bytes on the server and in Python; orders are placed through a procedure whose output is each new order’s id; every price is updated in one table parameter, and reads back exactly as the server picked it.',
        '<b>Columns the server fills, <code>DEFAULT</code>, the sort and unique hint, and the send order</b> behave as MS-TDS describes.',
      ])}
      <p>Found while building, now on ${L('ref/types', 'Data Types')}: <b>the server requires the default status bit for <i>no table</i></b>, where MS-TDS says it must be zero (error 8060 without it), so <code>DEFAULT</code> sends it (<i>amended by D-53:</i> <code>None</code> is sent too, without the bit, and the server’s refusal reaches the application); <b>the sort hint is checked</b> (error 4819 for rows out of order); <b>an identity column sent with values is refused</b> (error 1077); <b><code>sp_executesql</code> needs the table type’s name</b> (error 8059).</p>
      ${list([
        '<b>A table-valued parameter with a column of every short type</b> is sent to a procedure, and the procedure sees every row, exactly (D-48).',
        `<b>The whole <code>shop</code> scenario round-trips</b> (${L('build', 'Building the Client §4', '4-milestones')}).`,
      ])}

      <h2>M9 · Bulk load</h2>
      <p><b>Status: built, 2026-10-16.</b> All 366 tests pass. Done as listed: 203 rows of every short type, NULL and NOT NULL, from a list and from a source, and the large and special types (<code>(max)</code>, <code>xml</code>, <code>text</code>, <code>ntext</code>, <code>image</code>, <code>sql_variant</code>, <code>json</code>, <code>vector</code>, <code>geography</code>, <code>hierarchyid</code>) load exactly, compared as bytes on the server and in Python; 1 GB (1,024 rows of 1 MB) loads from a source while the process’s memory grows by less than 200 MB; a source that fails partway is abandoned with <i>ignore</i>, nothing loads, and the channel accepts the next bulk load.</p>
      <p>Found while building, now on ${L('ref/requests', 'Requests › Edge cases', 'edge-cases')}: <b><code>json</code> travels as <code>nvarchar(max)</code></b>, declared so in the statement as well, like <code>text</code>, <code>ntext</code> and <code>image</code> (<code>xml</code> and CLR types may be declared either way); and <b>how the options behave</b>, including that a load without <code>CHECK_CONSTRAINTS</code> leaves the constraint <i>not trusted</i>.</p>
      ${list([
        '<b>Every type from M2–M7 loads exactly</b> (D-48, D-50): server-generated values, each type’s limits, and NULL, with the columns from <code>SELECT TOP 0 *</code> and the rows from a list or a source. <code>xml</code>, CLR and legacy text columns are included.',
        '<b>1 GB loads in bounded memory,</b> from a source.',
        '<b>Bulk data can’t be sent at the wrong time.</b> After <code>BulkInsert</code>, the channel accepts only <code>BulkRows</code>, and <code>BulkRows</code> is refused at any other time. A source that fails partway is abandoned with <i>ignore</i>, and the connection stays usable.',
        '<b>Each <code>INSERT BULK</code> option tested live behaves as documented:</b> <code>CHECK_CONSTRAINTS</code>, <code>FIRE_TRIGGERS</code>, <code>KEEP_NULLS</code>, <code>TABLOCK</code>, <code>ORDER</code>, <code>ROWS_PER_BATCH</code>, <code>KILOBYTES_PER_BATCH</code>.',
        `<b>Every bulk-load behavior on ${L('ref/requests', 'Requests › Edge cases', 'edge-cases')} has a live test,</b> deviations from MS-TDS included.`,
      ])}

      <h2>M10 · Transaction manager</h2>
      <p><b>Status: built, 2026-10-16.</b> All 366 tests pass. Done as listed. <code>Propagate</code> is tested only for its refusal of a bad cookie (error 8509), and the enlist, defect and transaction-ended announcements remain unobserved.</p>
      ${list([
        '<b>Each request works live, and the session follows its announcements</b> (D-51), through nesting and savepoints.',
        '<b>Commit-and-begin keeps its isolation level</b> for the session.',
        '<b>Promote’s token is visible</b> in its announcement, and <b>the coordinator’s address</b> is read as one row.',
        '<b><code>Propagate</code> is sent as MS-TDS defines it, and only its refusal is tested.</b> It needs a cookie from a coordinator. The enlist, defect and transaction-ended announcements are unobserved.',
        '<b>Every transaction behavior on Requests, Request Response and Token Stream has a live test,</b> deviations from MS-TDS included.',
      ])}

      <h2>M11 · Every token the server can send</h2>
      <p><b>Status: built, 2026-10-16.</b> Done as listed. <b>Tested live:</b> browse mode’s TABNAME and COLINFO. Found while building, now on ${L('ref/response', 'Request Response', 'edge-cases')}: the server sends them under <code>SET NO_BROWSETABLE ON</code> and for every kind of server cursor, as well as <code>FOR BROWSE</code>, so each used to end the connection; and browse mode adds hidden key and <code>rowversion</code> columns. <b>Tested with bytes built from MS-TDS:</b> data classification (both versions) and SESSIONSTATE, which need login features (M14); ALTMETADATA and ALTROW, which SQL Server no longer sends; SSPI and FEDAUTHINFO, which belong to other logins (M17). <b>Corrected:</b> OFFSET is no longer in the list, because it was removed in TDS 7.2. Also, NBCROW’s and ORDER’s MS-TDS section numbers in the code were wrong. They are now §2.2.7.15 and §2.2.7.17.</p>
      ${list([
        `<b>Every token MS-TDS 7.4 defines has a definition,</b> so no response ends the connection with an unknown tag: TABNAME, COLINFO, SESSIONSTATE, DATACLASSIFICATION, ALTMETADATA, ALTROW, SSPI and FEDAUTHINFO, in addition to those already built.`,
        `<b>What each token says is in the response record</b> (D-42), shown as the server sends it.`,
        `<b>Each token the local server can be made to send is tested live,</b> such as browse mode’s TABNAME and COLINFO (<code>SELECT … FOR BROWSE</code>). The rest are tested with bytes built from MS-TDS, and the page says which.`,
      ])}

      <h2>M12 · Slice 1’s failures, tested</h2>
      <p><b>Status: built, 2026-10-16.</b> All 388 tests pass. Each failure is tested, and so are the server closing mid-connect and a server that can’t be reached. The hello and login replies are fed to the core’s connect procedure; the connection timer and the unreachable server use real local sockets. The version check uses MS-TDS’s own sample login reply, which acknowledges TDS 7.2. <b>Made literate while building:</b> the connection timer used to appear as a bare <code>TimeoutError</code>, and a malformed reply as a parse error without its step. Each is now a <code>ConnectError</code> naming its step (<code>start</code>, <code>hello</code>, <code>secure</code>, <code>log in</code>), and a malformed reply shows the bytes that arrived.</p>
      ${list([
        `<b>Each failure in Slice 1’s client item 4 is tested,</b> and its error names the step, what was expected and what arrived (D-53): a server that can’t encrypt, an instance mismatch, a version below 7.4, a malformed reply, the connection timer.`,
      ])}

      <h2>M13 · TDS 8.0 and the observability levels</h2>
      <p><i>D-10 and D-12 agreed 2026-10-16.</i></p>
      <p><b>Status: built, 2026-10-16.</b> All 406 tests pass. TDS 8.0 connects with TLS 1.3 and ALPN <code>tds/8.0</code>, verified against the test container’s authority. This also works with MARS. Certificates are checked with Python’s <code>ssl.SSLContext</code>, and <code>trust_server_certificate</code> is gone: every test now verifies the certificate, and a wrong name, an unknown authority, and a non-verifying context under 8.0 are each refused with an error that says what the options are. The test container presents a certificate from a test authority, created reproducibly (<code>docker/macos/tls</code>). The levels: off builds nothing; outline and full show the same lines; full opens every message to its fields; the level changes between exchanges, never during one. Every structure names its reference page in the full view. <b>Captures replay into the identical full view,</b> byte for byte, under 7.4 and 8.0, with and without MARS, across results, messages, an output parameter, an error, transactions, a bulk load and a cancel. The password stays out of a capture unless it is kept, and is revealed in the view only for a session that asks.</p>
      <p>Found while building, now on ${L('ref/connect', 'Connect', 'edge-cases')}: SQL Server needs a certificate configured before it accepts 8.0; under 8.0 it answers the hello’s encryption with <i>not supported</i>, and its login reply still says TDS 7.4 (confirming Login Response’s open edge case); under 7.4 it negotiates TLS 1.2 at most. <b>Fixed while building:</b> at outline a request’s line said “0 packets”, because the count came from headers kept only at full; written requests showed parameter types as opaque bytes where reading showed their fields, and both now show the fields; bulk data, a procedure’s name and a call’s parameters gained reading definitions, for replay. <b>Not yet:</b> replay can’t decode table-valued parameters’ rows. Instead, it shows that message’s line and says so.</p>
      <p><b>Timing,</b> agreed and built 2026-10-16 (D-12 item 7): connect steps show their time since connecting began, responses their time to the first packet and to the end; captures record those times and the wall-clock start; <code>response.timing</code> is kept at every level. All 407 tests pass.</p>
      ${list([
        `<b>Connects on 8.0</b> in strict mode, offering ALPN <code>tds/8.0</code> and validating the certificate (Slice 1, client 3).`,
        `<b>The observability levels work as D-12 decides,</b> and Slice 1’s <i>The runtime shows…</i> items 1, 2 and 4 pass.`,
        `<b>A saved conversation, replayed offline, produces the identical view</b> (Slice 1, runtime 3).`,
      ])}

      <h2>M14 · Connection and login options</h2>
      <p><i>Needs D-8, D-9 and D-11 decided first.</i></p>
      <p><b>Status: built, 2026-10-16.</b> All 470 tests pass.</p>
      <ul>
        <li><b>Built:</b> the login’s feature list (${D(8)}: <code>connect(features=…)</code>; JSON, vector, UTF-8 support, data classification and session recovery are on by default, each with a command-line switch); the identity options (${D(9)}: application and host name, language, read-only intent, the real process ID); session recovery (${D(57)}): automatic at the next exchange if the connection broke with no request in progress, or through <code>connection.recover()</code>. A request in progress is never sent again. It is tested live, with sessions killed and connections cut through a relay, under MARS and TDS 8.0. Its login data is tested against MS-TDS’s own example; the mirroring partner, shown as <code>connection.session.mirroring_partner</code> and not acted on (${D(58)}), tested with constructed bytes, since SQL Server on Linux has no database mirroring; routing, followed once (${D(11)}), tested against a stand-in router; the DAC, live; and the Browser client, against MC-SQLR’s own examples and a stand-in on a local port. Every option is listed in ${L('ref/connect', 'Connect › Options', 'options')}; the Browser has its own page, ${L('ref/browser', 'Browser')}.</li>
        <li><b>Found while building:</b> with UTF-8 support, <code>json</code> arrives as UTF-8, not UTF-16LE (${L('ref/types', 'Data Types', 'edge-cases')}); a refused DAC closes the connection at the hello with no message; what session recovery brings back and what it doesn’t; the undocumented state 254 by which SQL Server says a session can’t be recovered, and its reason codes (${L('ref/connect', 'Connect', 'edge-cases')}); the answer to an abandoned request has a message before its DONE, which MS-TDS doesn’t mention. An M4 test had been matching another response, and claimed otherwise (${L('ref/requests', 'Requests', 'edge-cases')}).</li>
      </ul>
      ${list([
        `<b>Session recovery:</b> the login asks for it, SESSIONSTATE is kept, and a broken connection can be resumed with its session as the server allows.`,
        `<b>The remaining login features and identity flags work as D-8 and D-9 decide,</b> each tested live: UTF-8 support, data classification, read-only intent, failover partner (shown, D-58; tested with constructed bytes, because no mirrored server was available in M17 either).`,
        `<b>The dedicated administrator connection:</b> the test container accepts it from outside (remote admin connections on, port 1434 forwarded), and the driver connects through it.`,
        `<b>Routing works as D-11 decides,</b> tested with constructed bytes, and live in M17.`,
        `<b>A Browser client (MC-SQLR)</b> asks for an instance’s port, lists instances, and asks for the DAC port, tested with constructed bytes, and live in M17. The MC-SQLR specification is fetched beside MS-TDS into <code>docs/specification</code> (<code>tools/fetch_specifications.py</code>).`,
      ])}

      <h2>M15 · Always Encrypted</h2>
      <p><i>Design agreed: ${D(60)}, ${D(61)}.</i></p>
      <p><b>Status: built, 2026-10-17.</b> All 563 tests pass.</p>
      <ul>
        <li><b>Built:</b> the core reads and writes every Always Encrypted wire element: the feature, the key table, crypto metadata in columns and output parameters, encrypted parameters with their cipher info, and the enclave package as opaque bytes; a connection with the feature but without <code>tds.encryption</code> shows ciphertext. <code>tds.encryption</code>: the shared <code>Encryption</code>, which opens, pools or wraps connections; describing and encrypting parameters (for <code>sp_executesql</code> and procedure calls, positional ones too), describing again when the server refuses a call encrypted with an earlier description it kept; encrypting bulk rows; decrypting values through the core’s hook; a local key store of RSA files; <code>cryptography</code> as the optional extra <code>tds[encryption]</code>.</li>
        <li><b>Pass 1:</b> 28 types, from <code>tinyint</code> to <code>varbinary(max)</code>, at their edges and NULL, deterministic and randomized, read back exactly, through parameters and through bulk load, and each deterministic lookup finds its row. A column re-encrypted with another key is described again, and the call is sent again. Output parameters, ciphertext without the package, keys that can’t be decrypted, the server’s refusals, bulk load and a pool are tested live. The wire elements, the encryption, keys and normalization are tested against constructed bytes.</li>
        <li><b>Pass 2:</b> SqlClient 7.1.1 reads every value the driver wrote, inserted and bulk-loaded, and the driver reads every value SqlClient wrote, for the same 28 types, with lookups both ways. Two differences are SqlClient’s own: unpaired surrogates, and <code>time(0)</code> parameters (${L('ref/always-encrypted', 'Always Encrypted', 'edge-cases')}).</li>
        <li><b>Found while building:</b> table types can’t hold encrypted columns; bulk load into an encrypted column names it by its ciphertext’s type, as SqlClient’s SqlBulkCopy does (found by recording its statement on the server); MS-TDS numbers the algorithm two ways; the client’s bulk data needs a key table once the feature is agreed.</li>
      </ul>
      ${list([
        `<b>The core reads and writes every Always Encrypted wire element</b> (${D(60)}): the column encryption feature and its acknowledgement (version, enclave type); the key table and each column’s crypto metadata in COLMETADATA; crypto metadata in RETURNVALUE; encrypted parameters with their cipher info; the enclave package, as opaque bytes. Each is tested against constructed bytes, and live. A connection that negotiated the feature, without <code>tds.encryption</code>, shows encrypted values as ciphertext with their metadata.`,
        `<b><code>tds.encryption</code> works as ${D(60)} decides:</b> a shared <code>Encryption</code> context opens or wraps connections and pools, and refuses one whose login didn’t ask for column encryption. Its serial channels describe and encrypt parameters, and decrypt values through the core’s hook, in every way of reading a response.`,
        `<b>A local key store</b> (an RSA key file) decrypts column keys, and the tests create their master and column keys with it.`,
        `<b>Pass 1: what the driver writes, it reads back exactly</b> (${D(48)}), for every type an encrypted column can hold, deterministic and randomized: through parameters, result sets and output parameters. A lookup on a deterministic column finds its row.`,
        `<b>Errors are literate</b> (${D(53)}): no key store for a key’s provider, a key store that can’t decrypt a column key, a value whose authentication fails, the server’s refusals (such as error 33277, an encryption scheme mismatch), and a connection without the feature.`,
        `<b>Observed and documented:</b> an encrypted large value can’t be streamed, since nothing is released before its authentication is checked; whether bulk load into encrypted columns sends the key table; whether table-valued parameters can hold encrypted columns; and what the describe exchange shows at each observability level. Key material is never shown.`,
        `<b>Pass 2 (${D(61)}): .NET’s SqlClient reads what the driver wrote, and the driver reads what SqlClient wrote,</b> for every type, deterministic and randomized, with a custom key store over the same keys, in the .NET SDK container.`,
      ])}

      <h2>M16 · The convenience layer and the synchronous shell</h2>
      <p><i>Needs D-37 and D-38 decided first. DB-API is outside this project (${D(25)}).</i></p>
      ${list([
        `<b>The conveniences</b> (D-37), <b>the bulk-load helper</b> (D-50) and <b>the error translator</b> are built around the driver, using only its public surface (D-39).`,
        `<b>The synchronous entry point has the same shape as the asynchronous one</b> (D-38).`,
      ])}

      <h2>M17 · Other logins, on Azure</h2>
      <p><i>Needs D-55 decided first.</i></p>
      <p><b>Status: built, 2026-10-17,</b> before M16 (${D(62)}). 583 tests pass on macOS, local and Azure; the Kerberos tests pass on the Linux runner, and the Windows certificate store’s tests on SQL Server’s Windows VM. The infrastructure was created with Terraform (<code>infra/azure</code>) and deleted afterward.</p>
      <ul>
        <li><b>Built:</b> <code>connect(login=…)</code> with <code>WindowsLogin</code>, <code>EntraToken</code> and <code>EntraLogin</code>, their tokens from the application (${D(55)}), and adapters for pyspnego and azure-identity; <code>new_password=</code>; the hello’s FEDAUTHREQUIRED and nonce; LOGIN7’s Windows token and federated authentication feature; the SSPI exchange; FEDAUTHINFO and the token message; captures and observability that never show a credential. Key stores: Azure Key Vault, and the Windows certificate store through CNG.</li>
        <li><b>Live:</b> NTLM with a local and a domain account, Kerberos (and SPNEGO choosing it), both Entra ID logins, routing on Azure SQL, the Browser on SQL Server on Windows, changing an expired password and a contained database’s user on the local container, Always Encrypted with a Key Vault master key, and with a certificate store master key on Windows.</li>
        <li><b>Found:</b> a routed login must name the routed <code>server,port</code> (the original name is refused, 40613); Kerberos’s mutual authentication needs no answer, and an empty one breaks the connection; a wrong Windows password is refused as an “untrusted domain” (18452); Azure SQL’s Redirect policy routes connections from outside Azure too. Each is on ${L('ref/connect', 'Connect', 'edge-cases')} or ${L('ref/conversations', 'Conversations')}.</li>
      </ul>
      ${list([
        `<b>Each login in ${L('ref/conversations', 'Conversations', 'what-each-way-of-logging-in-needs--built-d-54-d-55')} works live</b> on transient Azure infrastructure, and the infrastructure is deleted afterward (D-54).`,
        `<b>Routing and the Browser are tested live</b> there, including which server name a routed login should send (${L('ref/connect', 'Connect', 'edge-cases')}).`,
        `<b>Always Encrypted’s other key stores</b> (${D(60)}): Azure Key Vault and the Windows certificate store decrypt column keys, beside the local one.`,
      ])}

      <h2>M18 · Azure-only login features</h2>
      <p><i>Needs D-8 decided for these features. Comes after M17, on the same Azure infrastructure.</i></p>
      <p><b>Status: built, 2026-10-17, with two parts open.</b></p>
      <ul>
        <li><b>The features</b> can be asked for, each off by default (<code>--azure-sql-support</code>, <code>--azure-dns-caching</code>, <code>--enhanced-routing</code>, <code>--global-transactions</code>). Azure SQL Database acknowledged Azure SQL support, DNS caching and global transactions with 1, and enhanced routing with 0 (not enabled). What each changes wasn’t seen: the test server had no failover partner, the driver caches no addresses (${D(39)}), no elastic transaction was run, and no ENVCHANGE 21 arrived. <i>Open:</i> whether any of them should be a default (${D(8)}).</li>
        <li><b>Enclaves:</b> version 2 and the enclave package, without attestation, were tested live on Azure SQL Database’s VBS enclave, with LIKE and range comparisons on randomized columns (${L('ref/always-encrypted', 'Always Encrypted › Enclaves', 'enclaves')}). Found: the package’s length is a u16, not MS-TDS’s u32. The describing call’s attestation parameters must be <code>varbinary(n)</code>. <i>Open:</i> version 3 (keys cached in the enclave), and attestation through Microsoft Azure Attestation or a Host Guardian Service.</li>
      </ul>
      ${list([
        '<b>Each Azure-only login feature is requested and acknowledged on Azure SQL,</b> and what it changes is observed and documented: Azure SQL support (failover partner with read-only intent), Azure DNS caching, enhanced routing (with D-11), global transactions.',
        `<b>Always Encrypted with enclaves</b> (${D(60)}): the column encryption feature’s versions 2 and 3, attestation, and the enclave package, on Azure SQL.`,
      ])}`,
  });
})();
