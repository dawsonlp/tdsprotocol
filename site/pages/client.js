/* The Client — the model's second and third expressions: how the code is built, and what the running client shows. */
(function () {
  const { T, L, D, table, code, term_out, tabs, layers, badge } = window.TDS;

  const LAYERS = `application
   │
outer layers        statements (parameterized, prepared, cursors) · Python values → SQL types
                    · conveniences · DB-API            ← built only on the driver's public surface
   │
the driver          connections and the pool · serial channels · exchange → response
                    · Batch · Call (any procedure, typed parameters) · cancel · session state
   │
TDS · TLS · TCP`;

  const DEFINITION = `token LoginAck  tag AD  length u16                -- Reference: Login Response · MS-TDS §2.2.7.14
  interface       u8 as Interface { default 0 · t-sql 1 }
  tds version     4 bytes as TdsVersion
  server program  short text
  server version  major u8 · minor u8 · build u16be
  summary: "LOGINACK {server program} · TDS {tds version}"`;

  const PROCEDURE = `connect(target, credentials)                       -- Reference: Connect
  if target is 8.0:  yield StartTls(alpn = "tds/8.0")
  reply = yield Exchange(Hello(encryption = on))
  require reply.instance is match                  "reached the wrong server instance"
  require reply.encryption gives full encryption   "server won't encrypt the connection"   -- D-10
  if target is 7.4:  yield StartTls(inside = hello packets)
  login = yield Exchange(Login(credentials))
  require login.ack                                "login rejected: {login.errors}"
  require login.ack.tds version is 7.4             "server speaks TDS {version}; 7.4 or later required"
  session.apply(login.announcements)
  if login.routing:  return Routed(login.routing)  -- D-11
  return Ready`;

  const MARS_USE = `with connection.serial_channel() as orders, connection.serial_channel() as lookups:   # the second needs MARS
  for row in orders.exchange("SELECT … FROM orders"):
    detail = lookups.exchange("SELECT … WHERE id = @id", id = row.id)`;

  const BORROW = `connection = await tds.connect(…)            # one connection, yours until you close it
async with pool.connection() as connection:   # borrowed whole: yours alone until the block ends
    async with connection.serial_channel() as channel:
        ...`;

  const RESPONSE = `async with await channel.exchange(request) as response:
    async for result_set in response:           # each result set as it starts arriving
        result_set.columns                      # its columns come first
        async for row in result_set:            # then its rows: plain tuples
            ...
        result_set.completion                   # the completion that closed it: count and flags
    returns = await response.returns(unread=Unread.KEEP)   # one entry per call the server completed`;

  const ITEMS = `Completion(kind, rows, status, statement)
    kind        STATEMENT · STATEMENT_IN_PROCEDURE · CALL       # DONE · DONEINPROC · DONEPROC
    rows        an int, or None when the server says the count isn't valid (SET NOCOUNT ON, an error)
    status      the DONE flags: MORE · ERROR · IN_TRANSACTION · COUNT · ATTENTION · SERVER_ERROR
    statement   the server's statement code, raw: 193 SELECT, 195 INSERT, … (MS-TDS doesn't define them)

Return(status, outputs, function_result, failed)
    status      the RETURN value, or None if the call never reached RETURN
    outputs     by ordinal (the parameter's position in the call, from 0) and by name
    failed      the call's DONEPROC is marked error`;

  const OUTLINE = `connect sales-db:1433 · ready in 41 ms
  → hello            47 B   encryption on · MARS on
  ← hello reply      43 B   server 16.0.1000 · encryption on
  ⇄ secure           TLS 1.2 · 4 records
  → log in          144 B   user sa · app OSQL-32
  ← login reply     353 B   8 tokens · LOGINACK Microsoft SQL Server · TDS 7.2`;

  window.TDS.page({
    id: 'client', group: 'Design', num: 'A', kind: 'explanation',
    title: 'The Client',
    where: 'The model’s second and third expressions: how the code is built, and what the running client shows.',
    outcome: 'name the client’s parts, say what each may and may not do, and predict what happens when code misuses a serial channel.',
    body: () => `
      <p>Each section shows its status from ${L('decisions', 'Decisions')}. Code below is <b>notation, not a chosen language</b>.</p>

      <h2 id="0-the-driver-and-the-layers-around-it">0 · The driver and the layers around it ${badge('Agreed')} ${D(39)}</h2>
      ${code(LAYERS, 'Layers')}
      <p><b>The driver represents SQL Server as TDS exposes it, as clearly and simply as possible.</b> Its requests are the protocol’s own: the ${L('ref/conversations', 'nine conversations')}. Anything shaped by what an application wants (statements, prepared queries, cursors, type inference, conveniences, DB-API) is built in a layer around the driver and uses only its public surface. Building them there adds no round trips. Prepared statements and cursors, for example, are calls to built-in procedures.</p>

      <h2 id="1-two-kinds-of-code">1 · Two kinds of code ${badge('Agreed')} ${D(27)}</h2>
      ${table(['', '<b>Teaching surfaces</b>', '<b>Machinery</b>'], [
        ['What', '<b>Definitions</b> (what the bytes are), <b>procedures</b> (how conversations go), <b>observability output</b> (what the client shows)', 'The generic engine: encode/decode, framing, I/O, buffering, scheduling'],
        ['Standard', 'Reads as plainly as the reference pages', 'As sophisticated as needed, but small, with written invariants, and fuzzed'],
        ['Protocol knowledge', '<b>All of it</b>: every tag, field, limit and policy decision', '<b>None</b>: no tag values, field names or message types'],
      ])}
      <p>The surfaces serve three readers:</p>
      <ul>
        <li><b>A security analyst</b> reads the definitions to see everything the client accepts (fields, size limits, redacted fields). The analyst reads the procedures to see every security decision (encryption, certificate, version, routing). The engine is reviewed separately for bounds safety, which is centralized there.</li>
        <li><b>A new developer</b> finds every surface mirrored by a page here, with the same names, in the same order, linked both ways. MS-TDS is only needed to cross-check.</li>
        <li><b>A maintainer facing a new MS-TDS release</b> matches its Change Tracking table against the MS-TDS section each surface element carries. That gives exactly what must change. A change that reaches the machinery means a new <i>kind</i> of structure has arrived.</li>
      </ul>
      <p><b>A definition</b> reads like its reference table. The grids on these pages are built from data of this same shape.</p>
      ${code(DEFINITION, 'Definition')}
      <p><b>A procedure</b> reads like its reference page. Each <code>yield</code> gives an action to the shell (§2). The shell performs the action and returns the result.</p>
      ${code(PROCEDURE, 'Procedure')}

      <h2 id="2-core-and-shells">2 · Core and shells ${badge('Agreed')} ${D(24)} ${D(32)}</h2>
      ${window.TDS.bands([
        { name: 'flow', parts: [{ label: 'client code' }, { label: 'serial channels', kind: 'mars' }, { label: 'CORE · pure protocol, TLS in memory', kind: 'tds', w: 2 }, { label: 'SHELL · sockets, clock, tasks', kind: 'tls', w: 2 }, { label: 'network' }] },
      ])}
      ${table(['<b>Core</b>: never touches I/O', '<b>Shell</b>: moves bytes and time, nothing else'], [
        ['Definitions and the codec · packet and MARS framing · procedures · session state · ownership rules · observation · TLS, run in memory (D-32)',
          'Sockets · clock and timers · identifying the current task or thread · scheduling'],
      ])}
      <ul>
        <li><b>Shell → core:</b> bytes arrived · TLS output · deadline reached · client calls (open, send, read, cancel, close), each tagged with the caller’s ${T('owner')}.</li>
        <li><b>Core → shell:</b> send bytes · feed TLS · start TLS · set a deadline · deliver rows, results, errors or announcements to a channel · close.</li>
      </ul>
      <p><b>Benefits:</b></p>
      <ul>
        <li>Procedures read as pure protocol.</li>
        <li>Every byte crosses one boundary, so observation happens at a single point.</li>
        <li>Replay is another shell, fed saved bytes, so its view is always identical to the live view. Tests are shells too.</li>
        <li>One core serves an async shell and a sync shell (for DB-API).</li>
      </ul>
      <p><b>Costs:</b></p>
      <ul>
        <li>Rows must be delivered in batches to keep the per-row overhead low.</li>
        <li>Backpressure must be part of the design. The core never buffers without limit.</li>
        <li>There are two thin shells to test.</li>
      </ul>

      <h2 id="3-connections-and-serial-channels">3 · Connections and serial channels ${badge('Agreed')} ${D(17)}–${D(23)}, ${D(36)}</h2>
      ${layers([
        { name: 'pool', desc: 'lends whole connections, each to one borrower at a time' },
        { name: 'connection', desc: 'a session: its own login, transaction and settings; runs in parallel with other connections' },
        { name: 'serial channel', desc: 'one exchange at a time; with MARS, several that take turns and share this connection’s session' },
        { name: 'exchange', desc: 'one request and its complete response' },
      ])}
      <p>The ${T('connection manager')} sets up every connection and is the only code that knows TLS versions and MARS (${D(17)}). An application gets a connection from <code>tds.connect()</code>, or borrows one whole from a ${T('pool')}:</p>
      ${code(BORROW, 'Getting a connection')}
      <p><b>A pool lends connections, never channels.</b> A borrowed connection is its borrower’s session alone. If the borrower uses MARS, every extra channel it opens is on <i>its own</i> session, for its own interleaving. Unrelated borrowers never share a transaction or settings.</p>
      <p><b>Requests are made only on a serial channel.</b> Neither the pool nor the connection makes requests itself (${D(36)}).</p>
      ${table(['When the pool…', '…this happens'], [
        ['is asked for a connection', 'lends an idle one, or opens a new one if the pool is below its size limit; otherwise waits until one is returned'],
        ['gets a connection back', 'resets its session before lending it again. The reset flag is set on the next request’s first packet, and the client’s session state returns to what login established'],
        ['gets a connection back with a request still in progress', 'closes it and never lends it again, because its next borrower would read another borrower’s response'],
      ])}
      <p>Per MS-TDS, a session reset doesn’t reset distributed transactions or the isolation level. A connection’s session id identifies its session while the session exists. SQL Server reuses ids after a session ends.</p>
      <p>The Python client follows ${D(21)}: every ${T('serial channel')} is <b>owned by the task that opened it</b> and <b>closes when its block ends</b>. The ${L('rust', 'Rust proposal', '1-ownership-and-permissions-come-first')} uses unique movable authority instead of task identity (${D(64)}); its core move/borrow and awaited cleanup contracts are agreed.</p>
      ${table(['When client code…', '…this happens'], [
        ['opens a second serial channel without MARS', `fails immediately; the open channel and the connection are unaffected (${D(20)})`],
        ['starts a request while a response is still open', `fails immediately; never queued (${D(22)})`],
        ['uses a serial channel from another task', `fails immediately, every time (${D(21)})`],
        ['cancels or closes from another task', `allowed (${D(23)})`],
        ['hands a serial channel to another task explicitly', `allowed; ownership moves (${D(21)})`],
        ['leaves the channel’s block', `authority is revoked; active exchanges are canceled/drained before release (${D(21)})`],
        ['hits a fatal error on any channel', `every channel on the connection fails with that error (${D(17)})`],
        ['receives an announcement on any channel', `the connection’s shared session state is updated (${D(17)})`],
      ])}
      <p>Channel close revokes one lifetime. Active exchanges cancel/drain through acknowledgement and its message boundary under a separate total cleanup budget (default 5 seconds). Failure or canceled cleanup discards the connection. Repeats share the first deadline; stale controls cannot affect a replacement. A pool can reuse a connection after proven cleanup; an unresolved abandoned exchange still forces discard. Close does not promise rollback.</p>
      <p>MARS exists for one pattern: reading one result while making other requests on the same connection.</p>
      ${code(MARS_USE, 'Interleaving on one connection')}

      <h2 id="4-exchanges-and-responses">4 · Exchanges and responses ${badge('Agreed')} ${D(33)} ${D(34)}</h2>
      <p>An ${T('exchange')} is one turn in the ${T('conversation')} on a serial channel: the client sends one request, then reads the server’s response to its end. Every operation an application performs is built on it. <code>exchange</code> always does the same thing: it sends the request and returns the open response. It never branches on the kind of operation. What differs is in the request definitions and the conveniences.</p>
      <h3>What a request can be</h3>
      <p>The driver’s requests are the protocol’s own (${D(39)}):</p>
      ${table(['Request', 'What it sends', 'Decision'], [
        ['<code>Batch</code>', 'SQL text', '—'],
        ['<code>Call</code> / <code>Calls</code>', 'one RPC, or several in one message: a procedure by name or built-in number, with explicitly typed parameters', D(40)],
        ['<code>BulkInsert</code>, then <code>BulkRows</code>', 'bulk load: the application’s <code>INSERT BULK</code> statement, then the columns and rows; the channel keeps the pair together', D(50)],
        ['<code>tds.transactions</code>: <code>Begin</code>, <code>Commit</code>, <code>Rollback</code>, <code>Save</code>, <code>Promote</code>, <code>Propagate</code>, <code>CoordinatorAddress</code>', 'transaction-manager requests', D(51)],
      ], 'compact')}
      <p>Cancel isn’t a request: it ends the exchange in progress (${L('ref/conversations', 'Conversations')} #9).</p>
      <p><b>Requests are built whole before sending,</b> except where only streaming makes the request practical. <b>Large values</b> (<code>…(max)</code>, <code>xml</code>), a table parameter’s rows and <b>bulk load</b> rows can be sent as a stream (${D(41)}). If a stream’s source fails partway, the driver abandons the whole request with the packet’s <i>ignore</i> flag. The server runs nothing and says so. The driver reads that answer, so that the channel is clean, then raises the source’s error. Nothing ever runs partially, so the driver doesn’t need TDS’s NO-EXEC separator (${D(40)}).</p>

      <h3>What a response holds ${D(42)}</h3>
      <p>A response is <b>the record of what the server did</b>: one ordered sequence of items, one per server token, exactly as they arrived. The server marks its structure by where certain tokens fall (${L('ref/response', 'Request Response')}). The driver shows that structure and builds no tree the server didn’t send.</p>
      ${table(['Item', 'From', 'What it says'], [
        ['<code>ResultSet</code>', 'COLMETADATA, then ROW / NBCROW, ORDER; TABNAME, COLINFO, DATACLASSIFICATION, ALTMETADATA, ALTROW', 'columns, then rows (plain tuples), its sort order if sent, and the completion that closed it. Where sent: where its columns came from (<code>tables</code>, <code>column_info</code>: browse mode and server cursors), its <code>classification</code>, and <code>COMPUTE</code> totals (<code>totals</code>, <code>total_rows</code>)'],
        ['<code>Completion</code>', 'DONE · DONEINPROC · DONEPROC', 'a statement ended (in a batch, or inside a procedure), or an outermost procedure call ended, with its count when the server gives one'],
        ['<code>Message</code>', 'INFO', '<code>PRINT</code>, a low-severity <code>RAISERROR</code>, a warning'],
        ['<code>Error</code>', 'ERROR', 'a statement failed'],
        ['<code>ReturnStatus</code>', 'RETURNSTATUS', 'a call’s <code>RETURN</code> value'],
        ['<code>OutputValue</code>', 'RETURNVALUE', 'an output parameter, or a function’s result'],
        ['<code>Announcement</code>', 'ENVCHANGE', 'a session setting changed; the session state is updated too'],
        ['<code>SessionState</code>', 'SESSIONSTATE', 'the session’s state, for recovering it, when the login asked for session recovery'],
      ], 'compact')}
      <p><b>Views.</b> Each is defined by one token rule, never by what was requested (${D(33)}):</p>
      ${table(['View', 'Rule', 'Readable'], [
        [T('result set', 'result sets'), 'COLMETADATA opens one; the next completion closes it', 'by iterating the response'],
        ['<code>response.completions</code>', 'every DONE, DONEINPROC and DONEPROC', 'as far as the response has been read'],
        ['<code>response.messages</code>, <code>response.errors</code>', 'every INFO; every ERROR', 'as far as read'],
        ['<code>returns()</code>', 'one <code>Return</code> per DONEPROC: the RETURNSTATUS and RETURNVALUEs before it', 'at the end; <code>unread</code> decides'],
        ['<code>response.sequence</code>', 'everything, in order', 'as far as read'],
      ], 'compact')}
      ${code(ITEMS, 'Completions and returns')}
      <h3 id="reading-a-response">Reading a response</h3>
      <p>A response is read <b>incrementally</b> as packets arrive, and <b>forward-only</b>: nothing later in it exists on the client until what comes before has been read.</p>
      ${code(RESPONSE, 'Reading a response')}
      ${table(['To', 'Use', 'Unread items'], [
        ['move forward', 'iterate the response, then each result set', 'moving to the next result set <b>discards</b> the current one’s unread rows'],
        ['read everything', '<code>await response.fetch()</code>', '<b>kept</b>: returns a <code>FetchedResponse</code> (below)'],
        ['read to the end', '<code>await response.finish()</code>', 'rows <b>discarded</b>; everything else kept'],
        ['see how it starts', '<code>await response.peek()</code>', 'nothing consumed: the record’s first item, once it has arrived (<code>tds.encryption</code> uses it to see a refusal, D-60)'],
        ['stop', '<code>await response.close()</code> by the owner, or leave the <code>async with</code> block early', `<b>abandoned</b>: the request is canceled, and the driver reads to the server’s acknowledgement (${L('ref/conversations', 'Conversations')} #9)`],
        ['stop it from another task', `<code>response.cancel()</code>, from any task (${D(23)})`, 'sends Attention and returns immediately; the owner’s next read raises <code>Cancelled</code>'],
        ['read large values as they arrive', '<code>result_set.streamed()</code> (below)', 'value by value; moving to the next value <b>discards</b> the unread rest of a large one'],
      ])}
      <h3>Live and fetched responses</h3>
      <p><code>fetch()</code> returns a <code>FetchedResponse</code>: <b>a specialization of the response, backed by memory instead of the stream.</b> It reads exactly as a live response does, so code written for one works on the other, and it adds what memory makes possible:</p>
      ${table(['', 'Live response (backed by the stream)', '<code>FetchedResponse</code> (backed by memory)'], [
        ['Holds the serial channel', 'yes, until it ends', 'no: <code>fetch()</code> freed it'],
        ['<code>returns()</code>', '<code>unread</code> decides', 'always available'],
        ['Read again, or step back', 'no: forward-only', '<b>yes</b>'],
        ['Index directly, for example result set 2, row 10', 'no', '<b>yes</b>'],
      ], 'compact')}
      <p>The extra abilities exist only on the specialization, so code that relies on them says so by the type it asks for.</p>
      <p><b><code>returns()</code> is the one end-of-response item.</b> A call’s returns come just before its DONEPROC, so they can’t be read until the response has been read that far. It gives one entry per call the server completed. The driver offers no single-call shortcut, but an outer layer can offer one (${D(39)}, ${D(40)}). It takes <code>unread</code>, an enumerated type that says what happens to anything not yet read:</p>
      ${table(['<code>Unread.</code>', 'If the item hasn’t arrived yet'], [
        ['<code>REFUSE</code> (default)', 'raise an error that names the options'],
        ['<code>KEEP</code>', 'read ahead, keeping everything, as <code>fetch()</code> does'],
        ['<code>DISCARD</code>', 'read ahead, skipping rows, as <code>finish()</code> does'],
      ], 'compact')}
      <ul>
        <li><b>An open response holds its serial channel</b> (${D(22)}). The channel is free once the response has been read to its end, finished, closed, or canceled and acknowledged.</li>
        <li><b>A result set that the reader has moved past can’t be read again.</b> It still says how many rows arrived. Reading its rows raises an error that points to <code>fetch()</code>.</li>
        <li><b>Completions, messages and errors are collected as they pass</b>, so they’re always readable as far as the response has been read.</li>
        <li><b>Errors are raised at the end of the response</b>, by whichever call reaches it (<code>async for</code>, <code>fetch()</code>, <code>finish()</code> or <code>returns()</code>). The <code>ServerError</code> holds the errors and the whole record as a <code>FetchedResponse</code>: every result set’s columns, completion and row total, with rows wherever they were kept, and every message, error and return, in order. The channel is already free, and the record is the same at every observability level.</li>
        <li><b>Its message is literate</b> (${D(53)}). It gives every field the server sent for each error, in SQL Server’s own form: <code>Msg 8060, Level 16, State 1, Line 1 · server lpdtest1 · an error the user can correct</code>, then the text. The level’s meaning comes from ${L('ref/response', 'Request Response › Severity', 'severity')}. The message also lists the messages that came with the errors, in order, which request was refused and, for several calls, which call. <i>Then</i> says what the server did next: its announcements (such as a rollback) and whether it continued.</li>
        <li><b>A value the driver refuses</b> (${D(48)}) says where it was: <code>the call to shop.update_prices › parameter @changes (shop.pc) › row 2 › column 2 (decimal(10, 2)): …</code>. This applies whether the value was refused before sending, while encoding, or while a source was producing it.</li>
        <li><b>A canceled response raises <code>Cancelled</code></b> in the owner’s next read. The server’s acknowledgement is in the record: a completion marked <i>acknowledges a cancel</i>.</li>
        <li><b>A response dropped while still open raises a <code>ResourceWarning</code></b>, in the same way Python warns about an unclosed file.</li>
      </ul>
      <h3 id="large-values">Large values ${badge('Agreed')} ${D(47)}</h3>
      <p>On the wire, a row is its values in column order, and a large value (the <code>(max)</code> types, <code>xml</code>, <code>text</code>, <code>ntext</code>, <code>image</code>) is chunks of unknown total length. A 1 GB value has to be read, or skipped, before the next column exists. So a result set can be read in two ways, both forward-only:</p>
      ${code(`async for row in result_set:                    # tuples: every value whole, large ones too
    ...

async for row in result_set.streamed():         # value by value, in column order
    async for value in row:
        if isinstance(value, tds.ValueStream):  # a large value, as it arrives
            async for piece in value:           # bytes, or str for text and xml
                sink.write(piece)`, 'Two ways to read a result set')}
      <ul>
        <li><b>Tuples are the common case.</b> They hold large values whole, in memory. An application that wants to limit memory reads with <code>streamed()</code> instead. <code>fetch()</code> and <code>Unread.KEEP</code> also keep them whole.</li>
        <li><b>A <code>ValueStream</code></b> is readable while its row is current, and only once. Moving to the next value discards what is unread.</li>
        <li><b>A result set with large values waits at its first row</b> until the application chooses how to read it: tuples, <code>streamed()</code>, <code>fetch()</code>, or moving to the next result set. Nothing is held whole, or streamed, before the application has said which.</li>
        <li><b>Text is decoded as it arrives,</b> with the column’s collation, and never split inside a character.</li>
        <li><b>Sending works the same way</b> (${D(41)}). A parameter’s value can be whole, or a <b>source</b>: an async iterator whose pieces the driver sends as the iterator produces them, in a <code>Call</code> or in <code>Calls</code>. If the source fails, a chunk doesn’t fit, or the task is canceled while sending, the whole request is abandoned. Nothing runs, the channel is free again, and the original error is raised.</li>
        <li><b>Large values need the ODBC flag,</b> which is on by default (${D(9)}). With <code>odbc=False</code> the server truncates them to 4,096 bytes before sending, and the driver shows what it sent.</li>
      </ul>

      <h3 id="the-serial-channel-s-conveniences">The serial channel’s conveniences ${badge('Agreed')} ${D(37)}</h3>
      <p><i>A layer around the driver, built in M16.</i></p>
      <p>Each is one exchange plus a way of reading its response:</p>
      ${table(['Convenience', 'Sends', 'Returns'], [
        ['<code>exchange(request)</code>', 'any request: the primitive', 'live <code>Response</code>'],
        ['<code>query(sql, **params)</code>', 'SQL', 'live <code>Response</code>'],
        ['<code>fetch(sql, **params)</code>', 'SQL, read to the end', '<code>FetchedResponse</code>'],
        ['<code>fetch_value(sql, **params)</code>', 'SQL, expecting exactly one value', 'the value'],
        ['<code>call(procedure, **params)</code>', 'a stored procedure call', '<code>FetchedResponse</code>, with outputs and return status'],
        ['<code>prepare(sql, **types)</code>', 'a prepare request, once', '<code>PreparedStatement</code>, with the same <code>query</code> / <code>fetch</code> / <code>fetch_value</code>'],
        ['<code>describe(sql)</code>', 'a shape request; nothing runs', 'columns'],
        ['<code>transaction()</code>', 'begin, then commit or roll back', 'async context manager'],
      ], 'compact')}
      <p><b>Shortcuts check their shape.</b> <code>fetch_value</code> refuses anything but exactly one row and one column, and says what came back. <code>FetchedResponse.rows</code> exists only when there was exactly one result set; otherwise it says how many there were.</p>
      <p><b>There are no aliases:</b> one name per behavior.</p>

      <h2 id="5-how-outer-layers-read-a-response">5 · How outer layers read a response ${badge('Agreed')} ${D(42)}</h2>
      <p>The driver delivers the record of what the server did and never interprets it. An outer layer adds meaning, because only it knows what it sent: the SQL text and the calls. This section is the contract between them: what the structure guarantees, and how to answer common questions with it.</p>
      <p><b>What the structure guarantees</b> (${L('ref/response', 'Request Response › Rules', 'rules')}):</p>
      <ul>
        <li><b>Every result set</b> has its columns first and ends with a completion, which carries its count.</li>
        <li><b>Completions arrive in statement order.</b> Each statement produces at most one.</li>
        <li><b>Each DONEPROC ends exactly one outermost procedure call.</b> That call’s return status and outputs come just before it.</li>
        <li><b>The response ends</b> at the completion whose <i>more follows</i> bit is clear.</li>
        <li><b>Messages and errors sit where the server sent them.</b></li>
      </ul>
      ${table(['An outer layer asks', 'It reads', 'The reality to expect'], [
        ['How many rows did my <code>UPDATE</code> change?', 'the statement’s completion: <code>rows</code>', '<code>None</code> under <code>SET NOCOUNT ON</code> or after an error. DB-API’s <code>rowcount = -1</code> means exactly this.'],
        ['Which completion belongs to which of my statements?', '<code>response.completions</code> in order, against the SQL it sent', 'A declaration without an initial value produces none. <code>SET</code> options, <code>PRINT</code> and <code>RAISERROR</code> produce one without a count. Assignments and <code>RETURN</code> count 1. A nested <code>EXEC</code> adds one, with code 224. Only the layer that wrote the SQL can match them. Sending one statement per request makes this simple.'],
        ['Did each of my calls run?', '<code>returns()</code>, against the calls it sent', 'A refused call has an entry with <code>failed</code> set and <code>status</code> <code>None</code>. A call after a batch-ending error has no entry. Fewer entries than calls means the request stopped there, and the <code>ServerError</code> says why.'],
        ['Where are my output values?', '<code>returns()[i].outputs</code>, by ordinal or name', 'They exist only for RPC parameters with <code>output=True</code>. In a SQL batch, outputs go into T-SQL variables, which the SQL must <code>SELECT</code>.'],
        ['Which messages came with which result set?', '<code>response.sequence</code>', 'Messages sit where the server sent them, between result sets or among their rows.'],
        ['Can I trust these rows?', '<code>result_set.completion.status</code>', '<code>ERROR</code>: the statement failed after its columns were sent. <code>SERVER_ERROR</code>: the server asks for the rows to be discarded, and a streaming reader may already have used them.'],
        ['Is a transaction open?', 'the session state, kept current by announcements, and each completion’s <code>IN_TRANSACTION</code> flag', '—'],
        ['Is this an error or a warning?', '<code>Error</code> or <code>Message</code>, with the severity the server reported', `Session settings decide. Division by zero is a message with ANSI_WARNINGS off (the driver’s sessions, ${D(9)}) and an error with it on. <code>RAISERROR</code> at severity 10 arrives as severity 0.`],
      ])}
      <p><b>For example, DB-API.</b> This is one way a DB-API layer could be built on the record, to show that the record is enough. The DB-API layer’s own policies are decided later.</p>
      ${table(['DB-API', 'Built from'], [
        ['<code>cursor.execute(sql, params)</code>', '<code>Call(Builtin.SP_EXECUTESQL, …)</code>, with SQL types inferred by the outer layer'],
        ['<code>cursor.description</code>', 'the current <code>result_set.columns</code>'],
        ['<code>fetchone()</code> · <code>fetchmany()</code> · <code>fetchall()</code>', 'iterating the current result set'],
        ['<code>cursor.nextset()</code>', 'moving to the next result set'],
        ['<code>cursor.rowcount</code>', 'the relevant completion’s <code>rows</code>, or −1 when it’s <code>None</code>'],
        ['<code>cursor.callproc(name, params)</code>', '<code>Call(name, …)</code>, then <code>returns()[0].outputs</code>'],
        ['warnings', '<code>response.messages</code>'],
      ], 'compact')}

      <h2 id="6-what-the-running-client-shows">6 · What the running client shows ${badge('Agreed')} ${D(12)}</h2>
      <p>These tabs show the same login at each level. The <b>full</b> view is generated from the same sample data as the Worked Example’s grid. Open any token to see its fields.</p>
      ${tabs([
        { label: 'full', html: `<div data-tree="login-reply"></div>` },
        { label: 'outline', html: term_out(OUTLINE) },
        { label: 'off (optimized)', html: term_out('connect sales-db:1433 · ready in 39 ms') },
      ])}
      <p><b>How it works</b> (${D(12)}):</p>
      <ul>
        <li><b>The observer says how much it wants.</b> <code>connect(observe=Printer(Level.FULL))</code>, or any callable with a <code>level</code>; a plain callable counts as full, and none is off. Off builds no events and no inspection trees: the optimized mode. Outline builds one line per step, message and change. Full also keeps every message’s tree.</li>
        <li><b>It can change between exchanges:</b> <code>connection.observe = Printer(Level.FULL)</code> starts observing a pooled connection that is already open. During an exchange the change is refused, because a request described at one level must have its response read at the same level.</li>
        <li><b>Every byte is reachable:</b> <code>event.node.find("login reply", "LOGINACK", "tds version")</code>. Each structure in the full view names the reference page that explains it. Large values are summarized (${D(47)}).</li>
        <li><b>Timing:</b> each connect step shows its time since connecting began (<code>● hello · at 24 ms</code>). Each response shows the time from sending to its first packet (roughly, how long the server took before answering) and to its end (<code>← response · … · first packet 12 ms · done 40 ms</code>). The durations are shown at the end of the line, separate from its text. A capture records them. A capture’s first line records the wall-clock start. <code>response.timing</code> gives applications the same (<code>sent</code>, <code>first_packet</code>, <code>ended</code>, <code>until_first_packet</code>, <code>until_end</code>). It is collected at every level.</li>
        <li><b>Captures and replay:</b> <code>capture=Capture("session.jsonl")</code>, or <code>connection.capture</code> between exchanges, records every event’s line and every plaintext packet, with times. <code>replay("session.jsonl", Printer(Level.FULL))</code> decodes the packets with the same definitions and shows the identical view. The login’s password is zeroed unless <code>keep_password=True</code>. Query text and data stay. Saved table inputs retain their declaration, default columns, ordering hints, placement and exact rows. Rust’s <code>--replay</code> CLI reads the same physical recordings offline; see <a href="#/offline-replay">Offline Rust Replay</a>.</li>
        <li><b>The password stays hidden at full</b> unless an observer reveals it for the sessions it watches: <code>Printer(…, reveal_password=True)</code>.</li>
        <li><b>Diagnostic output failure:</b> a failed optional observer is disabled; database work and recording continue. Its exception is available separately as <code>connection.observation_error</code>, cleared when an observer is installed. Pool callbacks follow the same policy (<code>pool.observation_error</code>). The current decoding mode stays unchanged until explicitly reconfigured. Saved-recording failure raises <code>tds.CaptureError</code> with its writer <code>cause</code>, closes the connection and wakes waiters. Each line is flushed to expose buffered write failures; disk durability is not guaranteed. Recovery cannot resume an incomplete recording. Sent SQL may have executed; closing does not prove rollback.</li>
      </ul>
      <p><b>Recording ownership:</b> each recording belongs permanently to one physical connection. <code>Capture</code> refuses attachment to another physical lifetime, even after detachment/close. Pools require <code>capture_factory</code>, a callable returning a new Capture with a distinct output per opened connection; loans of the same transport keep its recording. Connect also supports the factory for separate files on routing/recovery; a direct capture refuses those transitions. The application owns/closes Python capture resources. Rust moves one non-Clone Capture into each driver and uses the same factory rule (<a href="#/rust">Rust plan</a>).</p>
      <p><b>Still to design</b> (carried over from the earlier draft):</p>
      <ul>
        <li>views: annotated hex (like the grids here), JSON;</li>
        <li>TLS key-log export, so Wireshark can cross-check the decoding;</li>
        <li>partial decoding that shows exactly where a malformed message broke;</li>
        <li>linking errors and announcements to the exchange that caused them.</li>
      </ul>`,
  });
})();
