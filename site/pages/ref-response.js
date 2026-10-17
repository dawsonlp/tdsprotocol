/* Reference: Request Response. A view of docs/design/3-reference/response.md (the record, D-29). */
(function () {
  const { T, L, D, table, code, source } = window.TDS;

  const SHAPE = `DECLARE @t …; INSERT 3 rows; SELECT; EXEC p; SELECT 9

  DONE        count 3                               the INSERT (DECLARE sends nothing)
  COLMETADATA  ROW ROW ROW  DONE count 3            the SELECT, with its result set
  DONEINPROC … DONEINPROC  RETURNSTATUS  DONEPROC   the statements inside p, then p's end
  COLMETADATA  ROW  DONE count 1 (final)            the last SELECT, and the end of the response`;

  const COUNTS = `DECLARE @t TABLE (i int); INSERT @t VALUES (1),(2),(3); UPDATE @t SET i = i + 1 WHERE i > 1; SELECT i FROM @t; DELETE @t

  DONE         more · count   3   code 195     INSERT
  DONE         more · count   2   code 197     UPDATE
  COLMETADATA  i int
  ROW          1
  ROW          3
  ROW          4
  DONE         more · count   3   code 193     SELECT
  DONE         count          3   code 196     DELETE, and the end of the response`;

  const ERRORS = `SET ANSI_WARNINGS ON; SELECT 1; SELECT 1 / 0; SELECT 2        SELECT 1; SELECT CAST(N'x' AS int); SELECT 2

  DONE         more              code 185                     COLMETADATA  ROW  DONE more · count 1
  COLMETADATA  ROW  DONE more · count 1                       COLMETADATA  b
  COLMETADATA  b                                              ERROR        245 Conversion failed …
  ERROR        8134 Divide by zero error encountered.         DONE         error · final
  DONE         more · error                                     (SELECT 2 never runs)
  COLMETADATA  ROW  DONE count 1`;

  const CALLS = `#bump(@a = 41, by reference)  then  #outer(@o = NULL, by reference), which runs EXEC #bump inside

  COLMETADATA  seen_on_entry        ROW  41                   #bump sees the value sent
  DONEINPROC   ×3
  RETURNSTATUS 7
  RETURNVALUE  ordinal 0 · @a · output · 42
  DONEPROC     more                                           the first call ends
  DONEINPROC   …                    DONEINPROC code 224       the nested #bump ends: no status, no outputs
  COLMETADATA  step                 ROW  outer done
  DONEINPROC   ×2
  RETURNSTATUS 3
  RETURNVALUE  ordinal 0 · @o · output · 101
  DONEPROC     final                                          the second call, and the response, end`;

  window.TDS.page({
    id: 'ref/response', group: 'Reference', kind: 'reference',
    title: 'Request Response',
    where: `message › <b>body</b>, a ${T('token stream')} › ${T('token')}. What the server sends back for a SQL batch or an RPC.`,
    outcome: 'find where each statement, result set and procedure call begins and ends in a response, and what every token in it means.',
    body: () => `
      <h2>Purpose</h2>
      <p>A response is one token stream, and it is flat: no token encloses another. Certain tokens mark its structure by their position. Four structures matter, and each one has a mark. Messages, errors and ${T('announcement', 'announcements')} appear where they happened.</p>

      <h2>Shape</h2>
      ${table(['Structure', 'Starts', 'Ends'], [
        ['<b>response</b>', 'at its first token', 'at the completion whose <i>more follows</i> bit is clear'],
        ['<b>statement</b>', 'after the previous completion', `at a <b>${T('completion')}</b>: DONE in a batch, DONEINPROC inside a procedure`],
        [`<b>${T('result set')}</b>`, 'at COLMETADATA', 'at the next completion, which carries its count'],
        ['<b>procedure call</b>, outermost only', 'after the previous call ended', 'at RETURNSTATUS, then a RETURNVALUE for each output, then DONEPROC'],
      ])}
      <p>A <i>completion</i> is any of the three DONE tokens.</p>
      ${code(SHAPE, 'Where the marks fall')}

      <h3>The tokens</h3>
      ${table(['Tag', 'Token', 'Means', 'Fields'], [
        ['<code>81</code>', 'COLMETADATA', 'a result set begins: its columns', `count, then each column: user type, flags, type, name. A count of <code>FFFF</code> means no columns follow, because the call asked for no metadata. Once column encryption is agreed, a key table follows the count, and an encrypted column has crypto metadata before its name (${L('ref/always-encrypted', 'Always Encrypted')}).`],
        ['<code>A9</code>', 'ORDER', 'the result set is sorted on these columns', 'column numbers'],
        ['<code>D1</code>', 'ROW', 'one row', 'each column’s value, laid out as COLMETADATA says'],
        ['<code>D2</code>', 'NBCROW', 'one row, with its NULLs in a bitmap', 'a null bitmap, then the non-null values'],
        ['<code>AB</code>', 'INFO', 'a message: <code>PRINT</code>, a low-severity <code>RAISERROR</code>, a warning', 'number, state, severity, text, server, procedure, line'],
        ['<code>AA</code>', 'ERROR', 'a statement failed', 'the same fields as INFO'],
        ['<code>E3</code>', 'ENVCHANGE', 'a session setting changed', `kind, new value, old value (${L('ref/login-response', 'Login Response')})`],
        ['<code>A4</code>', 'TABNAME', 'the base tables of the result set’s columns (browse mode, server cursors)', 'each table’s name, in parts'],
        ['<code>A5</code>', 'COLINFO', 'where each column came from', 'each column: its number, its table in TABNAME (0 for an expression), status (<code>04</code> expression · <code>08</code> key · <code>10</code> hidden · <code>20</code> different name), and the base column’s name when it differs'],
        ['<code>A3</code>', 'DATACLASSIFICATION', 'the result set’s data classification, when the login asked for it', 'sensitivity labels and information types (name, id), then each column’s sensitivities; ranks from version 2'],
        ['<code>88</code> <code>D3</code>', 'ALTMETADATA, ALTROW', '<code>COMPUTE</code> totals and their rows', 'deprecated in TDS 7.4; SQL Server no longer sends them'],
        ['<code>E4</code>', 'SESSIONSTATE', 'the session’s state, for recovering it, when the login asked for session recovery', 'sequence number, recoverable, then each state’s id and value'],
        ['<code>79</code>', 'RETURNSTATUS', 'the procedure’s <code>RETURN</code> value', 'i32'],
        ['<code>AC</code>', 'RETURNVALUE', 'an output parameter’s value, or a function’s result', `ordinal, name, status (<code>01</code> output · <code>02</code> function result), user type, flags, type, [crypto metadata, when encrypted: ${L('ref/always-encrypted', 'Always Encrypted')}], value`],
        ['<code>FD</code>', 'DONE', 'a statement in a batch ended', 'status, statement code, row count'],
        ['<code>FF</code>', 'DONEINPROC', 'a statement inside a procedure ended', 'the same'],
        ['<code>FE</code>', 'DONEPROC', 'an outermost procedure call ended', 'the same'],
      ], 'compact')}

      <h3>Completion fields</h3>
      ${table(['Field', 'Size', 'Meaning'], [
        ['status', 'u16', 'bits: <code>01</code> more follows · <code>02</code> error · <code>04</code> in a transaction · <code>10</code> count is valid · <code>20</code> acknowledges a cancel · <code>80</code> one of several calls (on every DONEPROC but the last) · <code>100</code> server error: discard this result set'],
        ['statement code', 'u16', 'the kind of statement, as a number the server chooses. MS-TDS leaves the values to the server.'],
        ['row count', 'u64', 'rows affected or returned; meaningful only when <i>count is valid</i> is set'],
      ], 'compact')}
      <h3 id="transaction-announcements">Transaction announcements</h3>
      <p>ENVCHANGE kinds that come in responses. Each value is bytes with a u8 length; the descriptor is 8 bytes.</p>
      ${table(['Kind', 'Announces', 'New value', 'Old value'], [
        ['8', 'a transaction began', 'its descriptor', 'empty'],
        ['9', 'the transaction committed', 'empty', 'its descriptor'],
        ['10', 'the transaction rolled back', 'empty', 'its descriptor'],
        ['11', 'enlisted in a distributed transaction', 'empty', 'the descriptor (per MS-TDS; not observed)'],
        ['12', 'defected from a distributed transaction', 'the descriptor', 'empty (per MS-TDS; not observed)'],
        ['15', 'the transaction was promoted', 'the coordinator’s token: bytes with a <b>u32</b> length', 'empty'],
        ['16', 'the coordinator’s address', 'MS-TDS says it isn’t used', ''],
        ['17', 'the transaction ended', 'empty', 'the descriptor (per MS-TDS; not observed)'],
        ['18', `the session was reset (${L('ref/packet', 'Packet')})`, 'empty', 'empty'],
      ], 'compact')}
      <p><b>The driver keeps the session’s descriptor from the new value:</b> a non-empty value is the descriptor, and an empty value means no transaction. Every request carries it in its headers (${L('ref/requests', 'Requests', 'shape')}). Only the outermost transaction is announced.</p>

      <h3 id="severity">Severity</h3>
      <p>An INFO or ERROR’s severity (MS-TDS calls it <i>class</i>) says what kind of problem it is. MS-TDS leaves the meanings to the server; Microsoft’s “Database Engine error severities” gives them. A <code>ServerError</code> shows the severity’s meaning after its level (${D(53)}).</p>
      ${table(['Level', 'Means'], [
        ['0–10', 'information. The server sends 10 as 0.'],
        ['11–16', 'errors the user can correct: 11 an object doesn’t exist · 12 a query that takes no locks may have read inconsistent data · 13 a deadlock · 14 security, such as permission denied · 15 syntax · 16 general'],
        ['17–19', 'for the administrator: 17 out of resources, or a limit the administrator set · 18 a problem in the server’s software; the statement completed · 19 a server limit was exceeded; the batch stopped'],
        ['20–24', 'fatal: the task running the statement ends, and in most cases the connection may end too · 20 a problem with the statement · 21 a problem affecting the whole database · 22 a damaged table or index · 23 the database’s integrity is in doubt · 24 a media failure'],
        ['25', 'fatal; <code>RAISERROR</code> can raise it'],
      ], 'compact')}

      <h2>Rules</h2>
      <ul>
        <li><b>Every statement ends with a completion, except a declaration without an initial value.</b> <code>SET</code> options, <code>PRINT</code> and <code>RAISERROR</code> end with one that carries no count.</li>
        <li><b>A count is valid only when its bit says so.</b> Under <code>SET NOCOUNT ON</code> the completions still arrive, with the bit clear. No count is not the same as a count of 0.</li>
        <li><b>A result set’s count comes after its rows,</b> in the completion that closes it. An empty result set still sends its columns and a count of 0.</li>
        <li><b>Only the outermost procedure call ends with DONEPROC,</b> preceded by its RETURNSTATUS and RETURNVALUEs.
          <ul>
            <li>A procedure it runs ends with a DONEINPROC (statement code 224, no count) and sends no return status or outputs of its own.</li>
            <li>This is the same whether the call came by RPC or as <code>EXEC</code> in a SQL batch.</li>
          </ul></li>
        <li><b>Outputs come back only for parameters passed by reference,</b> one RETURNVALUE each.
          <ul>
            <li>The ordinal is the parameter’s position in the call, from 0. It counts every parameter, including <code>sp_executesql</code>’s <code>@stmt</code> and <code>@params</code>.</li>
            <li>Large-object outputs come after all the others.</li>
            <li>In a SQL batch, output parameters are assigned to T-SQL variables, and no RETURNVALUE is sent.</li>
          </ul></li>
        <li><b>An error appears where it happened,</b> followed by a completion marked <i>error</i>.
          <ul>
            <li>Whether later statements run depends on the error: some end only their statement, others end the whole batch.</li>
            <li><i>Server error</i> asks the client to discard that result set’s rows.</li>
          </ul></li>
        <li><b>In a request with several calls,</b> a call can fail in two ways:
          <ul>
            <li>A call the server refuses before running it ends with DONEPROC marked <i>error</i> · <i>more follows</i>, and the next call runs.</li>
            <li>An error that ends the batch ends the whole request: DONEPROC marked <i>error</i> · <i>final</i>. Later calls don’t run and send nothing.</li>
          </ul></li>
        <li><b>A function called as an RPC</b> sends exactly one RETURNVALUE, marked <i>function result</i>, unnamed, at ordinal 0, and no RETURNSTATUS.</li>
        <li><b>A cancel is acknowledged</b> by a completion with <i>acknowledges a cancel</i> set (${L('ref/conversations', 'Conversations')} #9).</li>
      </ul>

      <h2>Example</h2>
      <p>Responses observed from SQL Server 2025 (17.0.5015.4). One line per token.</p>
      ${code(COUNTS, 'Counts, with and without a result set')}
      ${code(ERRORS, 'Errors: one statement fails, then one batch ends')}
      ${code(CALLS, 'Two calls in one RPC request, with an output')}

      <h2>Edge cases</h2>
      <p><b>Where SQL Server differs from MS-TDS.</b> Observed from SQL Server 2025 (17.0.5015).</p>
      <ul><li><b>A <i>promote</i> announcement’s length covers only its kind:</b> the length is 1, and the token and the empty old value follow outside it (${L('ref/token-stream', 'Token Stream › Edge cases', 'edge-cases')}).</li></ul>
      <p><b>What MS-TDS doesn’t state.</b> Observed from SQL Server 2025 (17.0.5015).</p>
      <ul>
        <li><b>Browse mode adds columns the query didn’t ask for.</b> <code>FOR BROWSE</code> appends each table’s key and <code>rowversion</code> columns to the result set, and COLINFO marks them <i>hidden</i>. The rows carry them too.</li>
        <li><b>Browse mode’s tokens come with more than <code>FOR BROWSE</code>:</b> under <code>SET NO_BROWSETABLE ON</code> (which OLE DB clients use), on an ordinary <code>SELECT</code>; and from every kind of server cursor (<code>sp_cursoropen</code>). Before M11, each of these ended the connection.</li>
        <li><b>Assignments count one row:</b> <code>DECLARE @x int = 41</code>, <code>SET @x = …</code>, and <code>RETURN</code> inside a procedure each end with a completion carrying count 1 (code 193).</li>
        <li><b><code>RAISERROR</code> at severity 10</b> arrives as INFO with severity 0.</li>
        <li><b>ORDER is sent only when the server sorts.</b> <code>ORDER BY</code> over a single constant row sends none.</li>
        <li><b>Session settings change what is an error.</b> A session logged in without the ODBC flag (<code>odbc=False</code>; the driver’s default is on, ${D(9)}) starts with every ANSI option off, ANSI_WARNINGS among them (${L('ref/types', 'Data Types › Edge cases', 'edge-cases')}). With ANSI_WARNINGS off, division by zero returns NULL plus INFO 3607, and nothing fails. With it on (as the ODBC flag sets it), it is ERROR 8134, and that statement fails.</li>
        <li><b>A parameter passed by reference to a parameter not declared <code>OUTPUT</code></b> is refused with ERROR 8162 before the call runs. A parameter declared <code>OUTPUT</code> but passed by value is accepted, and its output isn’t returned.</li>
        <li><b>Statement codes seen:</b> 193 <code>SELECT</code> · 195 <code>INSERT</code> · 196 <code>DELETE</code> · 197 <code>UPDATE</code> · 185 <code>SET … ON</code> · 186 <code>SET … OFF</code> · 222 <code>CREATE PROCEDURE</code> · 224 <code>EXEC</code> · 246 <code>RAISERROR</code> · 247 <code>PRINT</code> · 253 an empty batch.</li>
      </ul>

      ${source('§2.2.1.6, §2.2.2.4–§2.2.2.9, §2.2.4.3, §2.2.6.6, §2.2.7.1–§2.2.7.9, §2.2.7.15, §2.2.7.17–§2.2.7.21, §2.2.7.23')}`,
  });
})();
