/* Reference: Requests. A view of docs/design/3-reference/requests.md (the record, D-29). */
(function () {
  const { T, L, D, table, source } = window.TDS;

  window.TDS.page({
    id: 'ref/requests', group: 'Reference', kind: 'reference',
    title: 'Requests',
    where: `message › <b>body</b>, a ${T('structure')} › ${T('field')}. The client’s half of an ${T('exchange')}: what the client asks the server.`,
    outcome: 'read or build any request the driver sends: the headers every request carries, then the request itself.',
    body: () => `
      <h2>Purpose</h2>
      <p>Every request is one message on a ${T('serial channel')}, and the server answers it with one ${L('ref/response', 'response')}. The driver’s requests are the protocol’s own (${D(39)}):</p>
      ${table(['Request', 'Packet type', 'Here'], [
        ['<b>SQL batch</b>: T-SQL text', '<code>01</code>', 'below'],
        ['<b>RPC</b>: procedure calls with typed parameters', '<code>03</code>', 'below'],
        ['<b>Bulk load</b>: rows into a table, as a stream', '<code>01</code>, then <code>07</code>', 'below; not built yet'],
        ['<b>Transaction manager</b>: begin, commit, roll back, savepoints, distributed transactions', '<code>0E</code>', 'below; not built yet'],
      ], 'compact')}
      <p>Cancel isn’t a request. It is a header-only packet of type <code>06</code> that ends the exchange in progress (${L('ref/conversations', 'Conversations')} #9).</p>

      <h2>Shape</h2>
      <p><b>Headers.</b> SQL batches, RPCs and transaction-manager requests begin with them.</p>
      ${table(['Field', 'Size', 'Meaning'], [
        ['total length', 'u32', 'the length of all the headers, this field included'],
        ['<i>then each header:</i>', '', ''],
        ['length', 'u32', 'this header’s length, this field included'],
        ['type', 'u16', '<code>0001</code> query notifications · <code>0002</code> transaction descriptor · <code>0003</code> trace activity'],
        ['data', 'as the type says', ''],
      ], 'compact')}
      <p><b>The transaction descriptor header</b> (type <code>0002</code>) is required, and is the only one the driver sends:</p>
      ${table(['Field', 'Size', 'Meaning'], [
        ['transaction', 'u64', 'the descriptor from the latest <i>begin transaction</i> announcement; 0 when none is open'],
        ['outstanding requests', 'u32', '1 in autocommit; otherwise requests active on the connection, this one included (more than 1 only under MARS)'],
      ], 'compact')}
      <p><b>SQL batch</b> (packet type <code>01</code>):</p>
      ${table(['Field', 'Size', 'Meaning'], [
        ['headers', 'as above', ''],
        ['enclave package', 'u16 length, then bytes', `always present once Always Encrypted’s enclaves are agreed; empty when there’s nothing to send (${L('ref/always-encrypted', 'Always Encrypted')})`],
        ['text', 'to the end of the message', 'the T-SQL, as UTF-16LE. It has no length field. It runs to the end of the message, across as many packets as it needs.'],
      ], 'compact')}

      <p><b>RPC</b> (packet type <code>03</code>): the headers, then one or more calls separated by a BATCH marker, <code>FF</code>.</p>
      ${table(['Field', 'Size', 'Meaning'], [
        ['procedure', 'name: u16 length, then UTF-16LE · or <code>FF FF</code> and a u16 built-in number', 'which procedure to call'],
        ['options', 'u16', '<code>01</code> recompile · <code>02</code> no metadata · <code>04</code> reuse metadata'],
        ['enclave package', 'u16 length, then bytes', `always present once Always Encrypted’s enclaves are agreed; empty when there’s nothing to send (${L('ref/always-encrypted', 'Always Encrypted')})`],
        ['<i>then each parameter:</i>', '', ''],
        ['name', 'u8 length, then UTF-16LE', '<code>@name</code>, or empty for positional'],
        ['status', 'u8', `<code>01</code> by reference: an output parameter · <code>02</code> default value · <code>08</code> encrypted (${L('ref/always-encrypted', 'Always Encrypted')})`],
        ['type', `TYPE_INFO (${L('ref/types', 'Data Types')})`, 'the parameter’s declared type'],
        ['value', 'as the type says', `NULL when the status asks for the default. A large value is PLP. A whole value is sent with its total length. A value from a source is sent with its length <i>not known yet</i>, in chunks as the source produces them (${L('ref/types', 'Data Types')}, ${D(41)}). A table is sent as its columns, then its rows, whole or as a source produces them (${D(49)})`],
        ['cipher info', 'when encrypted', `what the ciphertext holds, and with which column key (${L('ref/always-encrypted', 'Always Encrypted')})`],
      ], 'compact')}
      <p><b>Bulk load</b> is two messages, each its own exchange:</p>
      <ol>
        <li><b>A SQL batch:</b> <code>INSERT BULK table (column type, …) [WITH (options)]</code>. It names the columns the rows will fill, and the server answers with a DONE. The options are <code>CHECK_CONSTRAINTS</code>, <code>FIRE_TRIGGERS</code>, <code>KEEP_NULLS</code>, <code>TABLOCK</code>, <code>ORDER (column, …)</code>, <code>ROWS_PER_BATCH = n</code> and <code>KILOBYTES_PER_BATCH = n</code>.</li>
        <li><b>The bulk data</b> (packet type <code>07</code>). It has <b>no headers</b>:</li>
      </ol>
      ${table(['Field', 'Meaning'], [
        ['COLMETADATA', `the columns, laid out as in a ${L('ref/response', 'response')}, with a key table once column encryption is agreed, and an encrypted column’s crypto metadata (${L('ref/always-encrypted', 'Always Encrypted')}). The statement names an encrypted column by its ciphertext’s type. The columns must match the statement’s columns exactly (Edge cases).`],
        ['ROW, repeated', 'one row each, laid out as in a response'],
        ['DONE', 'the end; its count is ignored'],
      ], 'compact')}
      <p>The server answers with one DONE carrying the number of rows loaded. Some column types are sent as other types: <code>xml</code>, <code>json</code>, <code>text</code>, <code>ntext</code>, <code>image</code> and CLR types (Edge cases).</p>
      <p><b>Transaction-manager request</b> (packet type <code>0E</code>): the headers, a request type (u16), then the payload.</p>
      ${table(['Type', 'Request', 'Payload', 'The server answers with'], [
        ['0', 'the coordinator’s address', 'empty bytes with a u16 length: <code>00 00</code>', 'one row with one binary column'],
        ['1', 'propagate: join a distributed transaction', 'the coordinator’s cookie, as bytes with a u16 length', 'per MS-TDS, a result set holding the new descriptor. Not observed, because it needs a cookie from a coordinator'],
        ['5', 'begin', 'isolation (u8), then a name', 'a <i>begin</i> announcement, for the outermost transaction only'],
        ['6', 'promote to a distributed transaction', 'none', 'a <i>promote</i> announcement carrying the coordinator’s token'],
        ['7', 'commit', 'a name, flags (u8: <code>01</code> begin another), then, when beginning another, its isolation and name', 'a <i>commit</i> announcement for the outermost transaction; then <i>begin</i>, if asked'],
        ['8', 'roll back', 'as commit. A savepoint’s name rolls back to the savepoint.', 'a <i>rollback</i> announcement, unless only to a savepoint; then <i>begin</i>, if asked'],
        ['9', 'savepoint', 'a name, which must not be empty', 'nothing'],
      ], 'compact')}
      <p><b>A name</b> is a u8 byte count, then the name as UTF-16LE. <b>Isolation:</b> <code>00</code> unchanged · <code>01</code> read uncommitted · <code>02</code> read committed · <code>03</code> repeatable read · <code>04</code> serializable · <code>05</code> snapshot. An isolation level given with <i>begin another</i> stays for the session after that transaction ends. The announcements are on ${L('ref/response', 'Request Response', 'transaction-announcements')}.</p>
      <p><b>Built-in procedures</b>, called by number: 1–9 the cursor procedures (<code>sp_cursor</code> … <code>sp_cursorclose</code>) · 10 <code>sp_executesql</code> · 11 <code>sp_prepare</code> · 12 <code>sp_execute</code> · 13 <code>sp_prepexec</code> · 14 <code>sp_prepexecrpc</code> · 15 <code>sp_unprepare</code>.</p>

      <h2>Rules</h2>
      <ul>
        <li><b>Headers come once, at the start of the message,</b> not in every packet.</li>
        <li><b>The transaction descriptor follows the session.</b> The client takes it from the server’s announcements (ENVCHANGE begin, commit and roll back), never from its own guess at what the SQL did.</li>
        <li><b>A request’s packets carry the reset flag</b> on the first packet when the connection was returned to a pool since its last request (${L('ref/packet', 'Packet')}, ${D(36)}).</li>
        <li><b>The text runs to the end of the message.</b> A batch larger than one packet is split across packets. The last packet is marked <i>last</i>.</li>
        <li><b>An output parameter is sent by reference with a value.</b> The procedure sees the value sent, NULL included. TDS has no output-only parameter (${D(40)}).</li>
        <li><b>Several calls in one RPC are separated by BATCH (<code>FF</code>).</b> MS-TDS also defines NO-EXEC (<code>FE</code>), which skips the call before it. The driver never sends it (${D(40)}).</li>
        <li><b>The driver checks each value against its declared type before sending</b> (${D(48)}). A value that doesn’t fit is refused, and nothing is sent.</li>
        <li><b>A request from a source is sent while the source produces it.</b> Each chunk, or each row of a table, is checked when it is encoded.</li>
        <li><b>A request that fails or is canceled partway is undone</b> (${D(41)}):
          <ul>
            <li><b>nothing sent yet:</b> nothing to undo;</li>
            <li><b>part of it sent:</b> the next packet carries <i>ignore</i> + <i>last</i>, and the server runs nothing and answers with a DONE marked <i>error</i> (after a message of its own; see Edge cases);</li>
            <li><b>all of it sent:</b> Attention cancels it.</li>
          </ul>
          In each case the driver reads the server’s answer, so that the channel is free. Then it raises the original error.</li>
      </ul>

      <h2>Example</h2>
      <p><code>SELECT 1</code> as a SQL batch, outside a transaction, with one request outstanding:</p>
      ${table(['At', 'Bytes', 'Field', 'Value'], [
        ['00', '<code>01 01 00 2E 00 00 01 00</code>', 'packet header', 'SQL batch · last · 46 bytes'],
        ['08', '<code>16 00 00 00</code>', 'total length', '22'],
        ['0C', '<code>12 00 00 00</code>', 'length', '18'],
        ['10', '<code>02 00</code>', 'type', 'transaction descriptor'],
        ['12', '<code>00 00 00 00 00 00 00 00</code>', 'transaction', '0: none'],
        ['1A', '<code>01 00 00 00</code>', 'outstanding requests', '1'],
        ['1E', '<code>53 00 45 00 4C 00 45 00 43 00 54 00 20 00 31 00</code>', 'text', '<code>SELECT 1</code>'],
      ], 'compact')}

      <p><b>A call:</b> <code>#bump</code> with one output parameter, <code>@a = 41</code>:</p>
      ${table(['Bytes', 'Field', 'Value'], [
        ['<code>03 01 00 39 00 00 01 00</code>', 'packet header', 'RPC · last · 57 bytes'],
        ['<code>16 00 00 00</code> … <code>01 00 00 00</code>', 'headers', 'as above'],
        ['<code>05 00 23 00 62 00 75 00 6D 00 70 00</code>', 'procedure', '5 code units: <code>#bump</code>'],
        ['<code>00 00</code>', 'options', 'none'],
        ['<code>02 40 00 61 00</code>', 'name', '<code>@a</code>'],
        ['<code>01</code>', 'status', 'by reference: an output parameter'],
        ['<code>26 04</code>', 'type', '<code>int</code>, 4 bytes'],
        ['<code>04 29 00 00 00</code>', 'value', '41'],
      ], 'compact')}

      <h2>Edge cases</h2>
      <ul>
        <li><b>Query notifications and trace activity headers</b> are optional, and the driver doesn’t send them. Query notifications ask the server to report when a query’s results change. Trace activity carries a correlation id.</li>
      </ul>
      <p><b>Where SQL Server differs from MS-TDS.</b> Observed from SQL Server 2025 (17.0.5015).</p>
      <ul>
        <li><b>The answer to <i>ignore</i> + <i>last</i> has a message before its DONE.</b> MS-TDS says the server answers with a DONE marked <i>error</i>. SQL Server sends that DONE after a message: for a call abandoned partway, error 4002 (severity 16, “The incoming tabular data stream (TDS) protocol stream is incorrect. The stream ended unexpectedly.”); for bulk rows, message 3621 (“The statement has been terminated.”). The driver reads this as the answer to the undo. The application gets the error that caused the undo. <i>Corrected 2026-10-16:</i> this page said a lone DONE, based on a test that matched a different response.</li>
        <li><b>A table’s default needs the default status bit,</b> which MS-TDS says must be zero for a table (${L('ref/types', 'Data Types › Edge cases', 'edge-cases')}).</li>
        <li><b>A large value in bulk data with a known length is the length, then the bytes:</b> no chunks, and no chunk of length 0 at the end. MS-TDS defines a known-length PLP value with chunks, and says the bulk data is laid out as the server would send the same rows. The server does send chunks, and refuses them in bulk data (error 4804). The unknown-length form, with chunks, is accepted as MS-TDS defines it.</li>
        <li><b>Promoting a transaction begun in T-SQL works.</b> MS-TDS says promote is supported only for transactions begun by a transaction-manager request, and that the server returns an error otherwise. SQL Server promotes it and returns a token, as for any other transaction.</li>
        <li><b>The coordinator’s address comes as one row,</b> as MS-TDS’s description of the request says. Its description of the announcements says a <i>transaction manager address</i> announcement answers this request, and its table of announcements says that kind isn’t used. None is sent.</li>
        <li><b>MS-TDS’s sample transaction-manager request</b> is labeled <i>promote</i>, but its request type is <code>16 00</code>, which is 22. Promote is 6.</li>
      </ul>
      <p><b>What MS-TDS doesn’t state.</b> Observed from SQL Server 2025 (17.0.5015).</p>
      <ul>
        <li><b>An empty batch</b> (or one holding only spaces or a comment) is still a request. The server answers with one final DONE, no count, statement code 253.</li>
        <li><b>A declared <code>varchar</code> parameter is in the database’s default collation,</b> whatever collation the value arrives in. This applies to <code>sp_executesql</code>’s declarations and to procedure parameters alike. The server converts the value when it arrives, and chooses a similar-looking character where it can: Greek α arrived as <code>a</code>, with no error. Therefore a value from a <code>varchar</code> column in another collation is sent back unchanged only through a parameter declared <code>nvarchar</code>. Even then, sequences the server itself writes back differently, such as duplicate encodings or default characters, can’t pass through any text parameter (${L('ref/types', 'Data Types', 'edge-cases')}).</li>
        <li><b><code>sp_execute</code> called by number refuses a named handle</b> with error 4002, “the TDS stream is incorrect”. It accepts the handle positional, or a name when called by name. <code>sp_prepare</code>, <code>sp_prepexec</code> and <code>sp_executesql</code> accept named parameters by number.</li>
        <li><b>The <i>no metadata</i> option is ignored:</b> for <code>sp_executesql</code> and <code>sp_execute</code> alike, the server still sends the columns. The driver reads either.</li>
        <li><b>Bulk load’s two messages must be adjacent, on the same channel:</b>
          <ul>
            <li>bulk data without a successful <code>INSERT BULK</code> just before it gets a DONE marked <i>error</i>, and then <b>the server closes the connection</b>;</li>
            <li>another request between them fails with error 4022, “bulk load data was expected but not sent”, and ends the bulk load. Bulk data after that closes the connection as above.</li>
          </ul></li>
        <li><b>The bulk data’s columns must match the statement’s exactly, by position:</b>
          <ul>
            <li>a different type is refused (error 4815, <i>invalid column length</i>), for example <code>bigint</code> data for an <code>int</code> column;</li>
            <li>so is the wrong code for the column’s nullability (error 4816, <i>invalid column type</i>): a <code>NOT NULL</code> column needs the fixed-size code, as the server would send it;</li>
            <li>every column the statement names must be sent (error 4804);</li>
            <li>names are ignored, but an empty name is refused (error 4804).</li>
          </ul></li>
        <li><b>Some columns load as another type:</b>
          ${table(['Column', 'The data’s type', 'The statement declares'], [
            ['<code>xml</code>', '<code>nvarchar(max)</code>, as MS-TDS says', 'either'],
            ['CLR types', '<code>varbinary(max)</code>, as MS-TDS says', 'either'],
            ['<code>text</code>, <code>ntext</code>, <code>image</code>', '<code>varchar(max)</code>, <code>nvarchar(max)</code>, <code>varbinary(max)</code>', 'the <code>(max)</code> type: declaring the column’s own type is refused (error 4816)'],
            ['<code>json</code>', '<code>nvarchar(max)</code>', '<code>nvarchar(max)</code>: declaring <code>json</code> is refused (error 4816)'],
          ], 'compact')}
          Data in the column’s own type is refused (error 4816; error 4804 for <code>text</code> with a text pointer). <code>sql_variant</code> and <code>vector</code> load as themselves.</li>
        <li><b>The options, as observed:</b>
          <ul>
            <li>without <code>CHECK_CONSTRAINTS</code>, constraints aren’t checked, and the server marks them <i>not trusted</i>; with it, a violation fails the load (error 547);</li>
            <li>without <code>KEEP_NULLS</code>, a NULL takes the column’s default;</li>
            <li>triggers fire only with <code>FIRE_TRIGGERS</code>, once per load;</li>
            <li><code>ORDER</code> is checked: rows out of order fail the load (error 4819).</li>
          </ul></li>
        <li><b>Identity values in bulk data are kept,</b> and the identity continues from them, without <code>IDENTITY_INSERT</code>.</li>
        <li><b>A bulk load runs as one statement:</b> a failed <code>CHECK</code> constraint loads no rows, and a bulk load inside a transaction rolls back with it.</li>
        <li><b>Transaction names are UTF-16LE.</b> An odd byte count is refused (error 3976).</li>
        <li><b>Only the outermost transaction is announced.</b> A nested begin, an inner commit, a savepoint and a rollback to a savepoint announce nothing.</li>
        <li><b>A refused savepoint name aborts the transaction:</b> an empty name (error 3977) or an odd byte count (error 3976) rolls back everything, and the server announces the rollback.</li>
      </ul>

      ${source('§2.2.1.4, §2.2.1.6, §2.2.1.7, §2.2.5.2.3, §2.2.5.3, §2.2.6.1, §2.2.6.6, §2.2.6.7, §2.2.6.9, §2.2.7.9, §4.13')}`,
  });
})();
