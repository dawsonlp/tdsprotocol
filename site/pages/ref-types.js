/* Reference: Data Types. A view of docs/design/3-reference/types.md (the record, D-29). */
(function () {
  const { T, L, D, table, source } = window.TDS;

  window.TDS.page({
    id: 'ref/types', group: 'Reference', kind: 'reference',
    title: 'Data Types',
    where: `${T('token')} › ${T('field')} › <b>value</b>. Every column, output value and parameter describes its type, then carries values laid out as that type says.`,
    outcome: 'read or write any value: its type’s description on the wire (TYPE_INFO), its layout, and the value the driver gives you for it.',
    body: () => `
      <h2>Purpose</h2>
      <p>On the wire, a value has no type of its own. Its column’s or parameter’s <b>type description</b> says how to read it. The driver has one vocabulary of SQL Server types, <code>tds.types</code>, for columns and parameters alike (${D(40)}). Every value it reads goes back exactly (${D(48)}). This page covers the short types (M2), the large ones (M4), <code>sql_variant</code> (M5), <code>json</code> and <code>vector</code> (M6), CLR types (M7), and tables (M8).</p>

      <h2>Shape</h2>
      <p>A type description is a one-byte <b>type code</b>, then whatever that code needs. A value is then laid out as the code says. NOT NULL columns may use the <b>fixed-size codes</b>, which have no length per value. Nullable columns, and every parameter, use the <b>codes with a length</b>.</p>
      ${table(['Code', 'Type', 'After the code', 'Each value'], [
        ['<code>30 34 38 7F</code>', '<code>tinyint smallint int bigint</code>, fixed size', '—', '1, 2, 4 or 8 bytes, little-endian; <code>tinyint</code> unsigned'],
        ['<code>26</code>', 'integer with a length', 'size: 1, 2, 4 or 8', 'length (0 = NULL), then that many bytes'],
        ['<code>32</code> / <code>68</code>', '<code>bit</code>, fixed / with a length', '— / size 1', '1 byte / length, then 1 byte'],
        ['<code>6A 6C</code>', '<code>decimal</code>, <code>numeric</code>', 'size, precision, scale', 'length (0 = NULL; 5, 9, 13 or 17), sign (1 = not negative), then the value × 10^scale, unsigned little-endian'],
        ['<code>3B 3E</code> / <code>6D</code>', '<code>real float</code>, fixed / with a length', '— / size 4 or 8', 'IEEE 754: 4 or 8 bytes'],
        ['<code>3C 7A</code> / <code>6E</code>', '<code>money smallmoney</code>, fixed / with a length', '— / size 8 or 4', 'the value × 10⁴, signed; <code>money</code> sends its high 4 bytes first'],
        ['<code>3D</code> / <code>6F</code>·8', '<code>datetime</code>', '— / size 8', 'days since 1900-01-01 (i32), then 1/300-second ticks since midnight (u32)'],
        ['<code>3A</code> / <code>6F</code>·4', '<code>smalldatetime</code>', '— / size 4', 'days since 1900-01-01 (u16), then minutes since midnight (u16)'],
        ['<code>28</code>', '<code>date</code>', '—', 'length (0 or 3), days since 0001-01-01 (u24)'],
        ['<code>29</code>', '<code>time(n)</code>', 'scale n', 'length (0, or 3, 4 or 5), then units of 10⁻ⁿ second since midnight'],
        ['<code>2A</code>', '<code>datetime2(n)</code>', 'scale n', 'length, the time, then the date'],
        ['<code>2B</code>', '<code>datetimeoffset(n)</code>', 'scale n', 'length, the <b>UTC</b> time and date, then the offset in minutes (i16, ±840)'],
        ['<code>24</code>', '<code>uniqueidentifier</code>', 'size 16', 'length (0 or 16), 16 bytes; the first three groups little-endian'],
        ['<code>AF A7</code>', '<code>char(n) varchar(n)</code>', 'max length (u16, bytes), collation (5)', 'length (u16; <code>FFFF</code> = NULL), bytes in the collation’s code page'],
        ['<code>EF E7</code>', '<code>nchar(n) nvarchar(n)</code>', 'max length (u16 = 2n), collation', 'length (u16; <code>FFFF</code> = NULL), UTF-16LE'],
        ['<code>AD A5</code>', '<code>binary(n) varbinary(n)</code>', 'max length (u16)', 'length (u16; <code>FFFF</code> = NULL), bytes'],
      ], 'compact')}
      <p><code>rowversion</code> arrives as <code>binary(8)</code> with user type 80, and <code>sysname</code> as <code>nvarchar(128)</code> with user type 256.</p>
      <p><b>Large values</b> (M4, ${D(47)}):</p>
      ${table(['Code', 'Type', 'After the code', 'Each value'], [
        ['<code>A5 A7 E7</code>', '<code>varbinary(max) varchar(max) nvarchar(max)</code>', 'max length <code>FFFF</code>; a collation for the text types', '<b>PLP</b>, below'],
        ['<code>F1</code>', '<code>xml</code>', 'schema present (u8); if 1, the database, owning schema and schema collection', 'PLP of UTF-16LE text'],
        ['<code>23 63 22</code>', '<code>text ntext image</code>', 'max length (u32); a collation for text and ntext; in a result, the table it comes from (part count, then each part)', 'in a result: a text pointer (u8 length; 0 means NULL), an 8-byte timestamp, then the length (u32) and the bytes. As a parameter: the length (u32; <code>FFFFFFFF</code> = NULL), then the bytes'],
      ], 'compact')}
      <p><b>PLP</b> (partially length-prefixed): a u64 total length (<code>FFFFFFFFFFFFFFFF</code> = NULL; <code>FFFFFFFFFFFFFFFE</code> = not known yet), then chunks, each a u32 length and that many bytes, ending with a chunk of length 0. In bulk data, a value whose length is known is that length, then the bytes alone (${L('ref/requests', 'Requests › Edge cases', 'edge-cases')}).</p>
      <p><b><code>sql_variant</code></b> (code <code>62</code>, M5): its type description is a max length (u32, 8,016). Each value carries its own base type:</p>
      ${table(['Field', 'Size', 'Meaning'], [
        ['length', 'u32', 'the rest of the value; 0 = NULL'],
        ['base type', 'u8', 'the base type’s code; the fixed-size code for integers, <code>bit</code>, <code>real</code>, <code>float</code>, <code>money</code>, <code>smallmoney</code>, <code>datetime</code>, <code>smalldatetime</code>'],
        ['property count', 'u8', 'how many bytes of properties follow'],
        ['properties', 'as counted', '<code>time</code>, <code>datetime2</code>, <code>datetimeoffset</code>: the scale · <code>decimal</code>, <code>numeric</code>: precision, scale · <code>binary</code>, <code>varbinary</code>: max length (u16) · <code>char</code> … <code>nvarchar</code>: collation (5), max length in bytes (u16) · the rest: none'],
        ['value', 'the rest', 'the base value, laid out as usual but <b>without its own length</b>: the sql_variant’s length covers it'],
      ], 'compact')}
      <p>A <code>sql_variant</code> can’t contain NULL or a large type. The driver gives each value as a <code>SqlVariant(type, value)</code>, and sends it back with the same base type (${D(48)}).</p>
      <p><b><code>json</code> and <code>vector</code></b> (M6) arrive as their real types only when the login asked for JSON support and vector support (${D(8)}); otherwise the server sends <code>nvarchar</code> text.</p>
      ${table(['Code', 'Type', 'After the code', 'Each value'], [
        ['<code>F4</code>', '<code>json</code>', '—', 'PLP. <b>The server sends UTF-8 with the UTF-8 login feature, UTF-16LE without; it reads parameters as UTF-8</b> (Edge cases)'],
        ['<code>F5</code>', '<code>vector(n)</code>, <code>vector(n, float16)</code>', 'max length (u16: 8 + n × element size), element type (u8: <code>00</code> float32, <code>01</code> float16)', 'length (u16; <code>FFFF</code> = NULL), an 8-byte header (layout <code>A9</code>, version <code>01</code>, the count u16, the element type, 3 reserved bytes), then the values, little-endian'],
      ], 'compact')}
      <p>The driver gives a <code>json</code> value as <code>str</code>, and a vector as <code>SqlVector(element, values)</code>, each value exactly a float32 or float16. A <code>vector</code> column has user type 255.</p>
      <p><b>CLR types</b> (code <code>F0</code>, M7): <code>hierarchyid</code>, <code>geometry</code>, <code>geography</code>, and types users define in .NET assemblies. A value is the type’s own serialization; the type description names the type.</p>
      ${table(['Where', 'After the code', 'Each value'], [
        ['a result', 'max size (u16; <code>FFFF</code> = no limit), then the database, schema and type name (each u8-length text), then the assembly-qualified name (u16-length text)', 'PLP'],
        ['a parameter', 'the database, schema and type name (each u8-length text; the database may be empty)', 'PLP'],
      ], 'compact')}
      <p>The driver gives a value as <code>bytes</code>, and a column’s type as <code>Clr</code>, named <code>database.schema.type</code> (<code>str(column.type)</code>). Parameters name it with <code>types.hierarchyid</code>, <code>types.geometry</code>, <code>types.geography</code>, or <code>types.clr("schema.type")</code>, or reuse the column’s type. An outer layer converts the bytes into shapes or paths (${D(39)}).</p>
      <p><b>Table-valued parameters</b> (code <code>F3</code>, M8, ${D(49)}): a table sent to a procedure, as a parameter only. It never comes back.</p>
      ${table(['Field', 'Size', 'Meaning'], [
        ['database, schema, type name', 'u8-length text, each', 'the table type. The database must be empty. The names may be empty for a procedure’s parameter, whose type the server knows'],
        ['column count', 'u16', '1 to 1,024; <code>FFFF</code> means <i>no table</i>'],
        ['<i>then each column:</i>', '', ''],
        ['user type', 'u32', '0'],
        ['flags', 'u16', '<code>0001</code> nullable · <code>0200</code> <b>default</b>: the server fills the column, and rows leave out its values'],
        ['type', 'TYPE_INFO', 'the column’s type, as for a parameter'],
        ['name', 'u8-length text', 'always empty'],
        ['<i>then, optionally:</i>', '', ''],
        ['sort and unique hint', '<code>10</code>, a count (u16), then each column number (u16) and its flags (u8: <code>01</code> ascending · <code>02</code> descending · <code>04</code> unique)', 'the rows are sorted by these columns, in this order; the unique ones have no duplicates'],
        ['send order', '<code>11</code>, a count (u16), then every column number (u16)', 'the order each row’s values travel in'],
        ['end', '<code>00</code>', ''],
        ['<i>then each row:</i>', '', ''],
        ['row', '<code>01</code>, then each value but the default columns’, as for a parameter', ''],
        ['end', '<code>00</code>', 'no more rows'],
      ], 'compact')}
      <p>Columns are numbered from 1. The driver writes a table type as its name and its columns’ types, in order: <code>types.table("shop.price_change", types.int, types.decimal(10, 2))</code>. A column the server fills is <code>types.default(type)</code>. <code>order=</code>, <code>unique=</code> and <code>send_order=</code> give the optional tokens. The value is an iterable of tuples, or a source of tuples. Each tuple holds the values of every column except those marked <code>types.default</code>, in the type’s order. The driver sends them in the send order. <code>DEFAULT</code> sends <i>no table</i>. The driver checks only what its encoding needs; the server checks the rest (Edge cases).</p>
      <p><b>Collation</b>, 5 bytes:</p>
      ${table(['Bits', 'Field', 'Meaning'], [
        ['0–19', 'locale id', 'for example <code>0x0409</code>, English (United States)'],
        ['20–27', 'flags', '<code>01</code> ignore case · <code>02</code> ignore accent · <code>04</code> ignore width · <code>08</code> ignore kana · <code>10</code> binary · <code>20</code> binary2 · <code>40</code> <b>UTF-8</b>'],
        ['28–31', 'version', 'the collation’s version'],
        ['32–39', 'sort id', 'non-zero for SQL collations (<code>SQL_…</code>)'],
      ], 'compact')}
      <p><b>Its code page:</b> UTF-8 if the UTF-8 flag is set; otherwise the sort id’s, for SQL collations; otherwise the locale’s. The table is <code>tds/collations.py</code>, generated from the server (${D(44)}). Code page 0 means Unicode only, so <code>varchar</code> can’t use the collation.</p>

      <h2>Rules</h2>
      <ul>
        <li><b>The same type, whichever code it arrives in.</b> A NOT NULL <code>int</code> column arrives as <code>38</code>, a nullable one as <code>26</code>·4; both are <code>types.int</code>.</li>
        <li><b>Parameters always use the codes with a length,</b> so they can be NULL.</li>
        <li><b>A <code>varchar</code> value is in its own column’s collation,</b> not the session’s.</li>
        <li><b>A max length of <code>FFFF</code> means <code>(max)</code>:</b> those values come as PLP. The driver spells it <code>types.MAX</code>: <code>types.varbinary(types.MAX)</code> (${D(47)}).</li>
        <li><b>A large value is read whole, or value by value</b> (<code>result_set.streamed()</code>), and sent whole or from a source (${L('client', 'The Client §4', 'large-values')}, ${D(41)}, ${D(47)}). <code>text</code>, <code>ntext</code> and <code>image</code> can’t be sent from a source: their length goes first.</li>
        <li><b>A session without the ODBC flag cuts every large value to 4,096 bytes</b> (TEXTSIZE), before the server sends it (${D(9)}).</li>
        <li><b>A table’s values are sent whole,</b> never from a source: rows can come from a source, but not a single value inside one.</li>
        <li><b>A decimal value’s integer may be shorter than its precision’s maximum:</b> each value’s length says how long it is. The driver writes the smallest of 4, 8, 12 or 16 bytes that holds the value, as the server does; inside a <code>sql_variant</code> the size is visible.</li>
        <li><b>The value the driver gives</b> (${D(48)}): <code>int</code> · <code>bool</code> · <code>Decimal</code> (with the column’s scale) · <code>float</code> · <code>datetime.date</code> · <code>datetime.datetime</code> for <code>smalldatetime</code> · <code>SqlTime</code>, <code>SqlDateTime2</code>, <code>SqlDateTimeOffset</code> (100 ns ticks) · <code>SqlDateTime</code> (1/300 s ticks) · <code>str</code> · <code>bytes</code> · <code>uuid.UUID</code> · <code>bytes</code> for CLR types, their serialization · <code>None</code> · for a table parameter, an iterable or source of tuples. The <code>Sql…</code> values convert to Python’s types exactly, or refuse unless rounding is asked for.</li>
        <li><b>Text decodes as SQL Server reads it, and encodes back to the same bytes.</b> A sequence reads as the server’s character when the server writes that character back as the same bytes; any other sequence it holds is carried as escapes (U+DC80–U+DCFF). <code>nvarchar</code> keeps unpaired surrogates.</li>
        <li><b>A value that doesn’t fit its declared type exactly is refused before sending.</b></li>
      </ul>

      <h2>Example</h2>
      <p>An empty <code>nvarchar(1)</code> column named <code>b</code>, from ${L('ref/response', 'Request Response')}’s first example:</p>
      ${table(['Bytes', 'Field', 'Value'], [
        ['<code>00 00 00 00</code>', 'user type', '0'],
        ['<code>20 00</code>', 'flags', 'computed: an expression, not a table column; not nullable'],
        ['<code>E7</code>', 'type code', '<code>nvarchar</code>'],
        ['<code>02 00</code>', 'max length', '2 bytes: <code>nvarchar(1)</code>'],
        ['<code>09 04 D0 00 34</code>', 'collation', 'locale <code>0x0409</code> · ignore case, width, kana · sort id 52: <code>SQL_Latin1_General_CP1_CI_AS</code>, code page 1252'],
        ['<code>01 62 00</code>', 'name', '<code>b</code>'],
      ], 'compact')}
      <p><code>1.50</code> as a <code>decimal(10, 2)</code> parameter: <code>6A 09 0A 02</code> (decimal · size 9 · precision 10 · scale 2), then <code>09 01 96 00 00 00 00 00 00 00</code> (length 9 · not negative · 150).</p>

      <h2>Edge cases</h2>
      <p><b>Where SQL Server differs from MS-TDS.</b> Observed from SQL Server 2025 (17.0.5015).</p>
      <ul>
        <li><b><code>json</code> arrives as UTF-16LE unless the login asked for UTF-8 support.</b> MS-TDS says <code>json</code> values follow RFC 8259, which requires UTF-8 between systems. SQL Server reads parameters as UTF-8, as RFC 8259 requires. It sends values as UTF-8 only when the login’s UTF-8 support feature was accepted (${D(8)}, on by default), and as UTF-16LE otherwise. Nothing in the value says which encoding it uses, so the driver reads each value by what the login agreed.</li>
        <li><b>A table can’t be NULL, and <i>no table</i> needs the default status bit.</b> MS-TDS says the bit must be zero for a table, but SQL Server refuses <i>no table</i> without it (error 8060: “a null table-valued parameter is required to be sent as a default parameter”). The driver sends <i>no table</i> for <code>DEFAULT</code> with the bit set, and the procedure sees an empty table. It sends <code>None</code> as <i>no table</i> without the bit, and the server refuses it.</li>
        <li><b>A large value in bulk data with a known length is the length, then the bytes alone,</b> not chunks (${L('ref/requests', 'Requests › Edge cases', 'edge-cases')}).</li>
      </ul>
      <p><b>What MS-TDS doesn’t state.</b> Observed from SQL Server 2025 (17.0.5015).</p>
      <ul>
        <li><b>What the server refuses in a table parameter,</b> each with its own error: more or fewer columns than the type has (500); more than 1,024 columns (8050); a table inside a table (8032); a hint naming a column twice, or a column the table doesn’t have (8054); a hint on a column the server fills (8057); an output table (8162).</li>
        <li><b>SQL Server’s code pages are not Python’s.</b> In single-byte code pages it gives a character to bytes Python refuses (C1 controls; private-use characters in cp874, cp1253, cp1255, cp1257). In double-byte code pages it maps whole user-defined areas to private-use characters (2,151 sequences in cp936, 6,219 in cp950), reads 249 cp950 sequences as different characters than Python does, and writes cp932’s duplicate encodings in their IBM form. <code>tds/collations.py</code> records every difference.</li>
        <li><b>UTF-8 <code>varchar</code>:</b> SQL Server refuses some invalid UTF-8 (error 9833), stores some as given (0xFF, an encoded surrogate, a code point past U+10FFFF), drops a trailing incomplete sequence, and <b>sends stored invalid bytes with U+FFFD in their place</b> (without the UTF-8 login feature, ${D(8)}). Those values can’t be sent back exactly. With the feature (the driver’s default), they arrive as stored, and go back exactly.</li>
        <li><b>Converting <code>char</code> or <code>varchar</code> to <code>varbinary</code> drops trailing zero bytes.</b> <code>DATALENGTH</code> and <code>binary(n)</code> don’t, and the value on the wire doesn’t.</li>
        <li><b>Binary values compare as if padded with zero bytes:</b> <code>0x00 = 0x0000</code> is true.</li>
        <li><b>SQL Server 2025 (17.0.5015) has no float16 vectors:</b> it accepts vector support version 1 only, and refuses <code>vector(n, float16)</code>. The driver reads and writes them as MS-TDS defines, tested with constructed bytes.</li>
        <li><b>A declared <code>varchar</code> parameter is in the database’s default collation,</b> so a value in another collation is converted when the server receives it. A value in a declared <code>nvarchar</code> parameter goes back exactly, except the sequences the server itself writes back differently (${L('ref/requests', 'Requests › Edge cases', 'edge-cases')}).</li>
        <li><b>A CLR column’s type names the database the column belongs to:</b> <code>tempdb.sys.geometry</code> for a temporary table’s column, the current database for an expression. The system types report <code>hierarchyid</code> with a max size of 892, and <code>geometry</code> and <code>geography</code> with no limit.</li>
        <li><b>A fixed-size user CLR type</b> (.NET’s Native format) reports its size, 9 for a point of two <code>int</code>s, and its column carries the fixed-length CLR flag (<code>0x100</code>, <code>ColumnFlags.FIXED_LENGTH_CLR_TYPE</code>). Its values still come as PLP.</li>
        <li><b>The sort and unique hint is checked:</b> rows out of the order it gives are refused (error 4819), and so are duplicates where the type has a key.</li>
        <li><b>A column the server fills must be flagged default:</b> an <code>IDENTITY</code> column sent with values is refused (error 1077).</li>
        <li><b><code>sp_executesql</code> needs the table type’s name:</b> when no procedure gives the type, empty names are refused (error 8059). A procedure’s parameter accepts them.</li>
        <li><b>A session logged in without the ODBC flag</b> (<code>odbc=False</code>; the driver’s default is on, ${D(9)}) starts with every ANSI option off, and TEXTSIZE at 4,096 bytes: arithmetic overflow gives NULL, not an error; <code>NULL + N'x'</code> is <code>N'x'</code>; a <code>char(n) NULL</code> column created in such a session holds its values unpadded.</li>
      </ul>

      ${source('§2.2.4.2.1.3, §2.2.5.1.2, §2.2.5.2.3, §2.2.5.4–§2.2.5.6, §2.2.5.5.2, §2.2.5.5.4, §2.2.5.5.5, §2.2.5.5.6, §2.2.5.5.7, §2.2.6.1, §2.2.6.4')}`,
  });
})();
