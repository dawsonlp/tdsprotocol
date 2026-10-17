/* The Model — the advance organizer: the whole protocol on one page, plus the vocabulary. */
(function () {
  const { T, L, D, layers, flow, bands, source } = window.TDS;

  const VOCAB = ['connection', 'pool', 'serial channel', 'exchange', 'packet', 'packet size', 'message', 'body', 'structure',
    'token stream', 'token', 'result set', 'completion', 'field', 'conversation', 'step', 'session state'];

  window.TDS.page({
    id: 'model', group: 'Learn', num: '1', kind: 'concept',
    title: 'The Model',
    where: 'The start of the reading path. Every other page builds on this one.',
    outcome: 'name every layer of a TDS conversation, say what each layer is for, and place any byte you see into one of them.',
    body: () => `
      <p class="lede">A client and a database server hold a ${T('conversation')} over a ${T('connection')}.
      Everything they say to each other nests like this. Hover a layer to focus it.</p>

      ${layers([
        { name: 'connection', desc: 'TCP, usually wrapped in TLS' },
        { name: 'serial channel', desc: 'one ordered request-and-response path; one per connection, or several with MARS' },
        { name: 'packet', desc: 'at most the packet size: an 8-byte header plus payload' },
        { name: 'message', desc: 'one or more packets of the same type; the last is marked “end”' },
        { name: 'body', desc: 'either a STRUCTURE (fixed layout) or a TOKEN STREAM (tagged items)' },
        { name: 'field', desc: 'a named, typed value: a number, a string, a list, a flag set' },
        { name: 'bytes', desc: 'what is actually on the wire' },
      ])}

      <h2>The conversation</h2>
      <p>The conversation is the order in which the two sides send messages. Connecting happens once per
      connection. After that, each ${T('serial channel')} carries ${T('exchange', 'exchanges')}, one at a time.</p>
      ${flow([
        { label: 'hello', sub: 'agree on terms' }, { label: 'secure', sub: 'start TLS' }, { label: 'log in', sub: 'who, and how' },
        { label: 'ready', kind: 'end' },
        { sep: 'then, repeatedly' },
        { label: 'request', kind: 'group' }, { label: 'response', kind: 'group', sub: 'ends with DONE' },
        { sep: 'at any time' }, { label: 'cancel', kind: 'fail' },
      ])}

      <p>MS-TDS defines <b>nine conversations in three families</b>: <b>connecting</b> (four ways to log in), <b>requests</b>
      (SQL batch, remote procedure call, bulk load, transaction-manager request) and <b>control</b> (cancel).
      ${L('ref/conversations', 'Conversations')} lists them all.</p>

      <h2>Rules that hold everywhere</h2>
      <ol class="rules">
        <li><b>On a serial channel, the client speaks, then the server answers.</b> Only one exchange runs at a time. The only interruption allowed is <i>cancel</i>.</li>
        <li><b>Every packet starts with the same 8-byte header.</b> It says what kind of message the packet carries, whether it is the last packet, and how long it is.</li>
        <li><b>Every server message has packet type <code>04</code>.</b> Apart from the hello reply, each is a ${T('token stream')} that ends with <code>DONE</code>. A <code>DONE</code> marked “more” means another one follows.</li>
        <li><b>Session settings change by ${T('announcement')}.</b> When the database, language or packet size changes, the server sends an <code>ENVCHANGE</code> token and the client updates its ${T('session state')}.</li>
        <li><b>Numbers are little-endian</b>, except in a few marked places: the packet header and the PRELOGIN directory are big-endian. <b>Text is UTF-16LE.</b></li>
      </ol>

      <h2>Where TLS and MARS fit</h2>
      <p>TDS 7.4 and 8.0 share every message and token. They differ only in <b>when TLS starts</b>.</p>
      ${bands([
        { name: 'TDS 7.4', parts: [{ label: 'TCP' }, { label: 'hello (plain)', kind: 'tds' }, { label: 'TLS handshake inside hello packets', kind: 'tls', w: 2 }, { label: 'TDS inside TLS', kind: 'tds', w: 3 }] },
        { name: 'TDS 8.0', parts: [{ label: 'TCP' }, { label: 'TLS handshake', kind: 'tls', w: 2 }, { label: 'all TDS inside TLS, starting with hello', kind: 'tds', w: 4 }] },
        { name: 'MARS', parts: [{ label: 'TCP' }, { label: 'TLS', kind: 'tls' }, { label: 'MARS framing: one connection, several serial channels', kind: 'mars', w: 3 }, { label: 'packets', kind: 'tds', w: 2 }] },
      ])}
      ${window.TDS.callout('key', 'MARS is not parallelism',
        `Serial channels on one connection <b>take turns</b> on the server and share its transaction and settings. Only separate connections run in parallel (${D(18)}).`)}

      <h2 id="vocabulary">Vocabulary</h2>
      <p>These words mean the same thing everywhere: in these pages, in the code, and in what the running client shows. Hover any dotted term on any page to see its definition.</p>
      <div class="vocab">${VOCAB.map((t) => `<div><b>${t}</b>${window.TDS.esc(window.TDS.glossary[t])}</div>`).join('')}</div>

      ${source('§1.3, §1.4, §2.1–§2.2.4')}`,
  });
})();
