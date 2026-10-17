/* Worked Example — one real login, byte by byte. Concrete before abstract. */
(function () {
  const { T, L, D, grid, callout, sequence, source } = window.TDS;
  const step = (n) => `#/example/step-${n}`;

  window.TDS.page({
    id: 'example', group: 'Learn', num: '2', kind: 'example',
    title: 'Worked Example: a Login',
    where: `The <i>connect</i> conversation from ${L('model', 'the Model')}, traced byte by byte.`,
    outcome: 'read a TDS login capture: find each message, split it into packets and fields, and say what each one does.',
    body: () => `
      <p class="lede">Five messages take a client from a plain TCP connection to <b>ready</b>. Every byte below is interactive.
      Hover a byte to see its field, its value and what it means. Click to pin the box, and use the arrow keys to move field by field.</p>
      <p>The bytes come from MS-TDS’s own samples, so you can check them against the official document. Only the client’s host name differs. They were captured
      from an older client (TDS 7.2), so what <a href="#/example/what-the-driver-sends-differently">the driver sends differently</a>
      is listed at the end. MS-TDS has no sample reply to the hello, so that one is <b>constructed</b> and labeled as such.</p>

      ${sequence([
        { dir: '>', label: 'hello', sub: 'PRELOGIN: versions, encryption', href: step(1) },
        { dir: '<', label: 'hello reply', sub: 'the server agrees on terms', href: step(2) },
        { dir: '<>', label: 'secure', sub: 'TLS handshake, carried inside hello packets', href: step(3) },
        { dir: '>', label: 'log in', sub: 'LOGIN7: who the client is', href: step(4), note: 'from here on, everything travels inside TLS' },
        { dir: '<', label: 'login reply', sub: 'a token stream ending in DONE', href: step(5) },
      ], { end: 'ready' })}

      <h2 id="step-1">1 · Hello: the client introduces itself</h2>
      <p>Every ${T('packet')} starts with the same 8-byte header. After it comes the hello’s ${T('body')}, a ${T('structure')} in two parts:
      a <b>directory</b> of <i>(option, offset, length)</i> entries ending in <code>FF</code>, then the <b>data</b> those entries point to.
      Hover an entry to highlight its value. Hover a value to highlight its entry.</p>
      ${grid('prelogin-request')}
      ${callout('notice', 'Notice', 'The directory and the version use <b>big-endian</b> numbers. This is one of the few places in TDS that does. The thread id, a few bytes later, is little-endian.')}

      <h2 id="step-2">2 · Hello reply: the server agrees on terms</h2>
      <p>The reply has <b>the same structure</b>, with three differences:</p>
      <ul>
        <li>The packet type is <code>04</code>, which every server message uses.</li>
        <li>The session id is now set.</li>
        <li>The values are the server’s. Instance <code>00</code> means “yes, that’s me”.</li>
      </ul>
      ${grid('prelogin-reply')}
      <p>Both sides said encryption <b>on</b>, so the next step is TLS.</p>

      <h2 id="step-3">3 · Secure: TLS, carried inside TDS</h2>
      <p>TLS handshake records travel as the payload of hello packets, in both directions, until the handshake completes.
      After that, the arrangement is reversed: <b>whole TDS packets, headers included, travel inside TLS.</b> The next two messages are shown as they look after decryption.</p>
      ${grid('tls-in-prelogin')}

      <h2 id="step-4">4 · Log in: who the client is, and what it wants</h2>
      <p>The login body has three parts:</p>
      <ul>
        <li>a <b>fixed part</b>: fields that are always present, in a fixed order;</li>
        <li>a <b>pointer table</b> of <i>(offset, length)</i> entries;</li>
        <li>a <b>data part</b> that holds the strings, one after another, with no gaps between them.</li>
      </ul>
      <p>Switch the grid to <b>Text</b> to read the strings.</p>
      ${grid('login7')}
      ${callout('notice', 'Notice', `Empty fields still have an offset. It points to where the next string <i>would</i> go. The password here is empty.
        A real password is lightly scrambled. For example, <code>a</code> (<code>61 00</code>) is sent as <code>B3 A5</code>. The scrambling does not provide security; TLS does.`)}

      <h2 id="step-5">5 · Login reply: the server accepts, and describes the session</h2>
      <p>The reply is one packet. Its body is a ${T('token stream')} of eight ${T('token', 'tokens')}:</p>
      <ul>
        <li>four ${T('announcement', 'announcements')} (<code>ENVCHANGE</code>) that set up the ${T('session state')};</li>
        <li>two informational messages;</li>
        <li><code>LOGINACK</code>, which accepts the login;</li>
        <li><code>DONE</code>, which ends the reply.</li>
      </ul>
      <p>The bar above the grid shows all the tokens. Hover one to highlight its bytes.</p>
      ${grid('login-reply')}
      ${callout('notice', 'Notice', `Success is signaled by <b>LOGINACK being present</b>, not by its position. Here it comes near the end.
        A failed login has an <code>ERROR</code> token and no LOGINACK. The new packet size takes effect from the <b>next</b> message.`)}

      <h2>What just happened</h2>
      <ol>
        <li>The client and server <b>agreed on terms</b> (hello), turned on <b>TLS</b> (secure), and the client <b>identified itself</b> (log in).</li>
        <li>The server answered with <b>announcements</b> that set up the session state, a <b>LOGINACK</b> accepting the login, and a <b>DONE</b> ending the reply.</li>
        <li>The client is now <b>ready</b> to open a ${T('serial channel')} and send requests.</li>
      </ol>
      ${callout('key', 'In TDS 8.0', 'Step 3 moves to the start. TLS is set up directly on TCP, before the hello. Steps 1, 2, 4 and 5 are identical.')}

      <h2 id="what-the-driver-sends-differently">What the driver sends differently</h2>
      <p>Each difference is a decision in ${L('decisions', 'Decisions')}.</p>
      <ul>
        <li>TDS version <code>04 00 00 74</code> (7.4) instead of <code>02 00 09 72</code> (${D(2)}).</li>
        <li>MARS <b>off</b> (<code>00</code>), unless <code>connect(mars=True)</code> asks for several serial channels (${D(18)}).</li>
        <li>The ODBC flag, unless <code>connect(odbc=False)</code> turns it off (${D(9)}).</li>
        <li>A feature list, pointed to by the <i>extension</i> entry. By default it asks for JSON support, vector support, UTF-8 support, data classification and session recovery (${D(8)}).</li>
      </ul>

      ${source('§4.1, §4.2, §4.4, §2.2.6.5')}`,
  });
})();
