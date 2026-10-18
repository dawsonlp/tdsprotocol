/* Roadmap — a view of docs/design/C-roadmap.md (the record, D-29). */
(function () {
  const { L, D, table, callout } = window.TDS;

  window.TDS.page({
    id: 'roadmap', group: 'Design', num: 'C', kind: 'explanation',
    title: 'Roadmap',
    where: `After ${L('build', 'Building the Client')}, whose milestones M1–M15, M17 and M18 are built. It sets out what comes next.`,
    outcome: 'say what each phase delivers, what it builds on, and which decisions it needs before it starts.',
    body: () => `
      ${callout('notice', `Agreed, 2026-10-17 (${D(63)})`, `The user revised the order: Rust first, then Python conveniences, then application drivers. The ${L('rust', 'Rust development plan')} is a proposal; its ${L('python-baseline', 'Python baseline')} records test evidence and server setup. Each phase’s design is agreed before its code is written. Accepted milestones are then added to ${L('done-when', 'Done When')}.`)}

      <h2 id="the-phases">The phases</h2>
      ${table(['#', 'Phase', 'Delivers', 'Builds on'], [
        ['1', '<b>A Rust client</b>', 'The same driver in Rust, with explicit ownership/permissions and the same learning intent', 'The design pages, and the Python code and tests'],
        ['2', '<b>Conveniences</b> (M16)', 'The standard patterns of use in one call each, in Python, asynchronous and synchronous', `The driver’s public surface (${D(39)})`],
        ['3', '<b>Application drivers</b>', 'DB-API 2.0 for Python, and possibly other standard interfaces', 'The conveniences'],
      ])}
      <p>Phase 3 depends on phase 2. Rust does not depend on completing Python M16.</p>

      <h2 id="1-a-rust-client">1 · A Rust client</h2>
      <p><b>Goal:</b> a second client that follows the same design in Rust. Its code teaches the protocol as the Python code does, with the same names, and links to the same reference pages.</p>
      <p><b>Development path:</b> establish the local Python baseline, analyze its code, agree ownership/permissions and exact representations, then implement Rust in small tested slices. The ${L('rust', 'Rust development plan')} begins with those rules; the ${L('python-baseline', 'Python baseline')} separates offline, local-live and remote validation.</p>
      <p><b>How the Python client helps:</b></p>
      <ul>
        <li><b>The design pages are the specification for both clients.</b> Each Rust module names the page it implements, as each Python module does.</li>
        <li><b>The sans-I/O core can be ported part by part:</b> the definitions and the codec first, then the procedures, then a shell (${D(24)}, ${D(27)}).</li>
        <li><b>The tests’ data can be shared:</b> MS-TDS’s own samples, the responses captured from SQL Server, and the generated collation table. A capture (${D(12)}) recorded by either client can be replayed through the other.</li>
        <li><b>The Python client is a reference to compare against.</b> For fixed deterministic inputs and options, both clients must encode the same protocol bodies and read the same semantic response record. Variable session fields, timestamps, nonces and TLS ciphertext require explicitly scoped comparisons.</li>
        <li><b>The live tests run against the same SQL Server container</b>, with the same scenarios.</li>
      </ul>
      <p><b>Current first slice:</b> <code>clients/rust/</code> contains a runtime-independent core and the approved Tokio shell/in-memory rustls pairing. One persistent connection task, movable channel authority, borrowed responses and conservative abandonment are agreed. Both TDS versions now support verified TLS, independent MARS channels and explicit-return pooling for the current integer/token subset; see the ${L('rust', 'Rust plan and evidence')}.</p>
      <p><b>Cancellation slice:</b> explicit awaited Attention/drain, exchange-scoped cancel handles and a separate configurable 5-second cleanup budget are agreed and implemented. Cleanup failure preserves the original cause and discards the connection. Delegated channel close and stale-lifetime isolation are now corrected in both clients; Python additionally has MARS/partial-send evidence.</p>
      <p><b>Observation slice:</b> the approved failure policy and one recording per physical connection are implemented in both clients. Rust provides initial step/message/packet/token observation and credential-redacted JSON-lines recording; four fresh Rust recordings replay through Python. Field inspection trees, detailed timings and Rust-native replay remain open. Python pools/routing/recovery use recording factories; reusing one transport across loans keeps its recording.</p>
      <p><b>Routing slice:</b> one-hop routing, a single deadline, destination certificate identity and separate recordings are implemented/tested through a local router to Docker under both TDS versions × plain/MARS. Recovery is now implemented in both clients: stable logical channel/close authority, fresh wire ids and retired old exchange permissions. The ${L('recovery-experiment', 'experiment record')} preserves the failure, correction and Python/Rust results. Rust epoch guards prevent old read/Drop controls from revoking the replacement. Sixteen physical recordings replay through Python with logical row attribution and redaction checked; remote failover/platform coverage remains separate.</p>
      <p><b>Still to decide before affected implementation:</b> response interfaces beyond the implemented Python-compatible retention subset, exact value representations beyond the first integer/text subset, neutral shared-fixture format, supported Rust/platform floor and later milestone details. The broader connection features remain tracked in the Rust plan.</p>

      <h2 id="2-conveniences">2 · Conveniences</h2>
      <p><b>Goal:</b> each common pattern of use takes one call, and still shows what the server did (${D(35)}).</p>
      <p><b>What it contains</b> (already agreed):</p>
      <ul>
        <li><b>The serial channel’s conveniences</b> (${D(37)}): <code>query</code>, <code>fetch</code>, <code>fetch_value</code>, <code>call</code>, <code>prepare</code>, <code>describe</code> and <code>transaction</code>. Each one is an exchange and a way of reading its response, and each checks the response’s shape.</li>
        <li><b>A synchronous entry point</b> with the same shape as the asynchronous one (${D(38)}).</li>
        <li><b>A bulk-load helper</b> that writes the <code>INSERT BULK</code> statement from the columns (${D(50)}).</li>
        <li><b>An error translator</b> (${L('done-when', 'Done When › M16', 'm16-the-convenience-layer-and-the-synchronous-shell')}).</li>
        <li><b>Parameterized statements</b> whose SQL types are inferred from Python values. ${D(39)} places type inference here, outside the driver.</li>
      </ul>
      <p>It uses only the driver’s public surface. If it needs something more, the driver is missing it (${D(39)}).</p>
      <p><b>To decide before building:</b></p>
      <ul>
        <li>Where it lives: a module of the <code>tds</code> package, or a package of its own.</li>
        <li>How each SQL type is inferred from a Python value, for example the length of a <code>str</code> parameter, a <code>Decimal</code>’s precision and scale, and a <code>datetime</code>’s type.</li>
        <li>How the synchronous shell runs. It could be a second shell around the same sans-I/O core, using blocking sockets (${D(24)}), or it could run the asynchronous shell on an event loop of its own.</li>
      </ul>

      <h2 id="3-application-drivers">3 · Application drivers</h2>
      <p><b>Goal:</b> standard interfaces that existing applications and libraries already use, built around the driver.</p>
      <ul>
        <li><b>DB-API 2.0</b> (PEP 249), for Python: a package that depends on <code>tds</code> (${D(39)}), built on the conveniences. Two of its questions are recorded in ${L('decisions', 'Decisions › Deferred', 'deferred')}: how long a serial channel lives (${D(25)}), and what happens when a cursor runs while another has unread rows (${D(26)}).</li>
        <li><b>Other standard interfaces, possibly:</b> each one a layer around the driver, such as an SQLAlchemy dialect for Python, built on DB-API. Which ones, and in what order, is decided when phase 3 starts.</li>
      </ul>
      <p><b>To decide before building:</b></p>
      <ul>
        <li>Whether each driver lives in this repository or in a repository of its own.</li>
        <li>DB-API’s parameter style, and how its type objects map to the driver’s types.</li>
        <li>How DB-API’s synchronous interface uses phase 2’s synchronous entry point.</li>
        <li>${D(25)} and ${D(26)}.</li>
      </ul>`,
  });
})();
