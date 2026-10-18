/* Roadmap — a view of docs/design/C-roadmap.md (the record, D-29). */
(function () {
  const { L, D, table, callout } = window.TDS;

  window.TDS.page({
    id: 'roadmap', group: 'Design', num: 'C', kind: 'explanation',
    title: 'Roadmap',
    where: `After ${L('build', 'Building the Client')}, whose milestones M1–M15, M17 and M18 are built. It sets out what comes next.`,
    outcome: 'say what each phase delivers, what it builds on, and which decisions it needs before it starts.',
    body: () => `
      ${callout('notice', `Completion scope agreed, 2026-10-18 (${D(65)})`, `The order remains Rust, Python conveniences, then application drivers (${D(63)}). Finish local Rust work including local-key Always Encrypted, create a transient GCP Windows lab, implement and validate Windows authentication, then destroy the lab. Entra and Azure-specific providers are deferred. These are requirements, not claims of implementation or deployment. Affected API/provider designs are agreed before code.`)}

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
      <p><b>Implemented baseline:</b> verified 7.4/8.0 TLS, SQL authentication, cancellation/cleanup, MARS, pooling/configuration, routing/recovery, exact scalar/large/special values, typed calls, streaming, TVPs, bulk and transactions. Native ${L('offline-replay', 'offline replay')} and connection/scalar-query ${L('rust-inspection', 'field inspection')} are implemented. The crate remains unpublished; the ${L('rust', 'Rust plan')} links to current support and acceptance evidence.</p>

      <h3 id="rust-completion-sequence--agreed-2026-10-18-d-65">Rust completion sequence · agreed 2026-10-18 (${D(65)})</h3>
      <p><b>Outcome:</b> a dependable, literate Rust client with an explicit supported scope, local-key Always Encrypted, tested Windows authentication and reproducible evidence. This is scoped completion, not full Python parity.</p>
      ${table(['Stage', 'Work', 'Exit evidence'], [
        ['1 · Finish locally', 'Agreed observation/replay gaps, correctness, readability/API/package review, repeatable checks and supported Rust/platform floor; local-key Always Encrypted with metadata, normalization, crypto and parameter orchestration', 'Local regressions, targeted malformed/fragmented-input checks, Docker matrices, independent .NET mutual encrypted read/write and deterministic lookups; intentional exclusions recorded'],
        ['2 · Create transient Windows lab', 'Terraform and configuration/test/teardown tooling under infra/gcp/, alongside the historical Azure setup; create only when Windows testing is ready', 'AD domain, DNS/time, SPNs, verified TLS, SQL Server and runners ready; Python and independent Windows-client checks establish the environment'],
        ['3 · Windows authentication', 'Agree provider contract/adapters; implement NTLM local/domain, Kerberos and negotiation; native Windows and actual Browser acceptance', 'Positive/negative cases, actual auth scheme without silent fallback, credential redaction, cancellation/failures and relevant pool/recovery; both TDS versions and plain/MARS where supported'],
        ['4 · Retain evidence and destroy', 'Export redacted results/captures; destroy the owned lab; reconcile acceptance/support/release documentation', 'Required tests ran without unavailable-environment skips; state and cloud inventory show owned resources gone; scoped Rust phase ends, M16 follows; publication separate'],
      ])}
      <p><b>Infrastructure proposal:</b> two small Windows Compute Engine VMs (disposable AD controller and domain-joined SQL Server), plus a Linux Kerberos runner. Native Windows tests can run on the SQL VM. Install SQL Server Developer on a Windows base image. Use a separate VPC and restricted access; keep DNS/Kerberos/Browser traffic inside the lab where appropriate. Adapt Azure scenarios without copying cloud-specific configuration.</p>
      <p><b>Cost/lifecycle:</b> explicit project, region, sizes, current cost estimate and maximum test window before apply; never use the default project implicitly. A fixed expiry must survive guest reboots, deleting VMs and auto-deleting test disks as a fallback. Normal and failure paths require full teardown and inventory checks for VMs, disks, addresses and other owned billable resources. Preserve state until cleanup is verified; never print or commit secrets. No lab left running between development sessions. Detailed networking, secret delivery and provider designs remain to be reviewed.</p>
      <p><b>Deferred:</b> Entra/federated authentication; Azure Key Vault and Azure-specific features/providers; Windows certificate-store key-provider support; enclaves/attestation. A GCP Windows lab does not establish Azure SQL or genuine remote-failover behavior.</p>
      <p><b>Feasibility checked 2026-10-18:</b> Google documents <a href="https://docs.cloud.google.com/compute/docs/instances/sql-server/creating-sql-server-instances">Windows/SQL Server VMs</a>, <a href="https://docs.cloud.google.com/compute/docs/instances/windows/best-practices">Active Directory</a> and <a href="https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime">automatic termination with Terraform</a>. Microsoft documents <a href="https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/microsoft-entra-authentication-sql-server-enable-without-arc?view=sql-server-ver17">Entra without Azure Arc</a>, but tenant/application permissions are still required and unavailable for this campaign. No GCP deployment, quota or IAM acceptance is established.</p>

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
