# site/: an interactive view of the design

Open `index.html` in a browser. It runs directly from disk. It needs no server and no build step, and it loads nothing from the network.

**This is a separate deliverable, not the system of record.** The design lives in [`docs/design/`](../docs/design/README.md). When the two disagree, the record is right and this site is fixed to match (D-29).

## Publishing

Every push to `main` that changes `site/` publishes it to GitHub Pages, through `.github/workflows/pages.yml`. The workflow can also be run manually from the Actions tab. It checks that every script parses, then publishes the folder as it is.

The site is published at [dawsonlp.github.io/tdsprotocol](https://dawsonlp.github.io/tdsprotocol/). Pages' source is set to **GitHub Actions** in the repository's settings. In a fork, change `dawsonlp` in `README.md` and `clients/python/pyproject.toml` to the fork's account, and set Pages' source the same way.

Every link is relative: pages link to each other through `#/…` routes, never to a file in the repository, so the site works both from disk and from Pages. Paths such as `docs/design/` appear as text, not links, because the repository's files are not part of the site. A Pages site is public, even from a private repository (except on GitHub Enterprise Cloud).

## How it's built

The site follows the client's own design rule: definitions are data, written once, and everything displayed is generated from them.

| Folder | What lives there | Change it when… |
|--------|------------------|-----------------|
| `data/glossary.js` | Every vocabulary term. It drives the dotted-term hovers and the Model's vocabulary. | a term is added or its meaning changes |
| `data/fields.js` | Every field's meaning, type, MS-TDS name and decoder | a field is added, or MS-TDS changes one |
| `data/samples.js` | Real bytes, split into fields by **byte count only**. Offsets are computed, values are decoded, meanings come from `fields.js`. | an example message is added |
| `pages/*.js` | One file per page, in reading order. Each page is plain HTML written with small helpers. | content changes |
| `assets/` | The engine: `core.js` (helpers), `bytegrid.js` (grids, hovers, table and tree views), `components.js` (diagrams), `app.js` (routing, navigation), `site.css` | presentation changes |

The Rust plan and Python baseline pages are generated from their Markdown records. After editing either, run `uv run tools/render_planning_pages.py` from the repository root. This authoring tool leaves the site self-contained; readers and publication need no Markdown renderer.

## Adding to it

- **A new message or token:**
  1. Add its fields to `data/fields.js`.
  2. Add a sample to `data/samples.js`.
  3. Put `${grid('sample-id')}` on a page.

  If the field sizes don't add up to the sample's length, the grid shows a red warning.
- **A new page:**
  1. Copy a page file from `pages/` of the same kind: concept, example, reference, procedure, decision or check.
  2. Add a `<script>` line to `index.html` in reading order.
- **Vocabulary:** wrap a term as `${T('term')}` to give it a hover definition.

## Colors

The grid's categorical colors are the first five slots of a CVD-validated palette, selected separately for light and dark mode. Every grid also has a table view, and visible labels in every cell, so a field is never identified by color alone.
