/* core.js — the namespace, registries and the small vocabulary pages are written in.
   Pages are plain HTML strings built with these helpers, so authoring stays readable. */
(function () {
  'use strict';

  const TDS = (window.TDS = {
    pages: [],          // registered pages, in reading order
    glossary: {},       // term -> { def, plural? }
    fields: {},         // field id -> { label, meaning, type, ms, ref, show }
    samples: {},        // sample id -> { title, hex, cats, parts }
    categories: {},     // category id -> label
  });

  /* ---------- registration ---------- */

  TDS.page = function (p) { TDS.pages.push(p); };
  TDS.term = function (name, def) { TDS.glossary[name] = def; };
  TDS.field = function (id, f) { TDS.fields[id] = f; };
  TDS.sample = function (id, s) { s.id = id; TDS.samples[id] = s; };

  /* ---------- authoring helpers (used inside page templates) ---------- */

  const esc = (TDS.esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])));

  /** A glossary term: shows its definition on hover. T('packet') or T('packet', 'packets'). */
  TDS.T = (term, text) => `<span class="term" tabindex="0" data-term="${esc(term)}">${esc(text || term)}</span>`;

  /** An internal link: L('ref/packet', 'Packet') or L('ref/packet', 'Packet', 'edge-cases'). */
  TDS.L = (page, text, anchor) =>
    `<a href="#/${page}${anchor ? '/' + anchor : ''}">${text}</a>`;

  /** A decision reference: D(21) -> link to that record on the Decisions page. */
  TDS.D = (n) => `<a class="dref" href="#/decisions/d-${n}">D-${n}</a>`;

  /** An interactive byte grid for a registered sample. */
  TDS.grid = (sampleId, opts = {}) =>
    `<div class="grid-mount" data-sample="${esc(sampleId)}" data-opts='${esc(JSON.stringify(opts))}'></div>`;

  /** A callout box: kind is 'notice' | 'key' | 'warn'. */
  TDS.callout = (kind, title, html) =>
    `<div class="callout callout-${kind}"><div class="callout-title">${title}</div><div class="callout-body">${html}</div></div>`;

  /** A status badge for decisions and sections. */
  TDS.badge = (status) => `<span class="badge badge-${status.toLowerCase().split(/[ ,]/)[0]}">${esc(status)}</span>`;

  /** Closing source line: the only place MS-TDS section numbers appear in prose. */
  TDS.source = (text, doc = 'MS-TDS') => `<p class="source"><span>Source</span> ${esc(doc)} ${esc(text)}</p>`;

  /** Hex string -> byte array. */
  TDS.bytes = (hex) => hex.trim().split(/\s+/).map((h) => parseInt(h, 16));
  TDS.hex2 = (b) => b.toString(16).toUpperCase().padStart(2, '0');
  TDS.hexOf = (arr) => arr.map(TDS.hex2).join(' ');
})();
