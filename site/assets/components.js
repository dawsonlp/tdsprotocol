/* components.js — reusable diagram pieces, each returning an HTML string for page templates. */
(function () {
  'use strict';
  const TDS = window.TDS;
  const esc = TDS.esc;

  /** Nested layers: [{ name, desc }] outermost first. Each layer is drawn inside the previous one. */
  TDS.layers = function (layers) {
    const build = (k) => {
      if (k >= layers.length) return '';
      const l = layers[k];
      return `<div class="nest nest-${k}" tabindex="0">
        <div class="nest-head"><span class="nest-name">${l.name}</span><span class="nest-desc">${l.desc}</span></div>
        ${build(k + 1)}
      </div>`;
    };
    return `<div class="nesting">${build(0)}</div>`;
  };

  /** A horizontal flow of steps. steps: [{ label, sub?, kind? }] ; kind 'end' | 'fail' | 'group'. */
  TDS.flow = function (steps, opts = {}) {
    return `<div class="flow${opts.wrap ? ' flow-wrap' : ''}">${steps
      .map((s, i) => {
        if (s.sep) return `<div class="flow-sep">${s.sep}</div>`;
        const arrow = i < steps.length - 1 && !steps[i + 1].sep ? '<div class="flow-arrow" aria-hidden="true"></div>' : '';
        return `<div class="flow-step${s.kind ? ' flow-' + s.kind : ''}"><div class="flow-label">${s.label}</div>${s.sub ? `<div class="flow-sub">${s.sub}</div>` : ''}</div>${arrow}`;
      })
      .join('')}</div>`;
  };

  /** A two-party sequence diagram. msgs: [{ dir: '>' | '<' | '<>', label, sub?, href? }] */
  TDS.sequence = function (msgs, opts = {}) {
    const rows = msgs
      .map((m, i) => {
        const cls = m.dir === '>' ? 'to-server' : m.dir === '<' ? 'to-client' : 'both';
        const inner = `<span class="seq-num">${i + 1}</span><span class="seq-label">${m.label}</span>${m.sub ? `<span class="seq-sub">${m.sub}</span>` : ''}`;
        const body = m.href ? `<a class="seq-msg ${cls}" href="${m.href}">${inner}</a>` : `<div class="seq-msg ${cls}">${inner}</div>`;
        return `<div class="seq-row${m.mark ? ' seq-mark' : ''}">${body}${m.note ? `<div class="seq-note">${m.note}</div>` : ''}</div>`;
      })
      .join('');
    return `<div class="seq">
      <div class="seq-ends"><span>${opts.left || 'client'}</span><span>${opts.right || 'server'}</span></div>
      ${rows}
      ${opts.end ? `<div class="seq-end">${opts.end}</div>` : ''}
    </div>`;
  };

  /** A layer stack drawn as horizontal bands: rows of [{ label, kind }] read left → right in time. */
  TDS.bands = function (rows) {
    return `<div class="bands">${rows
      .map((r) => `<div class="band-row"><div class="band-name">${r.name}</div><div class="band-track">${r.parts
        .map((p) => `<span class="band band-${p.kind || 'plain'}" style="flex:${p.w || 1}">${p.label}</span>`)
        .join('')}</div></div>`)
      .join('')}</div>`;
  };

  /** A simple table from rows of HTML cells. */
  TDS.table = function (head, rows, cls = '') {
    return `<div class="tbl-wrap"><table class="tbl ${cls}"><thead><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr></thead><tbody>${rows
      .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`)
      .join('')}</tbody></table></div>`;
  };

  /** Code-like notation block, with an optional caption. */
  TDS.code = function (text, caption) {
    return `<figure class="code">${caption ? `<figcaption>${caption}</figcaption>` : ''}<pre><code>${esc(text)}</code></pre></figure>`;
  };

  /** Terminal-style output block. */
  TDS.term_out = function (text) {
    return `<pre class="terminal"><code>${esc(text)}</code></pre>`;
  };

  /** Tabs: [{ label, html }] */
  TDS.tabs = function (tabs) {
    const id = 'tabs-' + Math.random().toString(36).slice(2, 8);
    return `<div class="tabs" id="${id}">
      <div class="tab-list" role="tablist">${tabs
        .map((t, i) => `<button type="button" role="tab" class="tab${i === 0 ? ' on' : ''}" aria-selected="${i === 0}" data-tab="${i}">${t.label}</button>`)
        .join('')}</div>
      ${tabs.map((t, i) => `<div class="tab-panel" role="tabpanel" data-panel="${i}"${i === 0 ? '' : ' hidden'}>${t.html}</div>`).join('')}
    </div>`;
  };

  /** Wire up interactive bits after a page renders. */
  TDS.hydrateComponents = function (scope) {
    scope.querySelectorAll('.tabs').forEach((t) => {
      t.querySelector('.tab-list').addEventListener('click', (e) => {
        const b = e.target.closest('.tab');
        if (!b) return;
        t.querySelectorAll('.tab').forEach((x) => { x.classList.toggle('on', x === b); x.setAttribute('aria-selected', x === b); });
        t.querySelectorAll('.tab-panel').forEach((p) => (p.hidden = p.dataset.panel !== b.dataset.tab));
      });
    });
    scope.querySelectorAll('.nesting').forEach((n) => {
      n.addEventListener('pointerover', (e) => {
        const box = e.target.closest('.nest');
        n.querySelectorAll('.nest.hl').forEach((x) => x.classList.remove('hl'));
        if (box) box.classList.add('hl');
      });
      n.addEventListener('pointerleave', () => n.querySelectorAll('.nest.hl').forEach((x) => x.classList.remove('hl')));
    });
  };
})();
