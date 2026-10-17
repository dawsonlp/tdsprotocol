/* bytegrid.js — the interactive packet grid.
   A sample is bytes plus an ordered list of fields (parts → fields, each with a byte count).
   Field meanings come from the field dictionary; values are decoded from the bytes. */
(function () {
  'use strict';
  const TDS = window.TDS;

  /* ---------- decoding: bytes -> values ---------- */

  const dec = {
    u8: (b) => b[0],
    u16be: (b) => (b[0] << 8) | b[1],
    u16le: (b) => b[0] | (b[1] << 8),
    u32le: (b) => (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0,
    i32le: (b) => b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24),
    u64le: (b) => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; },
    utf16: (b) => { let s = ''; for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode(b[i] | (b[i + 1] << 8)); return s; },
  };
  const hx = (n, w = 2) => '0x' + n.toString(16).toUpperCase().padStart(w, '0');

  /** Formatters used by the field dictionary. Each returns show(bytes) -> string. */
  TDS.fmt = {
    num: (d, unit) => (b) => { const v = dec[d](b); return unit ? (typeof unit === 'function' ? unit(v) : `${v} ${unit}`) : String(v); },
    enum: (d, map) => (b) => { const v = dec[d](b); return map[v] !== undefined ? map[v] : `unknown (${hx(v)})`; },
    text: () => (b) => (b.length ? `“${dec.utf16(b).replace(/\u0000/g, '␀')}”` : '(empty)'),
    flags: (bits) => (b) => {
      const v = b[0];
      const on = bits.filter(([mask]) => (v & mask) === mask && mask !== 0).map(([, name]) => name);
      return on.length ? on.join(' · ') : 'none set';
    },
    hex: () => (b) => TDS.hexOf(b),
    dec,
    hx,
  };

  /* ---------- layout: sample -> flat list of placed fields ---------- */

  function layout(sample) {
    const bytes = TDS.bytes(sample.hex);
    const items = [];
    const byId = {};
    let at = 0;
    sample.parts.forEach((part, pi) => {
      part.fields.forEach((f) => {
        const def = Object.assign({ label: f.f, meaning: '' }, TDS.fields[f.f] || {}, f);
        const b = bytes.slice(at, at + f.n);
        const value = f.value !== undefined ? f.value : def.show ? def.show(b, def) : TDS.hexOf(b);
        const item = { i: items.length, part: pi, cat: part.cat, start: at, n: f.n, def, bytes: b, value, id: f.id, points: f.points };
        items.push(item);
        if (f.id) byId[f.id] = item.i;
        at += f.n;
      });
    });
    const problem = at !== bytes.length ? `Field sizes add up to ${at} bytes, but the sample has ${bytes.length}.` : null;
    // Who points at whom, both ways.
    items.forEach((it) => {
      it.targets = (it.points ? [].concat(it.points) : []).map((id) => byId[id]).filter((x) => x !== undefined);
    });
    items.forEach((it) => (it.sources = items.filter((o) => o.targets.includes(it.i)).map((o) => o.i)));
    return { bytes, items, problem };
  }

  /* A string field's byte as text: `text` is the field's encoding, 'utf16' (TDS's strings, UTF-16LE: the character on
     its first byte, · on its second) or 'ascii' (one byte, one character, as MC-SQLR's strings). */
  const charAt = (text, b, i) => {
    const show = (c) => (c === 0 ? '␀' : String.fromCharCode(c));
    if (text === 'ascii') return show(b[i]);
    return i % 2 === 0 ? show(b[i] | (b[i + 1] << 8)) : '·';
  };

  const slotOf = (sample, cat) => sample.cats.indexOf(cat) + 1;
  const bodyStart = (sample) => (sample.noHeader ? 0 : 8);

  /* ---------- tooltip ---------- */

  const tip = () => document.getElementById('tip');
  let pinned = null; // { grid, i }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  /* A field's own explanation, beyond its meaning: `detail(bytes, def)` gives sections, each one of
     { parts: [[bytes, name, value, note]] }: the field split into what each byte holds;
     { title, rows: [[key, text]], on }: a list it relates to, row `on` marked;
     { text }: a paragraph. */
  function detailOf(sections) {
    const box = el('div', 'tip-detail');
    sections.forEach((s) => {
      if (s.parts) {
        const t = el('table', 'tip-parts');
        s.parts.forEach(([bytes, name, value, note]) => {
          const tr = el('tr');
          tr.append(el('td', 'mono', bytes), el('td', null, name), el('td', 'v', value), el('td', 'n', note || ''));
          t.append(tr);
        });
        box.append(t);
      } else if (s.rows) {
        if (s.title) box.append(el('div', 'tip-list-title', s.title));
        const t = el('table', 'tip-list');
        s.rows.forEach(([key, text], k) => {
          const tr = el('tr', k === s.on ? 'on' : '');
          tr.append(el('td', 'mono', key), el('td', null, text));
          t.append(tr);
        });
        box.append(t);
      } else if (s.text) box.append(el('p', null, s.text));
    });
    return box;
  }

  function fillTip(sample, model, i) {
    const it = model.items[i];
    const d = it.def;
    const t = tip();
    t.replaceChildren();
    t.dataset.slot = slotOf(sample, it.cat);

    t.append(el('div', 'tip-value', it.value));

    const head = el('div', 'tip-head');
    head.append(el('span', 'tip-key'), el('span', 'tip-label', d.label), el('span', 'tip-cat', TDS.categories[it.cat] || it.cat));
    t.append(head);

    if (d.meaning) t.append(el('p', 'tip-meaning', d.meaning));
    if (d.detail) t.append(detailOf(d.detail(it.bytes, d)));

    const meta = el('dl', 'tip-meta');
    const row = (k, v) => { if (v === undefined || v === '') return; meta.append(el('dt', null, k), el('dd', null, v)); };
    const shown = it.bytes.length > 12 ? TDS.hexOf(it.bytes.slice(0, 12)) + ' …' : TDS.hexOf(it.bytes);
    row('Bytes', shown);
    const bs = bodyStart(sample);
    row('Offset', it.start >= bs && bs ? `${hx(it.start - bs)} in body · ${hx(it.start)} in packet` : `${hx(it.start)}`);
    const typeAddsInfo = d.type && !/^\d+ bytes?$/.test(d.type);
    row('Size', `${it.n} byte${it.n === 1 ? '' : 's'}${typeAddsInfo ? ' · ' + d.type : ''}`);
    row(d.spec || 'MS-TDS', d.ms);
    t.append(meta);

    const rel = (label, list) => {
      if (!list.length) return;
      const p = el('div', 'tip-rel');
      p.append(el('span', 'tip-rel-k', label), el('span', null, list.map((j) => model.items[j].def.label).join(', ')));
      t.append(p);
    };
    rel('Points to →', it.targets);
    rel('Pointed to by ←', it.sources);
    if (d.note) t.append(el('p', 'tip-note', d.note));

    const foot = el('div', 'tip-foot');
    if (d.ref) {
      const a = el('a', null, 'Reference ›');
      a.href = '#/' + d.ref;
      foot.append(a);
    }
    foot.append(el('span', 'tip-hint', pinned ? 'Esc to unpin' : 'Click to pin'));
    t.append(foot);
  }

  function placeTip(anchor) {
    const t = tip();
    t.hidden = false;
    const r = anchor.getBoundingClientRect();
    const tw = t.offsetWidth, th = t.offsetHeight, m = 10;
    let left = Math.min(Math.max(r.left + r.width / 2 - tw / 2, m), window.innerWidth - tw - m);
    let top = r.bottom + m;
    if (top + th > window.innerHeight - m) top = r.top - th - m;
    if (top < m) top = m;
    t.style.left = `${left}px`;
    t.style.top = `${top}px`;
    t.classList.add('show');
  }

  function hideTip() { const t = tip(); t.classList.remove('show'); t.hidden = true; }

  /* ---------- rendering ---------- */

  function render(mount) {
    const sample = TDS.samples[mount.dataset.sample];
    if (!sample) { mount.textContent = `Missing sample: ${mount.dataset.sample}`; return; }
    const opts = JSON.parse(mount.dataset.opts || '{}');
    const cols = opts.cols || 16;
    const model = layout(sample);

    const fig = el('figure', 'bg');
    fig.style.setProperty('--cols', cols);

    /* caption + controls */
    const cap = el('figcaption', 'bg-cap');
    const titles = el('div', 'bg-titles');
    titles.append(el('div', 'bg-title', opts.title || sample.title));
    const sub = [`${model.bytes.length} bytes`, sample.note].filter(Boolean).join(' · ');
    titles.append(el('div', 'bg-sub', sub));
    cap.append(titles);
    const controls = el('div', 'bg-controls');
    const seg = (name, choices) => {
      const g = el('div', 'seg-toggle');
      g.setAttribute('role', 'group');
      g.setAttribute('aria-label', name);
      choices.forEach(([val, label], k) => {
        const b = el('button', k === 0 ? 'on' : '', label);
        b.type = 'button';
        b.dataset.val = val;
        b.setAttribute('aria-pressed', k === 0);
        g.append(b);
      });
      return g;
    };
    const viewToggle = seg('View', [['grid', 'Grid'], ['table', 'Table']]);
    const showToggle = seg('Show strings as', [['hex', 'Hex'], ['text', 'Text']]);
    const hasText = model.items.some((it) => it.def.text);
    if (hasText) controls.append(showToggle);
    controls.append(viewToggle);
    cap.append(controls);
    fig.append(cap);

    if (model.problem) fig.append(el('div', 'bg-problem', model.problem));

    /* structure bar: the message at a glance */
    const bar = el('div', 'bg-bar');
    sample.parts.forEach((part, pi) => {
      const len = part.fields.reduce((a, f) => a + f.n, 0);
      const s = el('div', `bar-seg slot-${slotOf(sample, part.cat)}`);
      s.style.flexGrow = Math.max(len, model.bytes.length / 40);
      s.dataset.part = pi;
      s.append(el('span', 'bar-label', part.label), el('span', 'bar-len', `${len} B`));
      s.title = `${part.label} · ${len} bytes`;
      bar.append(s);
    });
    fig.append(bar);

    /* legend */
    const legend = el('div', 'bg-legend');
    sample.cats.forEach((c) => {
      const li = el('span', `leg slot-${slotOf(sample, c)}`);
      li.dataset.cat = c;
      li.append(el('span', 'leg-sw'), el('span', null, TDS.categories[c] || c));
      legend.append(li);
    });
    fig.append(legend);

    /* the grid */
    const grid = el('div', 'bg-grid');
    grid.tabIndex = 0;
    grid.setAttribute('role', 'application');
    grid.setAttribute('aria-label', `${sample.title}: byte grid. Use arrow keys to move between fields.`);
    grid.append(el('div', 'col-head corner'));
    for (let c = 0; c < cols; c++) grid.append(el('div', 'col-head', c.toString(16).toUpperCase()));
    const rows = Math.ceil(model.bytes.length / cols);
    for (let r = 0; r < rows; r++) {
      const o = el('div', 'row-off', hx(r * cols, 3).replace('0x', ''));
      o.style.gridRow = r + 2;
      grid.append(o);
    }
    model.items.forEach((it) => {
      let at = it.start, left = it.n, first = true;
      while (left > 0) {
        const r = Math.floor(at / cols), c = at % cols;
        const len = Math.min(left, cols - c);
        const s = el('div', `seg slot-${slotOf(sample, it.cat)}${first ? ' first' : ''}${left === len ? ' last' : ''}${first && it.def.brk ? ' brk' : ''}`);
        s.dataset.i = it.i;
        s.dataset.part = it.part;
        s.style.gridRow = r + 2;
        s.style.gridColumn = `${c + 2} / span ${len}`;
        s.append(el('div', 'seg-label', first && (len >= 2 || it.n === 1) ? it.def.cell || it.def.label : ''));
        const bytesEl = el('div', 'seg-bytes');
        bytesEl.style.gridTemplateColumns = `repeat(${len}, minmax(0,1fr))`;
        for (let k = 0; k < len; k++) {
          const rel = at - it.start + k;
          const span = el('span', 'byte', TDS.hex2(it.bytes[rel]));
          span.dataset.hex = TDS.hex2(it.bytes[rel]);
          if (it.def.text) span.dataset.txt = charAt(it.def.text, it.bytes, rel);
          bytesEl.append(span);
        }
        s.append(bytesEl);
        grid.append(s);
        at += len; left -= len; first = false;
      }
    });
    fig.append(grid);

    /* table view (also the accessible equivalent of the grid) */
    const tableWrap = el('div', 'bg-table');
    tableWrap.hidden = true;
    fig.append(tableWrap);
    const buildTable = () => {
      if (tableWrap.firstChild) return;
      const t = el('table');
      const head = el('tr');
      ['Offset', 'Part', 'Field', 'Bytes', 'Value', 'Meaning'].forEach((h) => head.append(el('th', null, h)));
      const thead = el('thead');
      thead.append(head);
      t.append(thead);
      const tb = el('tbody');
      model.items.forEach((it) => {
        const tr = el('tr');
        const bs = bodyStart(sample);
        const key = el('span', `leg-sw slot-${slotOf(sample, it.cat)}`);
        const partCell = el('td', 'part');
        partCell.append(key, document.createTextNode(sample.parts[it.part].label));
        tr.append(
          el('td', 'mono', it.start >= bs && bs ? hx(it.start - bs) : hx(it.start)),
          partCell,
          el('td', null, it.def.label),
          el('td', 'mono', it.bytes.length > 8 ? TDS.hexOf(it.bytes.slice(0, 8)) + ' …' : TDS.hexOf(it.bytes)),
          el('td', 'val', it.value),
          el('td', 'mean', it.def.meaning || ''),
        );
        tb.append(tr);
      });
      t.append(tb);
      tableWrap.append(t);
    };

    mount.replaceChildren(fig);

    /* ---------- interaction ---------- */

    let active = null;
    const segsOf = (i) => grid.querySelectorAll(`.seg[data-i="${i}"]`);
    const clearMarks = () => {
      fig.classList.remove('has-active', 'has-part');
      fig.querySelectorAll('.is-on, .is-target, .is-source, .part-on').forEach((e) => e.classList.remove('is-on', 'is-target', 'is-source', 'part-on'));
    };
    const activate = (i, anchor) => {
      clearMarks();
      active = i;
      if (i === null) { hideTip(); return; }
      const it = model.items[i];
      fig.classList.add('has-active');
      segsOf(i).forEach((s) => s.classList.add('is-on'));
      it.targets.forEach((j) => segsOf(j).forEach((s) => s.classList.add('is-target')));
      it.sources.forEach((j) => segsOf(j).forEach((s) => s.classList.add('is-source')));
      bar.querySelector(`[data-part="${it.part}"]`).classList.add('part-on');
      fillTip(sample, model, i);
      placeTip(anchor || segsOf(i)[0]);
      document.getElementById('announce').textContent = `${it.def.label}: ${it.value}`;
    };
    const activatePart = (pi) => {
      if (pinned) return;
      clearMarks();
      hideTip();
      fig.classList.add('has-part');
      grid.querySelectorAll(`.seg[data-part="${pi}"]`).forEach((s) => s.classList.add('part-on'));
      bar.querySelector(`[data-part="${pi}"]`).classList.add('part-on');
    };
    const activateCat = (cat) => {
      if (pinned) return;
      clearMarks();
      fig.classList.add('has-part');
      model.items.filter((it) => it.cat === cat).forEach((it) => segsOf(it.i).forEach((s) => s.classList.add('part-on')));
    };

    grid.addEventListener('pointerover', (e) => {
      const s = e.target.closest('.seg');
      if (!s || (pinned && pinned.grid === grid) || +s.dataset.i === active) return;
      activate(+s.dataset.i, s);
    });
    grid.addEventListener('pointerleave', () => { if (!(pinned && pinned.grid === grid)) activate(null); });
    grid.addEventListener('click', (e) => {
      const s = e.target.closest('.seg');
      if (!s) return;
      const i = +s.dataset.i;
      if (pinned && pinned.grid === grid && pinned.i === i) { pinned = null; activate(i, s); return; }
      pinned = { grid, i };
      activate(i, s);
      tip().classList.add('pinned');
      e.stopPropagation();
    });
    grid.addEventListener('keydown', (e) => {
      const n = model.items.length;
      let i = active === null ? -1 : active;
      if (['ArrowRight', 'ArrowDown'].includes(e.key)) i = (i + 1) % n;
      else if (['ArrowLeft', 'ArrowUp'].includes(e.key)) i = (i - 1 + n) % n;
      else if (e.key === 'Home') i = 0;
      else if (e.key === 'End') i = n - 1;
      else if (e.key === 'Escape') { pinned = null; tip().classList.remove('pinned'); activate(null); return; }
      else return;
      e.preventDefault();
      activate(i);
    });
    grid.addEventListener('blur', () => { if (!pinned) activate(null); });

    bar.addEventListener('pointerover', (e) => { const s = e.target.closest('.bar-seg'); if (s) activatePart(+s.dataset.part); });
    bar.addEventListener('pointerleave', () => { if (!pinned) clearMarks(); });
    legend.addEventListener('pointerover', (e) => { const s = e.target.closest('.leg'); if (s) activateCat(s.dataset.cat); });
    legend.addEventListener('pointerleave', () => { if (!pinned) clearMarks(); });

    viewToggle.addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      viewToggle.querySelectorAll('button').forEach((x) => { x.classList.toggle('on', x === b); x.setAttribute('aria-pressed', x === b); });
      const table = b.dataset.val === 'table';
      if (table) buildTable();
      tableWrap.hidden = !table;
      grid.hidden = table;
      showToggle.hidden = table || !hasText;
    });
    showToggle.addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      showToggle.querySelectorAll('button').forEach((x) => { x.classList.toggle('on', x === b); x.setAttribute('aria-pressed', x === b); });
      const text = b.dataset.val === 'text';
      grid.querySelectorAll('.byte').forEach((sp) => {
        sp.textContent = text && sp.dataset.txt !== undefined ? sp.dataset.txt : sp.dataset.hex;
        sp.classList.toggle('is-char', text && sp.dataset.txt !== undefined);
      });
    });
  }

  /* Global: unpin on outside click or Escape; reposition hides on scroll. */
  document.addEventListener('click', (e) => {
    if (pinned && !e.target.closest('#tip') && !e.target.closest('.bg-grid')) {
      pinned = null;
      tip().classList.remove('pinned');
      hideTip();
      document.querySelectorAll('.bg.has-active').forEach((f) => f.classList.remove('has-active'));
      document.querySelectorAll('.seg.is-on, .seg.is-target, .seg.is-source').forEach((s) => s.classList.remove('is-on', 'is-target', 'is-source'));
    }
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && pinned) { pinned.grid.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })); }
  });
  window.addEventListener('scroll', () => { if (!pinned) hideTip(); }, { passive: true });

  /* ---------- tree view: the same dissection as an expandable outline ---------- */

  function renderTree(mount) {
    const sample = TDS.samples[mount.dataset.tree];
    const model = layout(sample);
    const root = el('div', 'tree');
    sample.parts.forEach((part, pi) => {
      const items = model.items.filter((it) => it.part === pi);
      const d = el('details', 'tree-node');
      const s = el('summary');
      const len = items.reduce((a, it) => a + it.n, 0);
      s.append(el('span', `leg-sw slot-${slotOf(sample, part.cat)}`), el('span', 'tree-name', part.label),
        el('span', 'tree-sum', part.summary || ''), el('span', 'tree-len', `${len} B`));
      d.append(s);
      const list = el('div', 'tree-fields');
      items.forEach((it) => {
        list.append(el('span', 'tf-label', it.def.label),
          el('span', 'tf-bytes mono', it.bytes.length > 8 ? TDS.hexOf(it.bytes.slice(0, 8)) + ' …' : TDS.hexOf(it.bytes)),
          el('span', 'tf-value', it.value));
      });
      d.append(list);
      root.append(d);
    });
    mount.replaceChildren(root);
  }

  TDS.hydrateGrids = function (scope) {
    scope.querySelectorAll('.grid-mount').forEach(render);
    scope.querySelectorAll('[data-tree]').forEach(renderTree);
  };
  TDS.layout = layout;
})();
