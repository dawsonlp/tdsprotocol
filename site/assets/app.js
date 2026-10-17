/* app.js — routing, navigation, page chrome, glossary hovers and theme. */
(function () {
  'use strict';
  const TDS = window.TDS;
  const $ = (s, r = document) => r.querySelector(s);

  const KIND = { concept: 'Concept', example: 'Worked example', reference: 'Reference', procedure: 'Procedure', decision: 'Decisions', check: 'Checks', explanation: 'Explanation' };
  const visited = new Set(JSON.parse(localStorage.getItem('tds-visited') || '[]'));

  /* ---------- navigation ---------- */

  function buildNav(current) {
    const groups = [];
    TDS.pages.forEach((p) => {
      let g = groups.find((x) => x.name === p.group);
      if (!g) groups.push((g = { name: p.group, pages: [] }));
      g.pages.push(p);
    });
    const done = TDS.pages.filter((p) => visited.has(p.id)).length;
    $('.sidebar').innerHTML = `
      <div class="progress" title="Pages you've opened">
        <div class="progress-bar"><span style="width:${(100 * done) / TDS.pages.length}%"></span></div>
        <div class="progress-text">${done} of ${TDS.pages.length} read</div>
      </div>
      ${groups
        .map((g) => `<div class="nav-group"><div class="nav-group-name">${g.name}</div>${g.pages
          .map((p) => `<a class="nav-link${p.id === current ? ' current' : ''}${visited.has(p.id) ? ' seen' : ''}" href="#/${p.id}"${p.id === current ? ' aria-current="page"' : ''}>
              <span class="nav-num">${p.num || ''}</span><span class="nav-title">${p.title}</span><span class="nav-seen" aria-hidden="true"></span></a>`)
          .join('')}</div>`)
        .join('')}`;
  }

  /* ---------- page rendering ---------- */

  function route() {
    const parts = location.hash.replace(/^#\/?/, '').split('/');
    let id = parts[0] || TDS.pages[0].id;
    let anchor = parts.slice(1).join('/');
    if (parts[0] === 'ref' || parts[0] === 'design') { id = parts.slice(0, 2).join('/'); anchor = parts.slice(2).join('/'); }
    const page = TDS.pages.find((p) => p.id === id) || TDS.pages[0];
    if (page === shown && anchor) { scrollToAnchor(anchor); return; }
    shown = page;
    render(page, anchor);
  }
  let shown = null;

  function scrollToAnchor(anchor) {
    const target = document.getElementById(anchor);
    if (!target) return false;
    target.scrollIntoView({ behavior: 'smooth' });
    target.classList.add('flash');
    setTimeout(() => target.classList.remove('flash'), 1600);
    return true;
  }

  function render(page, anchor) {
    visited.add(page.id);
    localStorage.setItem('tds-visited', JSON.stringify([...visited]));
    buildNav(page.id);
    document.title = `${page.title} · TDS Client Design`;

    const idx = TDS.pages.indexOf(page);
    const prev = TDS.pages[idx - 1], next = TDS.pages[idx + 1];
    const main = $('#main');
    main.innerHTML = `
      <header class="page-head">
        <div class="kind">${page.num ? `<span class="kind-num">${page.num}</span>` : ''}${KIND[page.kind] || ''}</div>
        <h1>${page.title}</h1>
        ${page.where || page.outcome ? `<div class="orient">
          ${page.where ? `<div><span class="orient-k">Where this sits</span>${page.where}</div>` : ''}
          ${page.outcome ? `<div><span class="orient-k">${page.kind === 'reference' ? 'Use this page to' : 'After reading this you can'}</span>${page.outcome}</div>` : ''}
        </div>` : ''}
      </header>
      <article class="content">${page.body()}</article>
      <nav class="pager">
        ${prev ? `<a class="pager-prev" href="#/${prev.id}"><span>Previous</span>${prev.title}</a>` : '<span></span>'}
        ${next ? `<a class="pager-next" href="#/${next.id}"><span>Next</span>${next.title}</a>` : '<span></span>'}
      </nav>`;

    // Give every h2 an id so it can be linked and listed.
    main.querySelectorAll('.content h2, .content h3[id]').forEach((h) => {
      if (!h.id) h.id = h.textContent.toLowerCase().replace(/[^\w]+/g, '-').replace(/^-|-$/g, '');
    });
    buildToc(main);
    TDS.hydrateGrids(main);
    TDS.hydrateComponents(main);
    if (page.after) page.after(main);

    if (anchor && scrollToAnchor(anchor)) return;
    window.scrollTo(0, 0);
    main.focus({ preventScroll: true });
  }

  function buildToc(main) {
    const hs = [...main.querySelectorAll('.content h2')];
    const toc = $('.toc');
    if (hs.length < 3) { toc.innerHTML = ''; return; }
    const label = (h) => { const c = h.cloneNode(true); c.querySelectorAll('.badge, .dref').forEach((x) => x.remove()); return c.textContent.replace(/[–\s]+$/, '').trim(); };
    toc.innerHTML = `<div class="toc-title">On this page</div>${hs.map((h) => `<a href="#/${currentId()}/${h.id}">${TDS.esc(label(h))}</a>`).join('')}`;
    const links = [...toc.querySelectorAll('a')];
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (en.isIntersecting) links.forEach((a) => a.classList.toggle('on', a.getAttribute('href').endsWith('/' + en.target.id)));
      });
    }, { rootMargin: '-15% 0px -75% 0px' });
    hs.forEach((h) => obs.observe(h));
  }
  const currentId = () => {
    const parts = location.hash.replace(/^#\/?/, '').split('/');
    return parts[0] === 'ref' || parts[0] === 'design' ? parts.slice(0, 2).join('/') : parts[0] || TDS.pages[0].id;
  };

  /* ---------- glossary hovers ---------- */

  function showTerm(span) {
    const def = TDS.glossary[span.dataset.term];
    if (!def) return;
    const t = $('#tip');
    if (t.classList.contains('pinned')) return;
    t.replaceChildren();
    t.dataset.slot = '';
    const h = document.createElement('div');
    h.className = 'tip-term';
    h.textContent = span.dataset.term;
    const p = document.createElement('p');
    p.className = 'tip-meaning';
    p.textContent = def;
    const f = document.createElement('div');
    f.className = 'tip-foot';
    const a = document.createElement('a');
    a.href = '#/model/vocabulary';
    a.textContent = 'Vocabulary ›';
    f.append(a);
    t.append(h, p, f);
    t.hidden = false;
    const r = span.getBoundingClientRect();
    const tw = t.offsetWidth, th = t.offsetHeight;
    let top = r.bottom + 8;
    if (top + th > innerHeight - 8) top = r.top - th - 8;
    t.style.left = `${Math.min(Math.max(r.left, 8), innerWidth - tw - 8)}px`;
    t.style.top = `${top}px`;
    t.classList.add('show');
  }
  function hideTerm() { const t = $('#tip'); if (!t.classList.contains('pinned')) { t.classList.remove('show'); t.hidden = true; } }
  document.addEventListener('pointerover', (e) => { const s = e.target.closest('.term'); if (s) showTerm(s); });
  document.addEventListener('pointerout', (e) => { if (e.target.closest('.term')) hideTerm(); });
  document.addEventListener('focusin', (e) => { if (e.target.classList && e.target.classList.contains('term')) showTerm(e.target); });
  document.addEventListener('focusout', (e) => { if (e.target.classList && e.target.classList.contains('term')) hideTerm(); });

  /* ---------- theme ---------- */

  const themes = ['auto', 'light', 'dark'];
  const toggle = $('.theme-toggle');
  const paintToggle = () => {
    const t = document.documentElement.dataset.theme || 'auto';
    toggle.dataset.mode = t;
    toggle.textContent = { auto: 'Auto', light: 'Light', dark: 'Dark' }[t];
  };
  toggle.addEventListener('click', () => {
    const cur = document.documentElement.dataset.theme || 'auto';
    const nxt = themes[(themes.indexOf(cur) + 1) % themes.length];
    if (nxt === 'auto') { delete document.documentElement.dataset.theme; localStorage.removeItem('tds-theme'); }
    else { document.documentElement.dataset.theme = nxt; localStorage.setItem('tds-theme', nxt); }
    paintToggle();
  });
  paintToggle();

  window.addEventListener('hashchange', route);
  route();
})();
