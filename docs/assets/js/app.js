/* ============================================================
   CrowdControl docs — shell rendering, theme, TOC, code copy
   ============================================================ */

const NAV = [
  {
    title: 'Get started',
    items: [
      { href: 'index.html', label: 'Overview' },
      { href: 'introduction.html', label: 'What is CrowdControl' },
      { href: 'quickstart.html', label: 'Quickstart' },
      { href: 'installation.html', label: 'Installation' },
      { href: 'playground.html', label: 'Playground', tag: 'beta' },
    ],
  },
  {
    title: 'Language',
    items: [
      { href: 'language.html', label: 'Language reference' },
      { href: 'conditions.html', label: 'Conditions & operators' },
      { href: 'schema.html', label: 'Schema validation' },
      { href: 'explain.html', label: 'Explain mode' },
    ],
  },
  {
    title: 'Guides',
    items: [
      { href: 'examples.html', label: 'Example policies' },
      { href: 'embedding.html', label: 'Embedding in Go' },
      { href: 'cli.html', label: 'CLI reference' },
      { href: 'serve.html', label: 'cc serve (HTTP PDP)', tag: 'new' },
    ],
  },
  {
    title: 'SDKs',
    items: [
      { href: 'sdks.html', label: 'SDK overview' },
      { href: 'conformance.html', label: 'Conformance suite' },
    ],
  },
  {
    title: 'Compare',
    items: [
      { href: 'comparison.html', label: 'vs CEDAR / Cerbos / Rego' },
      { href: 'when-to-use.html', label: 'When to use CrowdControl' },
    ],
  },
];

const GH_REPO = 'https://github.com/mikemackintosh/crowdcontrol';

/* ---------- theme toggle ----------------------------------- */
function initTheme() {
  const stored = localStorage.getItem('cc-theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const theme = stored || (prefersDark ? 'dark' : 'dark'); // dark default
  document.documentElement.setAttribute('data-theme', theme);
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme');
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('cc-theme', next);
  updateThemeIcon();
}
function updateThemeIcon() {
  const btn = document.getElementById('theme-btn');
  if (!btn) return;
  const dark = document.documentElement.getAttribute('data-theme') === 'dark';
  btn.innerHTML = dark ? ICONS.sun : ICONS.moon;
}

/* ---------- icons ------------------------------------------ */
const ICONS = {
  logo: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>`,
  github: `<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 .5C5.65.5.5 5.65.5 12a11.5 11.5 0 0 0 7.86 10.91c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.36-3.88-1.36-.52-1.32-1.28-1.68-1.28-1.68-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.76 2.7 1.25 3.36.96.1-.75.4-1.26.73-1.55-2.56-.29-5.24-1.28-5.24-5.7 0-1.26.45-2.28 1.19-3.08-.12-.3-.52-1.48.11-3.08 0 0 .98-.31 3.2 1.18a11.1 11.1 0 0 1 5.82 0c2.22-1.5 3.19-1.18 3.19-1.18.64 1.6.24 2.78.12 3.08.74.8 1.19 1.82 1.19 3.08 0 4.43-2.69 5.4-5.25 5.69.41.35.78 1.05.78 2.12v3.15c0 .31.21.67.8.56A11.5 11.5 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5z"/></svg>`,
  sun: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>`,
  moon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  menu: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18M3 12h18M3 18h18"/></svg>`,
  copy: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg>`,
  link: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
  arrow: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>`,
};

/* ---------- header ----------------------------------------- */
function renderHeader() {
  const header = document.createElement('header');
  header.className = 'site-header';
  const currentPage = location.pathname.split('/').pop() || 'index.html';
  header.innerHTML = `
    <a href="index.html" class="brand">
      <span class="logo">${ICONS.logo}</span>
      <span>CrowdControl</span>
    </a>
    <nav class="top-nav">
      <a href="introduction.html" ${currentPage === 'introduction.html' ? 'class="active"' : ''}>Docs</a>
      <a href="language.html" ${currentPage === 'language.html' ? 'class="active"' : ''}>Language</a>
      <a href="comparison.html" ${currentPage === 'comparison.html' ? 'class="active"' : ''}>Compare</a>
      <a href="sdks.html" ${currentPage === 'sdks.html' ? 'class="active"' : ''}>SDKs</a>
    </nav>
    <div class="spacer"></div>
    <div class="header-actions">
      <button class="header-btn mobile-menu-btn" id="menu-btn" aria-label="Toggle sidebar">${ICONS.menu}</button>
      <a href="${GH_REPO}" class="github-link" target="_blank" rel="noopener">${ICONS.github}<span>GitHub</span></a>
      <span class="divider"></span>
      <button class="header-btn" id="theme-btn" aria-label="Toggle theme">${ICONS.sun}</button>
    </div>
  `;
  document.body.prepend(header);

  document.getElementById('theme-btn').addEventListener('click', toggleTheme);
  document.getElementById('menu-btn').addEventListener('click', () => {
    document.body.classList.toggle('sidebar-open');
  });
  updateThemeIcon();
}

/* ---------- sidebar ---------------------------------------- */
function renderSidebar() {
  const side = document.getElementById('sidebar');
  if (!side) return;
  const currentPage = location.pathname.split('/').pop() || 'index.html';

  side.innerHTML = NAV.map(section => `
    <div class="sidebar-section">
      <div class="sidebar-section-title">${section.title}</div>
      ${section.items.map(item => `
        <a href="${item.href}" class="sidebar-item ${item.href === currentPage ? 'active' : ''}">
          ${item.label}
          ${item.tag ? `<span class="tag">${item.tag}</span>` : ''}
        </a>
      `).join('')}
    </div>
  `).join('');
}

/* ---------- toc (right rail) ------------------------------- */
function renderToc() {
  const toc = document.getElementById('toc');
  if (!toc) return;
  const article = document.querySelector('article.doc');
  if (!article) return;
  const headings = article.querySelectorAll('h2, h3');
  if (headings.length === 0) { toc.style.display = 'none'; return; }

  const items = [...headings].map(h => {
    if (!h.id) {
      h.id = h.textContent.toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .trim()
        .replace(/\s+/g, '-');
    }
    // add anchor icon
    const anchor = document.createElement('a');
    anchor.href = `#${h.id}`;
    anchor.className = 'anchor';
    anchor.textContent = '#';
    h.appendChild(anchor);
    return { id: h.id, text: h.textContent.replace(/#$/, '').trim(), level: h.tagName.toLowerCase() };
  });

  toc.innerHTML = `
    <div class="toc-title">On this page</div>
    <ul>
      ${items.map(i => `<li><a href="#${i.id}" class="${i.level === 'h3' ? 'toc-h3' : ''}">${i.text}</a></li>`).join('')}
    </ul>
  `;

  // scroll spy
  const links = toc.querySelectorAll('a');
  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        links.forEach(l => l.classList.remove('active'));
        const active = toc.querySelector(`a[href="#${entry.target.id}"]`);
        if (active) active.classList.add('active');
      }
    });
  }, { rootMargin: '-80px 0% -70% 0%' });
  headings.forEach(h => observer.observe(h));
}

/* ---------- code copy buttons ------------------------------ */
function decorateCodeBlocks() {
  document.querySelectorAll('article.doc pre').forEach(pre => {
    const code = pre.querySelector('code');
    if (!code) return;
    const lang = [...code.classList].find(c => c.startsWith('language-'));
    if (lang) {
      const tag = document.createElement('span');
      tag.className = 'code-lang';
      tag.textContent = lang.replace('language-', '');
      pre.appendChild(tag);
    }
    const btn = document.createElement('button');
    btn.className = 'copy-btn';
    btn.innerHTML = ICONS.copy;
    btn.setAttribute('aria-label', 'Copy code');
    btn.addEventListener('click', async () => {
      await navigator.clipboard.writeText(code.textContent);
      btn.innerHTML = ICONS.check;
      btn.classList.add('copied');
      setTimeout(() => {
        btn.innerHTML = ICONS.copy;
        btn.classList.remove('copied');
      }, 1500);
    });
    pre.appendChild(btn);
  });
}

/* ---------- footer ----------------------------------------- */
function renderFooter() {
  const footer = document.createElement('footer');
  footer.className = 'site-footer';
  footer.innerHTML = `
    <p>
      CrowdControl is open source under the
      <a href="${GH_REPO}/blob/main/LICENSE" target="_blank" rel="noopener">MIT license</a>.
      &nbsp;·&nbsp;
      <a href="${GH_REPO}" target="_blank" rel="noopener">GitHub</a>
      &nbsp;·&nbsp;
      <a href="${GH_REPO}/issues" target="_blank" rel="noopener">Issues</a>
    </p>
  `;
  document.body.appendChild(footer);
}

/* ---------- init ------------------------------------------- */
document.addEventListener('DOMContentLoaded', () => {
  renderHeader();
  renderSidebar();
  renderToc();
  decorateCodeBlocks();
  renderFooter();

  // syntax highlight after decoration
  if (window.Prism) {
    window.Prism.highlightAll();
  }
});

// run theme before DOMContentLoaded to avoid flash
initTheme();
