/* ==========================================================================
   Document preview for every CV, certificate and grade sheet on the site.
   Fetches the file (with the visitor's token for protected folders), shows
   PDFs page by page with pdf.js and images inline, and offers an optional
   Download button + Open in new tab.
   Exposes window.previewPDF(url, token|null, { title }).
   ========================================================================== */
(function () {
  'use strict';

  const PDFJS_VERSION = '3.11.174';
  const PDFJS_SRC = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${PDFJS_VERSION}/pdf.min.js`;
  const PDFJS_WORKER = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${PDFJS_VERSION}/pdf.worker.min.js`;

  const STR = {
    en: {
      eyebrow: 'Preview',
      fallbackTitle: 'Document',
      loading: 'Loading preview…',
      fail: 'The preview isn\'t available on this device, but you can still open or download the PDF.',
      loadFail: 'Could not load this file. Please try again.',
      download: 'Download PDF',
      downloadImg: 'Download image',
      open: 'Open in new tab',
      close: 'Close preview',
      page: (i, n) => `Page ${i} of ${n}`
    },
    ar: {
      eyebrow: 'معاينة',
      fallbackTitle: 'مستند',
      loading: 'جارٍ تحميل المعاينة…',
      fail: 'المعاينة غير متاحة على هذا الجهاز، لكن يمكنك فتح الملف أو تنزيله.',
      loadFail: 'تعذّر تحميل هذا الملف. يرجى المحاولة مرة أخرى.',
      download: 'تنزيل PDF',
      downloadImg: 'تنزيل الصورة',
      open: 'فتح في تبويب جديد',
      close: 'إغلاق المعاينة',
      page: (i, n) => `الصفحة ${i} من ${n}`
    }
  };
  const lang = () => {
    try { if (typeof currentLanguage !== 'undefined' && currentLanguage === 'ar') return 'ar'; } catch { /* not defined */ }
    return document.documentElement.lang === 'ar' || document.documentElement.dir === 'rtl' ? 'ar' : 'en';
  };
  const t = () => STR[lang()];

  const ICON = {
    close: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true"><path d="M18 6L6 18M6 6l12 12"/></svg>',
    download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12M7 10l5 5 5-5M5 21h14"/></svg>',
    open: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3"/></svg>'
  };

  /* ── pdf.js (lazy, shared with the CV generator if it loaded it first) ── */
  let pdfjsPromise = null;
  function loadPdfJs() {
    if (window.pdfjsLib) {
      if (!window.pdfjsLib.GlobalWorkerOptions.workerSrc) window.pdfjsLib.GlobalWorkerOptions.workerSrc = PDFJS_WORKER;
      return Promise.resolve(window.pdfjsLib);
    }
    if (pdfjsPromise) return pdfjsPromise;
    pdfjsPromise = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = PDFJS_SRC;
      s.crossOrigin = 'anonymous';
      s.referrerPolicy = 'no-referrer';
      s.onload = () => {
        if (!window.pdfjsLib) return reject(new Error('pdf.js missing'));
        window.pdfjsLib.GlobalWorkerOptions.workerSrc = PDFJS_WORKER;
        resolve(window.pdfjsLib);
      };
      s.onerror = () => { pdfjsPromise = null; reject(new Error('pdf.js failed to load')); };
      document.head.appendChild(s);
    });
    return pdfjsPromise;
  }

  /* ── DOM (built once, on first use) ─────────────────────────────────── */
  let overlay, dialog, titleEl, eyebrowEl, pagesEl, dlBtn, openBtn, closeBtn;
  let state = { blobUrl: null, bytes: null, doc: null, kind: 'pdf', fileName: 'document.pdf', lastFocus: null, lockedScroll: false };
  let renderToken = 0, resizeObs = null;

  function build() {
    if (overlay) return;
    overlay = document.createElement('div');
    overlay.className = 'pdfv-overlay';
    overlay.hidden = true;
    overlay.innerHTML = `
      <div class="pdfv" role="dialog" aria-modal="true" aria-labelledby="pdfv-title" tabindex="-1">
        <header class="pdfv-head">
          <div class="pdfv-titles">
            <span class="pdfv-eyebrow"></span>
            <h2 class="pdfv-title" id="pdfv-title"></h2>
          </div>
          <button type="button" class="pdfv-close">${ICON.close}</button>
        </header>
        <div class="pdfv-pages" aria-live="polite"></div>
        <footer class="pdfv-actions">
          <button type="button" class="pdfv-btn pdfv-btn-ghost pdfv-open">${ICON.open}<span></span></button>
          <a class="pdfv-btn pdfv-btn-primary pdfv-download" role="button">${ICON.download}<span></span></a>
        </footer>
      </div>`;
    document.body.appendChild(overlay);
    dialog = overlay.querySelector('.pdfv');
    titleEl = overlay.querySelector('.pdfv-title');
    eyebrowEl = overlay.querySelector('.pdfv-eyebrow');
    pagesEl = overlay.querySelector('.pdfv-pages');
    dlBtn = overlay.querySelector('.pdfv-download');
    openBtn = overlay.querySelector('.pdfv-open');
    closeBtn = overlay.querySelector('.pdfv-close');

    closeBtn.addEventListener('click', close);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
    openBtn.addEventListener('click', () => { if (state.blobUrl) window.open(state.blobUrl, '_blank', 'noopener'); });
    dlBtn.addEventListener('click', (e) => { if (!state.blobUrl) e.preventDefault(); });
    overlay.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); return; }
      if (e.key !== 'Tab') return;
      const f = [...dialog.querySelectorAll('button, a[href]')].filter((el) => !el.disabled && el.offsetParent !== null);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && (document.activeElement === first || document.activeElement === dialog)) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    });
    document.addEventListener('languageChanged', labels);
  }

  function labels() {
    if (!overlay) return;
    const s = t();
    eyebrowEl.textContent = s.eyebrow;
    closeBtn.setAttribute('aria-label', s.close);
    dlBtn.querySelector('span').textContent = state.kind === 'image' ? s.downloadImg : s.download;
    openBtn.querySelector('span').textContent = s.open;
    dialog.dir = lang() === 'ar' ? 'rtl' : 'ltr';
  }

  function setActionsEnabled(on) {
    openBtn.disabled = !on;
    dlBtn.classList.toggle('is-disabled', !on);
    dlBtn.setAttribute('aria-disabled', String(!on));
    if (on) { dlBtn.href = state.blobUrl; dlBtn.download = state.fileName; }
    else { dlBtn.removeAttribute('href'); dlBtn.removeAttribute('download'); }
  }

  function status(text) {
    const p = document.createElement('p');
    p.className = 'pdfv-status';
    p.textContent = text;
    pagesEl.replaceChildren(p);
  }

  /* ── Title / file name from the card that links to this file ─────────── */
  function describe(url) {
    let path = url;
    try { path = new URL(url, location.href).pathname; } catch { /* keep */ }
    const fileName = decodeURIComponent(path.split('/').pop() || 'document.pdf');
    const card = [...document.querySelectorAll('a.cv-modal-card[href]')]
      .find((a) => { try { return new URL(a.href, location.href).pathname === path; } catch { return false; } });
    let title = '';
    if (card) {
      const name = card.querySelector('.cv-card-name')?.textContent.trim();
      const lg = card.querySelector('.cv-card-lang')?.textContent.trim();
      title = [name, lg].filter(Boolean).join(' · ');
    } else {
      // Any other link to this file (certificates, grade sheets…): use its text
      const link = [...document.querySelectorAll('a[href]')]
        .find((a) => { try { return new URL(a.href, location.href).pathname === path && a.textContent.trim(); } catch { return false; } });
      if (link) title = link.textContent.replace(/\s+/g, ' ').replace(/[↗→←]/g, '').trim();
    }
    return { fileName, title: title || fileName.replace(/\.pdf$/i, '') || t().fallbackTitle };
  }

  /* ── Rendering ───────────────────────────────────────────────────────── */
  async function renderPages() {
    const my = ++renderToken;
    try {
      const pdfjs = await loadPdfJs();
      if (!state.doc) state.doc = await pdfjs.getDocument({ data: state.bytes.slice(0) }).promise;
      if (my !== renderToken) return;
      const doc = state.doc;
      const width = Math.max(220, Math.min(pagesEl.clientWidth - 24, 900));
      const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
      const frag = document.createElement('div');
      frag.className = 'pdfv-stack';
      for (let i = 1; i <= doc.numPages; i++) {
        const page = await doc.getPage(i);
        if (my !== renderToken) return;
        const base = page.getViewport({ scale: 1 });
        const scale = width / base.width;
        const vp = page.getViewport({ scale: scale * dpr });
        const canvas = document.createElement('canvas');
        canvas.width = Math.floor(vp.width);
        canvas.height = Math.floor(vp.height);
        canvas.style.width = `${Math.floor(base.width * scale)}px`;
        canvas.style.height = `${Math.floor(base.height * scale)}px`;
        canvas.setAttribute('role', 'img');
        canvas.setAttribute('aria-label', t().page(i, doc.numPages));
        await page.render({ canvasContext: canvas.getContext('2d'), viewport: vp }).promise;
        const fig = document.createElement('figure');
        fig.className = 'pdfv-page';
        fig.appendChild(canvas);
        if (doc.numPages > 1) {
          const cap = document.createElement('figcaption');
          cap.textContent = t().page(i, doc.numPages);
          fig.appendChild(cap);
        }
        frag.appendChild(fig);
        if (i === 1) pagesEl.replaceChildren(frag);   // show page 1 right away, the rest follow
      }
      if (my !== renderToken) return;
      watchResize();
    } catch {
      if (my === renderToken) status(t().fail);
    }
  }

  function watchResize() {
    if (!('ResizeObserver' in window) || resizeObs) return;
    let lastW = pagesEl.clientWidth, timer = null;
    resizeObs = new ResizeObserver(() => {
      const w = pagesEl.clientWidth;
      if (Math.abs(w - lastW) < 24 || overlay.hidden) return;
      lastW = w;
      clearTimeout(timer);
      timer = setTimeout(() => { if (state.kind === 'pdf') renderPages(); }, 180);
    });
    resizeObs.observe(pagesEl);
  }

  /* ── Open / close ───────────────────────────────────────────────────── */
  function cleanup() {
    renderToken++;
    if (state.doc) { try { state.doc.destroy(); } catch { /* ignore */ } }
    if (state.blobUrl) URL.revokeObjectURL(state.blobUrl);
    state.doc = null; state.bytes = null; state.blobUrl = null;
  }

  function close() {
    if (!overlay || overlay.hidden) return;
    overlay.classList.remove('is-open');
    overlay.hidden = true;
    cleanup();
    pagesEl.replaceChildren();
    if (state.lockedScroll) {
      document.body.classList.remove('no-scroll');
      document.documentElement.classList.remove('no-scroll');
      state.lockedScroll = false;
    }
    if (state.lastFocus && typeof state.lastFocus.focus === 'function') state.lastFocus.focus({ preventScroll: true });
  }

  async function previewPDF(url, token, opts = {}) {
    build();
    cleanup();
    labels();
    const info = describe(url);
    state.fileName = info.fileName;
    state.kind = /\.(png|jpe?g|webp|gif)$/i.test(info.fileName) ? 'image' : 'pdf';
    labels();
    titleEl.textContent = (opts.title && String(opts.title).replace(/\s+/g, ' ').replace(/[↗→←]/g, '').trim()) || info.title;
    state.lastFocus = document.activeElement;
    setActionsEnabled(false);
    status(t().loading);

    overlay.hidden = false;
    requestAnimationFrame(() => overlay.classList.add('is-open'));
    if (!document.body.classList.contains('no-scroll')) {
      document.body.classList.add('no-scroll');
      document.documentElement.classList.add('no-scroll');
      state.lockedScroll = true;
    }
    dialog.focus({ preventScroll: true });

    let res;
    try {
      res = await fetch(url, token ? { headers: { Authorization: 'Bearer ' + token } } : {});
    } catch {
      status(t().loadFail);
      return;
    }
    if (res.status === 401) {
      // Session expired: same behaviour as the rest of the site
      localStorage.removeItem('portfolio_token');
      localStorage.removeItem('portfolio_user');
      window.pendingPdfLink = url;
      close();
      if (typeof window.openAuthModal === 'function') window.openAuthModal('login');
      return;
    }
    if (!res.ok) { status(t().loadFail); return; }

    const blob = await res.blob();
    if (overlay.hidden) return;                        // closed while loading
    if (blob.type.startsWith('image/')) state.kind = 'image';
    labels();
    state.bytes = new Uint8Array(await blob.arrayBuffer());
    state.blobUrl = URL.createObjectURL(new Blob([state.bytes], { type: state.kind === 'image' ? (blob.type || 'image/png') : 'application/pdf' }));
    setActionsEnabled(true);
    if (state.kind === 'image') {
      const fig = document.createElement('figure');
      fig.className = 'pdfv-page pdfv-image';
      const img = document.createElement('img');
      img.alt = titleEl.textContent;
      img.decoding = 'async';
      img.src = state.blobUrl;
      img.onerror = () => status(t().fail);
      fig.appendChild(img);
      pagesEl.replaceChildren(fig);
    } else {
      renderPages();
    }
  }

  window.previewPDF = previewPDF;
})();
