/* ==========================================================================
   "Ask Ashfaaq" — free-text AI questions in the existing chatbot panel.
   The quick-question chips (script.js) keep working as before and as the
   fallback when the AI is unavailable.

   Safety: replies are rendered with DOM nodes + textContent only (never
   innerHTML). Links are created only for #sections, mailto: and https URLs,
   which the server has already restricted to the portfolio's own links.
   ========================================================================== */
(function () {
  'use strict';

  const API = '/api';
  const MAX_TURNS = 8;          // user+model messages sent back as context
  const TIMEOUT_MS = 30000;
  const SECTIONS = ['home', 'about', 'education', 'projects', 'fyp', 'expertise', 'connect'];

  const container = document.getElementById('chatbot-container');
  const messages = document.getElementById('chatbot-messages');
  const form = document.getElementById('cb-form');
  const input = document.getElementById('cb-text');
  const send = document.getElementById('cb-send');
  const count = document.getElementById('cb-count');
  if (!container || !messages || !form || !input || !send) return;

  const STR = {
    en: {
      thinking: 'Ashfaaq\'s assistant is typing…',
      error: 'Sorry, I couldn\'t answer that right now. Please try again, or tap a quick question below.',
      rate: 'You\'re sending messages a bit too quickly. Please wait a few minutes and try again.',
      busy: 'The assistant is busy right now. Please try again later, or tap a quick question below.',
      offline: 'You seem to be offline. Please check your connection.',
      blocked: 'I can\'t answer that one. Try asking about Ashfaaq\'s skills, projects or experience.',
      tooLong: (n) => `Please keep your question under ${n} characters.`,
      send: 'Send',
      left: (n) => `${n} left`
    },
    ar: {
      thinking: 'مساعد اشفاق يكتب…',
      error: 'عذراً، لم أتمكن من الإجابة الآن. حاول مرة أخرى أو اضغط على سؤال سريع أدناه.',
      rate: 'أنت ترسل الرسائل بسرعة كبيرة. يرجى الانتظار بضع دقائق ثم المحاولة مرة أخرى.',
      busy: 'المساعد مشغول حالياً. حاول لاحقاً أو اضغط على سؤال سريع أدناه.',
      offline: 'يبدو أنك غير متصل بالإنترنت. يرجى التحقق من الاتصال.',
      blocked: 'لا يمكنني الإجابة على ذلك. جرّب السؤال عن مهارات اشفاق أو مشاريعه أو خبراته.',
      tooLong: (n) => `يرجى ألا يتجاوز سؤالك ${n} حرفاً.`,
      send: 'إرسال',
      left: (n) => `متبقٍ ${n}`
    }
  };

  const lang = () => {
    try { if (typeof currentLanguage !== 'undefined' && currentLanguage === 'ar') return 'ar'; } catch { /* not defined */ }
    return document.documentElement.lang === 'ar' || document.documentElement.dir === 'rtl' ? 'ar' : 'en';
  };
  const t = () => STR[lang()];

  let maxLen = Number(input.getAttribute('maxlength')) || 500;
  let history = [];
  let pending = false;

  /* ── Availability ───────────────────────────────────────────────────── */
  fetch(`${API}/chat/status`, { headers: { Accept: 'application/json' } })
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (!d || !d.enabled) return;
      if (Number(d.maxMessage) > 0) { maxLen = Number(d.maxMessage); input.setAttribute('maxlength', String(maxLen)); }
      form.hidden = false;
      container.classList.add('cb-has-input');
      updateUi();
    })
    .catch(() => { /* stay on quick questions only */ });

  /* ── Safe renderer: tiny markdown subset → DOM ──────────────────────── */
  const INLINE_RE = /\[([^\]\n]+)\]\(([^)\s]+)\)|\*\*([^*\n]+)\*\*|([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/g;

  function closeChat() {
    const btn = document.getElementById('chatbot-minimize');
    if (btn) btn.click();
  }

  function linkNode(label, url) {
    const a = document.createElement('a');
    a.textContent = label;
    if (url.startsWith('#')) {
      const id = url.slice(1);
      if (!SECTIONS.includes(id)) return document.createTextNode(label);
      a.href = url;
      a.addEventListener('click', (e) => {
        if (typeof window.navigateToPage !== 'function' && typeof navigateToPage !== 'function') return;
        e.preventDefault();
        closeChat();                               // unlocks page scrolling first
        setTimeout(() => (window.navigateToPage || navigateToPage)(id), 60);
      });
      return a;
    }
    if (/^mailto:[^\s@]+@[^\s@]+$/i.test(url)) { a.href = url; return a; }
    if (/^https:\/\/[^\s]+$/i.test(url)) {
      a.href = url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer nofollow';
      a.dir = 'ltr';
      return a;
    }
    return document.createTextNode(label);
  }

  function appendInline(parent, text) {
    let last = 0;
    INLINE_RE.lastIndex = 0;
    let m;
    while ((m = INLINE_RE.exec(text))) {
      if (m.index > last) parent.appendChild(document.createTextNode(text.slice(last, m.index)));
      if (m[1] !== undefined) parent.appendChild(linkNode(m[1], m[2]));
      else if (m[3] !== undefined) { const b = document.createElement('strong'); b.textContent = m[3]; parent.appendChild(b); }
      else if (m[4] !== undefined) {
        const a = document.createElement('a'); a.href = `mailto:${m[4]}`; a.textContent = m[4]; a.dir = 'ltr';
        parent.appendChild(a);
      }
      last = INLINE_RE.lastIndex;
    }
    if (last < text.length) parent.appendChild(document.createTextNode(text.slice(last)));
  }

  function renderReply(text) {
    const frag = document.createDocumentFragment();
    let list = null;
    for (const raw of String(text).split('\n')) {
      const line = raw.trim();
      if (!line) { list = null; continue; }
      const bullet = /^(?:[-•*]|\d+[.)])\s+(.*)$/.exec(line);
      if (bullet) {
        if (!list) { list = document.createElement('ul'); frag.appendChild(list); }
        const li = document.createElement('li');
        appendInline(li, bullet[1]);
        list.appendChild(li);
      } else {
        list = null;
        const p = document.createElement('p');
        appendInline(p, line);
        frag.appendChild(p);
      }
    }
    return frag;
  }

  /* ── Messages ───────────────────────────────────────────────────────── */
  function bubble(kind, content) {
    const msg = document.createElement('div');
    msg.className = `chatbot-message chatbot-message-${kind}`;
    const body = document.createElement('div');
    body.className = 'message-content';
    body.dir = 'auto';
    if (typeof content === 'string') { const p = document.createElement('p'); p.textContent = content; body.appendChild(p); }
    else body.appendChild(content);
    msg.appendChild(body);
    messages.appendChild(msg);
    scrollDown();
    return msg;
  }

  function scrollDown() {
    requestAnimationFrame(() => { messages.scrollTop = messages.scrollHeight; });
  }

  function typing() {
    const msg = document.createElement('div');
    msg.className = 'chatbot-message chatbot-message-bot cb-typing-msg';
    msg.innerHTML = '<div class="message-content cb-typing"><span></span><span></span><span></span></div>';
    msg.querySelector('.cb-typing').setAttribute('aria-label', t().thinking);
    msg.querySelector('.cb-typing').setAttribute('role', 'status');
    messages.appendChild(msg);
    scrollDown();
    return msg;
  }

  function errorText(status, code) {
    if (!navigator.onLine) return t().offline;
    if (status === 429) return t().rate;
    if (status === 503) return t().busy;
    if (code === 'BLOCKED') return t().blocked;
    if (code === 'TOO_LONG') return t().tooLong(maxLen);
    return t().error;
  }

  async function ask(question) {
    pending = true;
    updateUi();
    container.classList.add('cb-chatting');
    bubble('user', question);
    const dots = typing();

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let reply = null, status = 0, code = '';
    try {
      const res = await fetch(`${API}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ message: question, lang: lang(), history: history.slice(-MAX_TURNS) }),
        signal: controller.signal
      });
      status = res.status;
      const data = await res.json().catch(() => ({}));
      if (res.ok && typeof data.reply === 'string' && data.reply.trim()) reply = data.reply;
      else code = data.code || '';
    } catch { status = 0; }
    clearTimeout(timer);
    dots.remove();

    if (reply) {
      bubble('bot', renderReply(reply));
      history.push({ role: 'user', text: question }, { role: 'model', text: reply });
      history = history.slice(-MAX_TURNS);
    } else {
      bubble('bot', errorText(status, code)).classList.add('cb-error');
    }
    pending = false;
    updateUi();
  }

  /* ── Input behaviour ────────────────────────────────────────────────── */
  function autosize() {
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 120) + 'px';
  }

  function updateUi() {
    const len = input.value.trim().length;
    send.disabled = pending || !len || input.value.length > maxLen;
    send.setAttribute('aria-label', t().send);
    form.classList.toggle('is-pending', pending);
    const remaining = maxLen - input.value.length;
    if (count) count.textContent = remaining <= 80 ? t().left(Math.max(0, remaining)) : '';
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const q = input.value.trim();
    if (!q || pending || q.length > maxLen) return;
    input.value = '';
    autosize();
    ask(q);
  });

  input.addEventListener('input', () => { autosize(); updateUi(); });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && e.keyCode !== 229) {
      e.preventDefault();
      form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event('submit', { cancelable: true }));
    }
  });

  // Quick-question chips: keep them in the AI's context so follow-ups work
  // ("tell me more about that"). Answers come from the site's own FAQ text.
  const faq = document.getElementById('chatbot-faq-container');
  if (faq) {
    faq.addEventListener('click', (e) => {
      const chip = e.target.closest('.cb-chip');
      if (!chip) return;
      try {
        const key = chip.getAttribute('data-faq');
        const label = (chip.querySelector('span:not(.cb-chip-icon)') || chip).textContent.trim();
        const html = window.translations?.[lang()]?.chatbot?.answers?.[key];
        if (!html) return;
        const tmp = document.createElement('template');
        tmp.innerHTML = html;                     // inert: <template> content never runs or loads
        const text = tmp.content.textContent.replace(/\s+/g, ' ').trim().slice(0, 1500);
        history.push({ role: 'user', text: label }, { role: 'model', text });
        history = history.slice(-MAX_TURNS);
      } catch { /* context is optional */ }
    });
  }

  // Language switch: refresh labels
  document.addEventListener('languageChanged', updateUi);

  // Focus the input when the panel opens on devices with a real keyboard
  const toggle = document.getElementById('chatbot-toggle');
  if (toggle) {
    toggle.addEventListener('click', () => {
      if (form.hidden || window.matchMedia('(pointer: coarse)').matches) return;
      setTimeout(() => input.focus({ preventScroll: true }), 450);
    });
  }

  /* ── Phones: keep the panel above the on-screen keyboard ────────────── */
  const vv = window.visualViewport;
  if (vv) {
    const reset = () => { container.style.removeProperty('top'); container.style.removeProperty('height'); container.style.removeProperty('max-height'); };
    const fit = () => {
      if (!container.classList.contains('open') || window.innerWidth > 480) return reset();
      const keyboardOpen = vv.height < window.innerHeight * 0.78;
      if (!keyboardOpen) return reset();
      const h = Math.max(220, vv.height - 16);
      container.style.top = `${vv.offsetTop + vv.height / 2}px`;
      container.style.height = `${h}px`;
      container.style.maxHeight = `${h}px`;
      scrollDown();
    };
    vv.addEventListener('resize', fit);
    vv.addEventListener('scroll', fit);
    input.addEventListener('blur', () => setTimeout(fit, 150));
  }

  updateUi();
})();
