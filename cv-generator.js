/* ==========================================================================
   Tailored ATS CV generator — front end
   --------------------------------------------------------------------------
   Opens from the "Generate a tailored ATS CV" card in the Resume modal.
   Sign-in required. Form → POST /api/cv/generate → PDF preview (pdf.js)
   → download. Works in EN/AR (RTL), light/dark, and every screen size.
   ========================================================================== */
(function () {
  'use strict';

  const API = '/api';
  const PDFJS_VERSION = '3.11.174';
  const PDFJS_SRC = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${PDFJS_VERSION}/pdf.min.js`;
  const PDFJS_WORKER = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/${PDFJS_VERSION}/pdf.worker.min.js`;
  const DRAFT_KEY = 'cvgen-draft-v1';
  const JD_MIN = 80, JD_MAX = 8000;

  /* ── i18n ─────────────────────────────────────────────────────────────── */
  const STR = {
    en: {
      eyebrow: 'AI · Beta', title: 'Tailored ATS CV', close: 'Close',
      quota: (r, l) => `${r} of ${l} left this month`, quotaNone: 'No generations left this month',
      intro: "Tell us about the role. Ashfaaq's CV is rebuilt around it using only his verified portfolio facts — skills he doesn't have are never added; you'll see them listed as gaps instead.",
      jobTitle: 'Job title', jobTitlePh: 'e.g. Junior MERN Stack Developer',
      company: 'Company', companyPh: 'e.g. Riyadh Tech Co',
      jd: 'Job description', jdPh: 'Paste the full job description — responsibilities, requirements, nice-to-haves…',
      jdCount: (n) => `${n.toLocaleString('en')} / ${JD_MAX.toLocaleString('en')}`,
      jdShort: (n) => `Add at least ${n} more characters`,
      skills: 'Must-have skills', optional: 'optional', skillsPh: 'Type a skill and press Enter', skillsHint: 'Up to 15. Press Enter or comma to add.',
      seniority: 'Seniority', sen: { any: 'Any', intern: 'Intern', junior: 'Junior', mid: 'Mid', senior: 'Senior' },
      workMode: 'Work mode', mode: { any: 'Any', remote: 'Remote', hybrid: 'Hybrid', onsite: 'Onsite' },
      language: 'CV language', length: 'Length', page1: '1 page', page2: '2 pages',
      consent: 'I understand this CV is AI-tailored (Beta) from verified portfolio data, and that this request is stored for 12 months as described in the',
      privacy: 'Privacy Policy',
      generate: 'Generate CV', uses: 'Uses 1 of your monthly generations',
      required: 'Required',
      steps: ['Reading the job description', "Matching Ashfaaq's verified profile", 'Writing & fact-checking every line', 'Laying out your PDF'],
      generating: 'Generating your CV…', generatingSub: 'Usually 10–20 seconds. You can keep this open.',
      matched: 'Matches the role', missing: 'Not in his profile', missingNote: "Listed honestly — these were not added to the CV.",
      none: 'None listed',
      download: 'Download PDF', openPdf: 'Open PDF', newCv: 'New CV', edit: 'Edit details',
      ref: 'Reference', pages: (n) => (n === 1 ? '1 page' : `${n} pages`),
      previewLoading: 'Rendering preview…', previewFail: "Preview isn't available on this device — use Download or Open PDF.",
      page: (i, n) => `Page ${i} of ${n}`,
      signInTitle: 'Sign in to continue', signInBody: 'The CV generator is available to signed-in visitors.',
      limitTitle: 'Monthly limit reached', limitBody: (d) => `You've used all 3 tailored CVs for this month. Your limit resets on ${d}.`,
      offTitle: 'Temporarily unavailable', offBody: 'The CV generator is offline right now. Please try again later — the standard CVs are still available.',
      errTitle: "Couldn't generate the CV",
      backToForm: 'Back to form', retry: 'Try again',
      downloaded: 'CV downloaded', confirmClose: 'Your CV is still being generated. Close anyway? It will be ready here when you come back.',
      errors: {
        INVALID_JOB_TITLE: 'Please enter a job title (2–100 characters, no < > { } symbols).',
        INVALID_COMPANY: 'Please enter the company name (2–100 characters, no < > { } symbols).',
        JOB_DESCRIPTION_TOO_SHORT: `The job description needs at least ${JD_MIN} characters.`,
        JOB_DESCRIPTION_TOO_LONG: `The job description can be at most ${JD_MAX.toLocaleString('en')} characters.`,
        INVALID_SKILLS: 'Skills: up to 15, each under 40 characters, no < > { } symbols.',
        CONSENT_REQUIRED: 'Please tick the confirmation box.',
        QUOTA: "You've used all your CV generations for this month.",
        BUSY: 'A CV is already being generated for you. Please wait a moment.',
        DAILY_CAP: 'The generator has reached its daily limit. Please try again tomorrow.',
        DISABLED: 'The CV generator is temporarily unavailable.',
        RATE_LIMITED: 'Too many requests. Please try again later.',
        AUTH: 'Your session has expired. Please sign in again.',
        NETWORK: 'Network problem — check your connection and try again. This attempt was not counted.',
        DEFAULT: 'Something went wrong on our side. This attempt was not counted — please try again.'
      }
    },
    ar: {
      eyebrow: 'ذكاء اصطناعي · تجريبي', title: 'سيرة ذاتية مخصصة متوافقة مع ATS', close: 'إغلاق',
      quota: (r, l) => `متبقٍ ${r} من ${l} هذا الشهر`, quotaNone: 'لا توجد محاولات متبقية هذا الشهر',
      intro: 'أخبرنا عن الوظيفة. تُعاد صياغة سيرة أشفاق الذاتية حولها باستخدام حقائق ملفه الموثقة فقط — لا تُضاف أي مهارة لا يملكها؛ بل ستظهر لك كفجوات.',
      jobTitle: 'المسمى الوظيفي', jobTitlePh: 'مثال: مطور MERN Stack مبتدئ',
      company: 'الشركة', companyPh: 'مثال: شركة تقنية الرياض',
      jd: 'الوصف الوظيفي', jdPh: 'الصق الوصف الوظيفي كاملاً — المهام، المتطلبات، المزايا الإضافية…',
      jdCount: (n) => `${n.toLocaleString('en')} / ${JD_MAX.toLocaleString('en')}`,
      jdShort: (n) => `أضف ${n} حرفاً على الأقل`,
      skills: 'المهارات الأساسية', optional: 'اختياري', skillsPh: 'اكتب مهارة واضغط Enter', skillsHint: 'حتى 15 مهارة. اضغط Enter أو فاصلة للإضافة.',
      seniority: 'المستوى', sen: { any: 'أي مستوى', intern: 'متدرب', junior: 'مبتدئ', mid: 'متوسط', senior: 'خبير' },
      workMode: 'نمط العمل', mode: { any: 'أي نمط', remote: 'عن بُعد', hybrid: 'هجين', onsite: 'حضوري' },
      language: 'لغة السيرة', length: 'الطول', page1: 'صفحة واحدة', page2: 'صفحتان',
      consent: 'أفهم أن هذه السيرة مخصصة بالذكاء الاصطناعي (نسخة تجريبية) من بيانات الملف الموثقة، وأن هذا الطلب يُحفظ لمدة 12 شهراً كما هو موضح في',
      privacy: 'سياسة الخصوصية',
      generate: 'إنشاء السيرة الذاتية', uses: 'يستهلك محاولة واحدة من رصيدك الشهري',
      required: 'مطلوب',
      steps: ['قراءة الوصف الوظيفي', 'مطابقة ملف أشفاق الموثق', 'كتابة كل سطر والتحقق منه', 'تنسيق ملف PDF'],
      generating: 'جارٍ إنشاء السيرة الذاتية…', generatingSub: 'يستغرق عادةً من 10 إلى 20 ثانية. يمكنك إبقاء هذه النافذة مفتوحة.',
      matched: 'يطابق متطلبات الوظيفة', missing: 'غير موجود في ملفه', missingNote: 'معروضة بأمانة — لم تُضَف إلى السيرة الذاتية.',
      none: 'لا يوجد',
      download: 'تنزيل PDF', openPdf: 'فتح PDF', newCv: 'سيرة جديدة', edit: 'تعديل البيانات',
      ref: 'المرجع', pages: (n) => (n === 1 ? 'صفحة واحدة' : 'صفحتان'),
      previewLoading: 'جارٍ عرض المعاينة…', previewFail: 'المعاينة غير متاحة على هذا الجهاز — استخدم التنزيل أو فتح PDF.',
      page: (i, n) => `الصفحة ${i} من ${n}`,
      signInTitle: 'سجّل الدخول للمتابعة', signInBody: 'مولّد السيرة الذاتية متاح للزوار المسجلين.',
      limitTitle: 'تم بلوغ الحد الشهري', limitBody: (d) => `لقد استخدمت جميع المحاولات الثلاث لهذا الشهر. يتجدد رصيدك في ${d}.`,
      offTitle: 'غير متاح مؤقتاً', offBody: 'مولّد السيرة الذاتية غير متاح حالياً. حاول لاحقاً — السير الذاتية القياسية لا تزال متاحة.',
      errTitle: 'تعذّر إنشاء السيرة الذاتية',
      backToForm: 'العودة إلى النموذج', retry: 'إعادة المحاولة',
      downloaded: 'تم تنزيل السيرة الذاتية', confirmClose: 'لا يزال إنشاء السيرة جارياً. هل تريد الإغلاق؟ ستجدها هنا جاهزة عند عودتك.',
      errors: {
        INVALID_JOB_TITLE: 'يرجى إدخال المسمى الوظيفي (2–100 حرف، بدون الرموز < > { }).',
        INVALID_COMPANY: 'يرجى إدخال اسم الشركة (2–100 حرف، بدون الرموز < > { }).',
        JOB_DESCRIPTION_TOO_SHORT: `يجب ألا يقل الوصف الوظيفي عن ${JD_MIN} حرفاً.`,
        JOB_DESCRIPTION_TOO_LONG: `يجب ألا يزيد الوصف الوظيفي عن ${JD_MAX} حرف.`,
        INVALID_SKILLS: 'المهارات: حتى 15 مهارة، كل منها أقل من 40 حرفاً، بدون الرموز < > { }.',
        CONSENT_REQUIRED: 'يرجى تحديد مربع التأكيد.',
        QUOTA: 'لقد استخدمت جميع محاولات هذا الشهر.',
        BUSY: 'يتم إنشاء سيرة ذاتية لك بالفعل. يرجى الانتظار قليلاً.',
        DAILY_CAP: 'بلغ المولّد حده اليومي. يرجى المحاولة غداً.',
        DISABLED: 'مولّد السيرة الذاتية غير متاح مؤقتاً.',
        RATE_LIMITED: 'طلبات كثيرة. يرجى المحاولة لاحقاً.',
        AUTH: 'انتهت جلستك. يرجى تسجيل الدخول مرة أخرى.',
        NETWORK: 'مشكلة في الاتصال — تحقق من الشبكة وحاول مجدداً. لم تُحتسب هذه المحاولة.',
        DEFAULT: 'حدث خطأ من جهتنا. لم تُحتسب هذه المحاولة — يرجى المحاولة مجدداً.'
      }
    }
  };
  const lang = () => (window.currentLanguage === 'ar' || document.documentElement.lang === 'ar' ? 'ar' : 'en');
  const t = () => STR[lang()];

  /* ── Helpers ──────────────────────────────────────────────────────────── */
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const token = () => { try { return localStorage.getItem('portfolio_token'); } catch { return null; } };
  const store = {
    get(k) { try { return JSON.parse(sessionStorage.getItem(k) || 'null'); } catch { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } },
    del(k) { try { sessionStorage.removeItem(k); } catch { /* ignore */ } }
  };
  const fmtDate = (iso) => {
    try {
      return new Intl.DateTimeFormat(lang() === 'ar' ? 'ar-SA-u-nu-latn-ca-gregory' : 'en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).format(new Date(iso));
    } catch { return iso.slice(0, 10); }
  };
  const reduceMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  async function api(path, opts = {}) {
    const res = await fetch(API + path, {
      ...opts,
      headers: { 'Content-Type': 'application/json', ...(token() ? { Authorization: 'Bearer ' + token() } : {}), ...(opts.headers || {}) }
    });
    let data = {};
    try { data = await res.json(); } catch { /* non-JSON */ }
    if (res.status === 401) data.code = 'AUTH';
    if (res.status === 429 && !data.code) data.code = 'RATE_LIMITED';
    return { ok: res.ok, status: res.status, data };
  }

  /* ── State ────────────────────────────────────────────────────────────── */
  const state = {
    view: 'form',          // form | loading | preview | error | signin | limit | off
    quota: null,
    skills: [],
    generating: false,
    result: null,          // { ref, fileName, pages, match, blob, url }
    error: null,
    lastFocus: null,
    pdfDoc: null
  };

  let overlay, dialog, body, stepTimer = null, resizeObs = null, renderToken = 0;

  /* ── DOM ──────────────────────────────────────────────────────────────── */
  function build() {
    overlay = document.createElement('div');
    overlay.className = 'cvgen-overlay';
    overlay.id = 'cvgen-overlay';
    overlay.hidden = true;
    overlay.innerHTML = `
      <div class="cvgen" role="dialog" aria-modal="true" aria-labelledby="cvgen-title" tabindex="-1">
        <header class="cvgen-head">
          <div class="cvgen-head-titles">
            <span class="cvgen-eyebrow" data-k="eyebrow"></span>
            <h2 class="cvgen-title" id="cvgen-title" data-k="title"></h2>
          </div>
          <span class="cvgen-quota" id="cvgen-quota" hidden></span>
          <button type="button" class="cvgen-close" id="cvgen-close">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>
          </button>
        </header>
        <div class="cvgen-body" id="cvgen-body"></div>
      </div>`;
    document.body.appendChild(overlay);
    dialog = $('.cvgen', overlay);
    body = $('#cvgen-body', overlay);

    $('#cvgen-close', overlay).addEventListener('click', requestClose);
    overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) requestClose(); });
    overlay.addEventListener('keydown', onKeydown);
  }

  function applyChrome() {
    const s = t();
    overlay.setAttribute('dir', lang() === 'ar' ? 'rtl' : 'ltr');
    overlay.setAttribute('lang', lang());
    overlay.querySelectorAll('[data-k]').forEach((el) => { el.textContent = s[el.dataset.k]; });
    $('#cvgen-close', overlay).setAttribute('aria-label', s.close);
    const q = $('#cvgen-quota', overlay);
    if (state.quota) {
      q.hidden = false;
      q.textContent = state.quota.remaining > 0 ? s.quota(state.quota.remaining, state.quota.limit) : s.quotaNone;
      q.classList.toggle('is-empty', state.quota.remaining <= 0);
    } else q.hidden = true;
    dialog.dataset.view = state.view;
  }

  /* ── Views ────────────────────────────────────────────────────────────── */
  function render() {
    applyChrome();
    stopSteps();
    const v = state.view;
    if (v === 'form') renderForm();
    else if (v === 'loading') renderLoading();
    else if (v === 'preview') renderPreview();
    else renderMessage(v);
  }

  function radios(name, options, checked) {
    return `<div class="cvgen-seg" role="radiogroup">${options.map(([value, label]) => `
      <label class="cvgen-seg-opt">
        <input type="radio" name="${name}" value="${value}" ${String(value) === String(checked) ? 'checked' : ''}>
        <span>${esc(label)}</span>
      </label>`).join('')}</div>`;
  }

  function renderForm() {
    const s = t();
    const d = store.get(DRAFT_KEY) || {};
    if (!state.skills.length && Array.isArray(d.skills)) state.skills = d.skills.slice(0, 15);
    const cvLang = d.language || lang();
    body.innerHTML = `
      <form class="cvgen-form" id="cvgen-form" novalidate>
        <p class="cvgen-intro">${esc(s.intro)}</p>
        <div class="cvgen-error" id="cvgen-form-error" role="alert" hidden></div>
        <div class="cvgen-grid">
          <div class="cvgen-field">
            <label for="cvgen-jobtitle">${esc(s.jobTitle)} <span class="cvgen-req" aria-hidden="true">*</span></label>
            <input id="cvgen-jobtitle" name="jobTitle" type="text" required minlength="2" maxlength="100" autocomplete="off" placeholder="${esc(s.jobTitlePh)}" value="${esc(d.jobTitle || '')}">
          </div>
          <div class="cvgen-field">
            <label for="cvgen-company">${esc(s.company)} <span class="cvgen-req" aria-hidden="true">*</span></label>
            <input id="cvgen-company" name="company" type="text" required minlength="2" maxlength="100" autocomplete="organization" placeholder="${esc(s.companyPh)}" value="${esc(d.company || '')}">
          </div>
          <div class="cvgen-field cvgen-span">
            <label for="cvgen-jd">${esc(s.jd)} <span class="cvgen-req" aria-hidden="true">*</span></label>
            <textarea id="cvgen-jd" name="jobDescription" required maxlength="${JD_MAX}" rows="7" placeholder="${esc(s.jdPh)}" aria-describedby="cvgen-jd-count">${esc(d.jobDescription || '')}</textarea>
            <div class="cvgen-help"><span id="cvgen-jd-count" aria-live="polite"></span></div>
          </div>
          <div class="cvgen-field cvgen-span">
            <label for="cvgen-skill-input">${esc(s.skills)} <span class="cvgen-opt">(${esc(s.optional)})</span></label>
            <div class="cvgen-chips" id="cvgen-chips">
              <input id="cvgen-skill-input" type="text" maxlength="40" autocomplete="off" placeholder="${esc(s.skillsPh)}" aria-describedby="cvgen-skills-hint" enterkeyhint="enter">
            </div>
            <div class="cvgen-help" id="cvgen-skills-hint">${esc(s.skillsHint)}</div>
          </div>
          <fieldset class="cvgen-field">
            <legend>${esc(s.seniority)}</legend>
            ${radios('seniority', ['any', 'intern', 'junior', 'mid', 'senior'].map((k) => [k, s.sen[k]]), d.seniority || 'any')}
          </fieldset>
          <fieldset class="cvgen-field">
            <legend>${esc(s.workMode)}</legend>
            ${radios('workMode', ['any', 'remote', 'hybrid', 'onsite'].map((k) => [k, s.mode[k]]), d.workMode || 'any')}
          </fieldset>
          <fieldset class="cvgen-field">
            <legend>${esc(s.language)}</legend>
            ${radios('language', [['en', 'English'], ['ar', 'العربية']], cvLang)}
          </fieldset>
          <fieldset class="cvgen-field">
            <legend>${esc(s.length)}</legend>
            ${radios('pages', [[1, s.page1], [2, s.page2]], d.pages || 1)}
          </fieldset>
          <label class="cvgen-consent cvgen-span">
            <input type="checkbox" id="cvgen-consent" name="consent">
            <span>${esc(s.consent)} <a href="privacy.html#cv-generator" target="_blank" rel="noopener">${esc(s.privacy)}</a>.</span>
          </label>
        </div>
        <div class="cvgen-actions">
          <span class="cvgen-uses">${esc(s.uses)}</span>
          <button type="submit" class="cvgen-btn cvgen-btn-primary" id="cvgen-submit">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l1.8 4.2L18 9l-4.2 1.8L12 15l-1.8-4.2L6 9l4.2-1.8z"/><path d="M19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z"/></svg>
            <span>${esc(s.generate)}</span>
          </button>
        </div>
      </form>`;

    const form = $('#cvgen-form', body);
    const jd = $('#cvgen-jd', body);
    const updateCount = () => {
      const n = jd.value.trim().length;
      const c = $('#cvgen-jd-count', body);
      c.textContent = n < JD_MIN ? `${s.jdShort(JD_MIN - n)} · ${s.jdCount(n)}` : s.jdCount(n);
      c.classList.toggle('is-warn', n > 0 && n < JD_MIN);
    };
    jd.addEventListener('input', updateCount);
    updateCount();
    renderChips();

    const skillInput = $('#cvgen-skill-input', body);
    const addSkill = (raw) => {
      raw.split(/[,،\n]/).map((x) => x.trim()).filter(Boolean).forEach((x) => {
        if (state.skills.length >= 15 || x.length > 40) return;
        if (!state.skills.some((y) => y.toLowerCase() === x.toLowerCase())) state.skills.push(x);
      });
      skillInput.value = '';
      renderChips();
      saveDraft();
    };
    skillInput.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' || e.key === ',' || e.key === '،') && !e.isComposing) {
        e.preventDefault();
        if (skillInput.value.trim()) addSkill(skillInput.value);
      } else if (e.key === 'Backspace' && !skillInput.value && state.skills.length) {
        state.skills.pop(); renderChips(); saveDraft();
      }
    });
    skillInput.addEventListener('paste', (e) => {
      const text = (e.clipboardData || window.clipboardData)?.getData('text') || '';
      if (/[,،\n]/.test(text)) { e.preventDefault(); addSkill(text); }
    });
    skillInput.addEventListener('blur', () => { if (skillInput.value.trim()) addSkill(skillInput.value); });
    $('#cvgen-chips', body).addEventListener('click', (e) => {
      const rm = e.target.closest('[data-rm]');
      if (rm) { state.skills.splice(Number(rm.dataset.rm), 1); renderChips(); saveDraft(); skillInput.focus(); }
      else if (e.target.id === 'cvgen-chips') skillInput.focus();
    });

    form.addEventListener('input', saveDraft);
    form.addEventListener('change', saveDraft);
    form.addEventListener('submit', (e) => { e.preventDefault(); submit(); });
  }

  function renderChips() {
    const box = $('#cvgen-chips', body);
    if (!box) return;
    box.querySelectorAll('.cvgen-chip-item').forEach((n) => n.remove());
    const input = $('#cvgen-skill-input', box);
    state.skills.forEach((sk, i) => {
      const chip = document.createElement('span');
      chip.className = 'cvgen-chip-item';
      chip.innerHTML = `<span>${esc(sk)}</span><button type="button" data-rm="${i}" aria-label="Remove ${esc(sk)}">×</button>`;
      box.insertBefore(chip, input);
    });
    input.hidden = state.skills.length >= 15;
  }

  function formData() {
    const form = $('#cvgen-form', body);
    if (!form) return null;
    const val = (n) => form.elements[n]?.value ?? '';
    return {
      jobTitle: val('jobTitle').trim(),
      company: val('company').trim(),
      jobDescription: val('jobDescription').trim(),
      mustHaveSkills: state.skills.slice(),
      seniority: form.querySelector('input[name="seniority"]:checked')?.value || 'any',
      workMode: form.querySelector('input[name="workMode"]:checked')?.value || 'any',
      language: form.querySelector('input[name="language"]:checked')?.value || 'en',
      pages: Number(form.querySelector('input[name="pages"]:checked')?.value || 1),
      consent: $('#cvgen-consent', body)?.checked === true
    };
  }

  function saveDraft() {
    const d = formData();
    if (!d) return;
    const { consent, mustHaveSkills, ...rest } = d;
    store.set(DRAFT_KEY, { ...rest, skills: mustHaveSkills });
  }

  function validateClient(d) {
    const bad = /[<>{}\\$`]/;
    if (d.jobTitle.length < 2 || bad.test(d.jobTitle)) return ['INVALID_JOB_TITLE', 'cvgen-jobtitle'];
    if (d.company.length < 2 || bad.test(d.company)) return ['INVALID_COMPANY', 'cvgen-company'];
    if (d.jobDescription.length < JD_MIN) return ['JOB_DESCRIPTION_TOO_SHORT', 'cvgen-jd'];
    if (d.jobDescription.length > JD_MAX) return ['JOB_DESCRIPTION_TOO_LONG', 'cvgen-jd'];
    if (!d.consent) return ['CONSENT_REQUIRED', 'cvgen-consent'];
    return null;
  }

  function showFormError(code, fieldId) {
    const box = $('#cvgen-form-error', body);
    if (!box) return;
    box.textContent = t().errors[code] || t().errors.DEFAULT;
    box.hidden = false;
    body.querySelectorAll('[aria-invalid]').forEach((el) => el.removeAttribute('aria-invalid'));
    const field = fieldId && $('#' + fieldId, body);
    if (field) { field.setAttribute('aria-invalid', 'true'); field.focus({ preventScroll: true }); field.scrollIntoView({ block: 'center', behavior: reduceMotion() ? 'auto' : 'smooth' }); }
    else box.scrollIntoView({ block: 'nearest' });
  }

  function renderLoading() {
    const s = t();
    body.innerHTML = `
      <div class="cvgen-loading" role="status" aria-live="polite">
        <div class="cvgen-doc" aria-hidden="true"><span></span><span></span><span></span><span></span><span></span></div>
        <h3>${esc(s.generating)}</h3>
        <p class="cvgen-muted">${esc(s.generatingSub)}</p>
        <ol class="cvgen-steps">${s.steps.map((x) => `<li>${esc(x)}</li>`).join('')}</ol>
      </div>`;
    const items = body.querySelectorAll('.cvgen-steps li');
    let i = 0;
    const tick = () => {
      items.forEach((li, j) => { li.classList.toggle('is-done', j < i); li.classList.toggle('is-active', j === i); });
      if (i < items.length - 1) { i++; stepTimer = setTimeout(tick, [2500, 4000, 5000][i - 1] || 4000); }
    };
    tick();
  }
  function stopSteps() { if (stepTimer) { clearTimeout(stepTimer); stepTimer = null; } }

  function renderPreview() {
    const s = t();
    const r = state.result;
    // Phones: lists start collapsed so the CV preview is visible straight away
    const wide = window.matchMedia('(min-width: 640px)').matches;
    const list = (arr, cls) => arr && arr.length
      ? `<ul class="cvgen-list ${cls}">${arr.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>`
      : `<p class="cvgen-muted">${esc(s.none)}</p>`;
    body.innerHTML = `
      <div class="cvgen-preview">
        <aside class="cvgen-side">
          <div class="cvgen-meta">
            <span class="cvgen-tag">${esc(r.language.toUpperCase())}</span>
            <span class="cvgen-tag">${esc(s.pages(r.pages))}</span>
            <span class="cvgen-ref">${esc(s.ref)}: <bdi>${esc(r.ref)}</bdi></span>
          </div>
          <details class="cvgen-match" ${wide ? 'open' : ''}>
            <summary>${esc(s.matched)} <span class="cvgen-count">${r.match.matched.length}</span></summary>
            ${list(r.match.matched, 'is-ok')}
          </details>
          <details class="cvgen-match" ${wide ? 'open' : ''}>
            <summary>${esc(s.missing)} <span class="cvgen-count">${r.match.missing.length}</span></summary>
            <p class="cvgen-muted cvgen-small">${esc(s.missingNote)}</p>
            ${list(r.match.missing, 'is-gap')}
          </details>
        </aside>
        <section class="cvgen-pages" id="cvgen-pages" aria-label="PDF preview">
          <p class="cvgen-muted cvgen-pages-status" id="cvgen-pages-status">${esc(s.previewLoading)}</p>
        </section>
        <div class="cvgen-actions cvgen-actions-preview">
          <button type="button" class="cvgen-btn cvgen-btn-ghost" id="cvgen-new">${esc(s.newCv)}</button>
          <a class="cvgen-btn cvgen-btn-ghost" id="cvgen-open-pdf" href="${r.url}" target="_blank" rel="noopener">${esc(s.openPdf)}</a>
          <a class="cvgen-btn cvgen-btn-primary" id="cvgen-download" href="${r.url}" download="${esc(r.fileName)}">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12M7 10l5 5 5-5M5 21h14"/></svg>
            <span>${esc(s.download)}</span>
          </a>
        </div>
      </div>`;

    $('#cvgen-new', body).addEventListener('click', () => { state.view = state.quota && state.quota.remaining <= 0 ? 'limit' : 'form'; render(); focusFirst(); });
    $('#cvgen-download', body).addEventListener('click', () => {
      api(`/cv/${encodeURIComponent(r.ref)}/downloaded`, { method: 'POST', body: '{}' }).catch(() => {});
      if (typeof window.showToast === 'function') {
        try { window.showToast({ title: s.downloaded, sub: r.fileName, icon: '📄', type: 'welcome', duration: 3500 }); } catch { /* optional */ }
      }
    });
    renderPdfPages();
  }

  function renderMessage(kind) {
    const s = t();
    const cfg = {
      signin: { icon: '🔒', title: s.signInTitle, body: s.signInBody, btn: null },
      limit: { icon: '🗓️', title: s.limitTitle, body: s.limitBody(fmtDate(state.quota?.resetsAt || new Date().toISOString())), btn: null },
      off: { icon: '🛠️', title: s.offTitle, body: s.offBody, btn: null },
      error: { icon: '⚠️', title: s.errTitle, body: s.errors[state.error] || s.errors.DEFAULT, btn: 'retry' }
    }[kind];
    body.innerHTML = `
      <div class="cvgen-message" role="${kind === 'error' ? 'alert' : 'status'}">
        <div class="cvgen-message-icon" aria-hidden="true">${cfg.icon}</div>
        <h3>${esc(cfg.title)}</h3>
        <p>${esc(cfg.body)}</p>
        ${cfg.btn ? `<div class="cvgen-actions cvgen-actions-center">
            <button type="button" class="cvgen-btn cvgen-btn-ghost" id="cvgen-back">${esc(s.backToForm)}</button>
            <button type="button" class="cvgen-btn cvgen-btn-primary" id="cvgen-retry">${esc(s.retry)}</button>
          </div>` : ''}
      </div>`;
    const back = $('#cvgen-back', body), retry = $('#cvgen-retry', body);
    if (back) back.addEventListener('click', () => { state.view = 'form'; render(); focusFirst(); });
    if (retry) retry.addEventListener('click', () => { state.view = 'form'; render(); submit(); });
  }

  /* ── PDF preview (pdf.js, lazy-loaded) ────────────────────────────────── */
  let pdfjsPromise = null;
  function loadPdfJs() {
    if (window.pdfjsLib) return Promise.resolve(window.pdfjsLib);
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

  async function renderPdfPages() {
    const myToken = ++renderToken;
    const wrap = $('#cvgen-pages', body);
    if (!wrap || !state.result) return;
    try {
      const pdfjs = await loadPdfJs();
      if (!state.pdfDoc) state.pdfDoc = await pdfjs.getDocument({ data: state.result.bytes.slice(0) }).promise;
      if (myToken !== renderToken) return;
      const doc = state.pdfDoc;
      const width = Math.max(240, wrap.clientWidth - 2);
      const dpr = Math.min(window.devicePixelRatio || 1, 2.5);
      const frag = document.createDocumentFragment();
      for (let i = 1; i <= doc.numPages; i++) {
        const page = await doc.getPage(i);
        if (myToken !== renderToken) return;
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
        fig.className = 'cvgen-page';
        fig.appendChild(canvas);
        const cap = document.createElement('figcaption');
        cap.textContent = t().page(i, doc.numPages);
        fig.appendChild(cap);
        frag.appendChild(fig);
      }
      if (myToken !== renderToken) return;
      wrap.replaceChildren(frag);
      observeResize(wrap);
    } catch (err) {
      if (myToken !== renderToken) return;
      wrap.innerHTML = `<p class="cvgen-muted cvgen-pages-status">${esc(t().previewFail)}</p>`;
    }
  }

  // Re-render crisp pages when the width changes (rotation, foldables, split view)
  function observeResize(wrap) {
    if (!('ResizeObserver' in window)) return;
    if (resizeObs) resizeObs.disconnect();
    let lastW = wrap.clientWidth, timer = null;
    resizeObs = new ResizeObserver(() => {
      const w = wrap.clientWidth;
      if (Math.abs(w - lastW) < 24) return;
      lastW = w;
      clearTimeout(timer);
      timer = setTimeout(() => { if (state.view === 'preview') renderPdfPages(); }, 180);
    });
    resizeObs.observe(wrap);
  }

  /* ── Actions ──────────────────────────────────────────────────────────── */
  async function refreshQuota() {
    try {
      const r = await api('/cv/quota');
      if (r.ok) state.quota = r.data;
      else if (r.data.code === 'AUTH') return 'AUTH';
    } catch { /* offline: keep going, the server enforces it anyway */ }
    return null;
  }

  async function submit() {
    if (state.generating) return;
    const d = formData();
    if (!d) return;
    const bad = validateClient(d);
    if (bad) return showFormError(bad[0], bad[1]);
    saveDraft();

    state.generating = true;
    state.view = 'loading';
    render();
    dialog.focus();
    let r;
    try {
      r = await api('/cv/generate', { method: 'POST', body: JSON.stringify(d) });
    } catch {
      r = { ok: false, data: { code: 'NETWORK' } };
    }
    state.generating = false;

    if (r.data && r.data.quota) state.quota = r.data.quota;
    if (r.ok && r.data.pdfBase64) {
      const bytes = Uint8Array.from(atob(r.data.pdfBase64), (c) => c.charCodeAt(0));
      if (state.result?.url) URL.revokeObjectURL(state.result.url);
      const blob = new Blob([bytes], { type: 'application/pdf' });
      state.pdfDoc = null;
      state.result = { ...r.data, bytes, url: URL.createObjectURL(blob) };
      delete state.result.pdfBase64;
      state.view = 'preview';
    } else {
      const code = r.data?.code || 'DEFAULT';
      if (code === 'AUTH') { signOutLocal(); state.view = 'signin'; render(); promptSignIn(); return; }
      if (code === 'QUOTA') state.view = 'limit';
      else if (code === 'DISABLED') state.view = 'off';
      else if (/^(INVALID_|JOB_DESCRIPTION_|CONSENT_)/.test(code)) { state.view = 'form'; render(); return showFormError(code); }
      else { state.error = code; state.view = 'error'; }
    }
    if (!overlay.hidden) { render(); focusFirst(); }
  }

  function signOutLocal() {
    try { localStorage.removeItem('portfolio_token'); localStorage.removeItem('portfolio_user'); } catch { /* ignore */ }
    if (typeof window.updateAuthLangState === 'function') window.updateAuthLangState();
  }

  let pendingAfterSignIn = false;
  function promptSignIn() {
    pendingAfterSignIn = true;
    close(true);
    if (typeof window.openAuthModal === 'function') window.openAuthModal('login');
  }

  /* ── Open / close ─────────────────────────────────────────────────────── */
  async function open() {
    if (!overlay) build();
    const cvOverlay = document.getElementById('cv-modal-overlay');
    if (cvOverlay && cvOverlay.classList.contains('active')) document.getElementById('cv-modal-close')?.click();

    if (!token()) { promptSignIn(); return; }

    state.lastFocus = document.activeElement;
    overlay.hidden = false;
    document.documentElement.classList.add('no-scroll');
    document.body.classList.add('no-scroll');
    requestAnimationFrame(() => overlay.classList.add('is-open'));

    if (state.generating) { state.view = 'loading'; render(); dialog.focus(); return; }
    if (state.view === 'preview' && state.result) { render(); focusFirst(); return; }

    const authProblem = await refreshQuota();
    if (authProblem) { signOutLocal(); promptSignIn(); return; }
    if (state.quota && state.quota.enabled === false) state.view = 'off';
    else if (state.quota && state.quota.remaining <= 0) state.view = 'limit';
    else if (!['error'].includes(state.view)) state.view = 'form';
    render();
    focusFirst();
  }

  function requestClose() {
    if (state.generating && !window.confirm(t().confirmClose)) return;
    close();
  }

  function close(silent) {
    if (!overlay || overlay.hidden) return;
    overlay.classList.remove('is-open');
    const done = () => {
      overlay.hidden = true;
      document.documentElement.classList.remove('no-scroll');
      document.body.classList.remove('no-scroll');
    };
    if (reduceMotion() || silent) done(); else setTimeout(done, 220);
    if (resizeObs) { resizeObs.disconnect(); resizeObs = null; }
    if (!silent && state.lastFocus && typeof state.lastFocus.focus === 'function') state.lastFocus.focus({ preventScroll: true });
  }

  function focusFirst() {
    const el = body.querySelector('input:not([type=hidden]):not([hidden]), textarea, .cvgen-btn-primary, button');
    (el || dialog).focus({ preventScroll: true });
  }

  function onKeydown(e) {
    if (e.key === 'Escape') { e.stopPropagation(); requestClose(); return; }
    if (e.key !== 'Tab') return;
    // Keep focus inside the dialog
    const f = [...dialog.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]):not([hidden]), textarea, [tabindex="0"], summary')]
      .filter((el) => el.offsetParent !== null || el === document.activeElement);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  /* ── Wiring ───────────────────────────────────────────────────────────── */
  function init() {
    const btn = document.getElementById('cvgen-open');
    if (btn) btn.addEventListener('click', open);
    window.openCvGenerator = open;

    document.addEventListener('portfolio:signed-in', () => {
      if (!pendingAfterSignIn) return;
      pendingAfterSignIn = false;
      setTimeout(open, 350);   // let the auth modal finish closing
    });
    // If the auth modal is dismissed without signing in, forget the pending open
    document.addEventListener('click', (e) => {
      if (pendingAfterSignIn && e.target.closest && e.target.closest('#auth-modal-close, #auth-modal-overlay')) pendingAfterSignIn = false;
    });

    document.addEventListener('languageChanged', () => {
      if (!overlay || overlay.hidden) return;
      if (state.view === 'form') saveDraft();
      render();
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
