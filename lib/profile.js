/**
 * Profile snapshot builder.
 *
 * Reads Ashfaaq's facts straight from the live portfolio source (script.js data
 * literals + index.html), so the CV generator and chatbot always match the site.
 * The snapshot is the ONLY source of truth for AI features: anything not in it
 * must never appear in a generated CV or chatbot answer.
 *
 * Extraction is strict: if any required block can't be found or parsed, it
 * throws, and callers must refuse to generate rather than use partial data.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');

// Facts that are not (yet) on the website itself, supplied by Ashfaaq.
const MANUAL_FACTS = {
  location: { en: 'Kozhikode, India', ar: 'كوزيكود، الهند' },
  portfolioUrl: process.env.SITE_URL || 'https://ashfaaqkt.com',
  // The one email shown on generated CVs (must also be listed on the site)
  cvEmail: 'ashfaaqktmail@gmail.com'
};

/* ── Literal extraction ─────────────────────────────────────────────────── */

/** Returns the index just past the bracket that closes the one at `start`. */
function matchBracket(src, start) {
  const open = src[start];
  const close = { '{': '}', '[': ']' }[open];
  if (!close) throw new Error('matchBracket: not a bracket');
  let depth = 0;
  for (let i = start; i < src.length; i++) {
    const c = src[i];
    // Skip strings and template literals (with nested ${...})
    if (c === '"' || c === "'" || c === '`') {
      i = skipString(src, i);
      continue;
    }
    // Skip comments
    if (c === '/' && src[i + 1] === '/') { i = src.indexOf('\n', i); if (i < 0) break; continue; }
    if (c === '/' && src[i + 1] === '*') { i = src.indexOf('*/', i) + 1; continue; }
    if (c === open) depth++;
    else if (c === close && --depth === 0) return i + 1;
  }
  throw new Error('matchBracket: unbalanced');
}

function skipString(src, i) {
  const q = src[i];
  for (let j = i + 1; j < src.length; j++) {
    const c = src[j];
    if (c === '\\') { j++; continue; }
    if (q === '`' && c === '$' && src[j + 1] === '{') { j = matchBracket(src, j + 1) - 1; continue; }
    if (c === q) return j;
  }
  throw new Error('skipString: unterminated string');
}

/** Finds `const <name> = {...}` / `[...]` in src and evaluates the literal in an empty sandbox. */
function extractLiteral(src, name) {
  const re = new RegExp(`const\\s+${name}\\s*=\\s*([\\[{])`);
  const m = re.exec(src);
  if (!m) throw new Error(`profile: "${name}" not found in script.js`);
  const start = m.index + m[0].length - 1;
  const end = matchBracket(src, start);
  const literal = src.slice(start, end);
  // Empty context, no globals, short timeout: the literal can only build plain data
  return vm.runInNewContext(`(${literal})`, Object.create(null), { timeout: 200 });
}

/* ── Text helpers ───────────────────────────────────────────────────────── */

const decodeEntities = (s) => s
  .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
  .replace(/&quot;/g, '"').replace(/&#39;/g, "'");

/** HTML → plain text (for chatbot answers that are stored as HTML snippets). */
const stripHtml = (s) => decodeEntities(String(s || '')
  .replace(/<li[^>]*>/gi, '\n- ').replace(/<br\s*\/?>/gi, '\n').replace(/<\/p>/gi, '\n')
  .replace(/<[^>]+>/g, '')).replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n').trim();

const attr = (html, re) => { const m = re.exec(html); return m ? decodeEntities(m[1]).trim() : ''; };

/* ── Snapshot ───────────────────────────────────────────────────────────── */

function buildSnapshot() {
  const js = fs.readFileSync(path.join(ROOT, 'script.js'), 'utf8');
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');

  const t = extractLiteral(js, 'translations');
  const projects = extractLiteral(js, 'projects');
  const skillsData = extractLiteral(js, 'skillsData');
  const languages = extractLiteral(js, 'languages');
  const hobbies = extractLiteral(js, 'hobbies');

  const en = t.en, ar = t.ar;
  if (!en?.hero || !en?.education?.timeline || !Array.isArray(projects) || !skillsData?.all) {
    throw new Error('profile: portfolio data has an unexpected shape');
  }

  // Contact details: ONLY from the Connect section, so other people's details on the
  // page (e.g. the FYP advisor's email) can never end up on the CV
  const uniq = (arr) => [...new Set(arr)];
  const connectStart = html.indexOf('id="page-connect"');
  if (connectStart < 0) throw new Error('profile: Connect section not found in index.html');
  const connectHtml = html.slice(connectStart, html.indexOf('</section>', connectStart));
  const mails = uniq([...connectHtml.matchAll(/href="mailto:([^"?]+)"/g)].map((m) => m[1]));
  const phones = uniq([...connectHtml.matchAll(/href="tel:([^"]+)"/g)].map((m) => m[1]));
  const linkedin = attr(html, /href="(https:\/\/(?:www\.)?linkedin\.com\/in\/[^"]+)"/);
  const github = attr(html, /href="(https:\/\/github\.com\/[A-Za-z0-9-]+)"/);

  // Final Year Project (detailed card in index.html)
  const fyp = {
    title: { en: attr(html, /class="fyp-card-title"[^>]*data-en="([^"]+)"/), ar: attr(html, /class="fyp-card-title"[^>]*data-ar="([^"]+)"/) },
    description: { en: attr(html, /class="fyp-card-desc"\s+data-en="([^"]+)"/), ar: attr(html, /data-ar="([^"]+)">\s*A production-grade multimodal/) },
    tech: [...(/<div class="fyp-tech-row">([\s\S]*?)<\/div>/.exec(html)?.[1] || '').matchAll(/<span>([^<]+)<\/span>/g)].map((m) => decodeEntities(m[1])),
    grade: 'Excellent (EX)'
  };

  const zipTimeline = (i) => ({
    period: en.education.timeline[i].badge,
    en: { title: en.education.timeline[i].title, subtitle: en.education.timeline[i].subtitle, description: en.education.timeline[i].description, items: (en.education.timeline[i].links || []).map((l) => l.text).concat(en.education.timeline[i].milestones || []) },
    ar: ar?.education?.timeline?.[i] ? { title: ar.education.timeline[i].title, subtitle: ar.education.timeline[i].subtitle, description: ar.education.timeline[i].description, items: (ar.education.timeline[i].links || []).map((l) => l.text).concat(ar.education.timeline[i].milestones || []) } : null
  });

  const snapshot = {
    name: { en: en.hero.name, ar: ar?.hero?.name || en.hero.name },
    headline: { en: en.hero.degree, ar: ar?.hero?.degree || '' },
    summarySource: {
      en: [en.hero.description, en.about.subtitle, en.about.card1.description, en.about.card2.description, en.about.card3.description, en.footer.statusText, en.connect.subtitle],
      ar: [ar?.hero?.description, ar?.about?.subtitle, ar?.about?.card1?.description, ar?.about?.card2?.description, ar?.about?.card3?.description, ar?.footer?.statusText, ar?.connect?.subtitle].filter(Boolean)
    },
    contact: {
      location: MANUAL_FACTS.location,
      emails: mails,
      cvEmail: mails.includes(MANUAL_FACTS.cvEmail) ? MANUAL_FACTS.cvEmail : null,
      phones,
      linkedin,
      github,
      portfolio: MANUAL_FACTS.portfolioUrl
    },
    timeline: en.education.timeline.map((_, i) => zipTimeline(i)),
    finalYearProject: fyp,
    projects: projects.map((p) => ({
      title: { en: p.title, ar: p.titleAr || '' },
      tech: p.meta || '',
      badge: p.badge || '',
      description: { en: p.description || '', ar: p.descriptionAr || '' },
      links: [p.link?.href, p.liveLink?.href].filter(Boolean)
    })),
    skills: skillsData.all.map((g) => ({
      category: g.category,
      title: { en: g.title, ar: g.titleAr || '' },
      skills: { en: g.skills || [], ar: g.skillsAr || g.skills || [] }
    })),
    languages: languages.map((l) => ({ name: { en: l.name, ar: l.nameAr || '' }, level: { en: l.level, ar: l.levelAr || '' } })),
    hobbies: hobbies.map((h) => ({ title: { en: h.title, ar: h.titleAr || '' } })),
    chatbotNotes: {
      en: Object.fromEntries(Object.entries(en.chatbot?.answers || {}).map(([k, v]) => [k, stripHtml(v)])),
      ar: Object.fromEntries(Object.entries(ar?.chatbot?.answers || {}).map(([k, v]) => [k, stripHtml(v)]))
    }
  };

  // Strict sanity checks — never hand partial data to the AI
  const problems = [];
  if (!snapshot.contact.emails.length) problems.push('no email');
  if (!snapshot.contact.cvEmail) problems.push('CV email not listed in the Connect section');
  if (!snapshot.contact.phones.length) problems.push('no phone');
  if (!snapshot.projects.length) problems.push('no projects');
  if (!snapshot.skills.some((g) => g.skills.en.length)) problems.push('no skills');
  if (!snapshot.finalYearProject.title.en) problems.push('no FYP');
  if (problems.length) throw new Error('profile: incomplete snapshot (' + problems.join(', ') + ')');

  // Whitelist used by the CV validator: every skill the AI is allowed to mention
  snapshot.allowedSkills = [...new Set(snapshot.skills.flatMap((g) => g.skills.en))];
  return snapshot;
}

// Cache per process: files only change on deploy
let cached = null;
function getProfileSnapshot({ fresh = false } = {}) {
  if (!cached || fresh) cached = Object.freeze(buildSnapshot());
  return cached;
}

module.exports = { getProfileSnapshot, extractLiteral, matchBracket };
