/**
 * HTML → PDF with headless Chromium.
 *
 * Locked down: JavaScript is disabled in the page and every network request is
 * aborted (only inline data: URIs are allowed), so CV content can never fetch
 * anything — no SSRF, no tracking, no remote fonts.
 *
 * Vercel/Linux: uses @sparticuz/chromium. Local dev: set CHROME_PATH, or a
 * locally installed Chrome / Edge / Chromium / Brave is detected.
 */
const fs = require('fs');
const path = require('path');
// Loaded on first use only, so a problem with the browser packages can never
// stop the rest of the API (sign-in, chatbot…) from starting.
// puppeteer-core is ESM-only: import() works on every Node version, whereas
// require() of an ES module fails on Vercel's runtime.
let puppeteerPromise = null;
const getPuppeteer = () => (puppeteerPromise ||= import('puppeteer-core').then((m) => m.default || m));
const { PDFDocument } = require('pdf-lib');

const LOCAL_BROWSERS = [
  process.env.CHROME_PATH,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'
].filter(Boolean);

let browserPromise = null;

async function launch() {
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
    // ESM-only package: import() works on every supported Node version
    const mod = await import('@sparticuz/chromium');
    const chromium = mod.default || mod;
    return (await getPuppeteer()).launch({
      args: chromium.args,
      executablePath: await chromium.executablePath(),
      headless: true
    });
  }
  const executablePath = LOCAL_BROWSERS.find((p) => { try { return fs.existsSync(p); } catch { return false; } });
  if (!executablePath) throw new Error('pdf: no local Chrome/Edge found — set CHROME_PATH');
  return (await getPuppeteer()).launch({ executablePath, headless: true, args: ['--no-first-run', '--no-default-browser-check'] });
}

/** One shared browser per warm instance; relaunched if it died. */
async function getBrowser() {
  if (browserPromise) {
    const b = await browserPromise.catch(() => null);
    if (b && b.connected) return b;
  }
  browserPromise = launch();
  return browserPromise;
}

/* ── Fonts (embedded as data URIs; nothing is fetched) ── */
const FONT_DIR = path.join(__dirname, 'cv-fonts');
let fontCss = null;
function getFontCss() {
  if (fontCss) return fontCss;
  const face = (family, file, weight, range) => {
    const b64 = fs.readFileSync(path.join(FONT_DIR, file)).toString('base64');
    return `@font-face{font-family:'${family}';font-style:normal;font-weight:${weight};font-display:block;` +
      `src:url(data:font/woff2;base64,${b64}) format('woff2');${range ? `unicode-range:${range};` : ''}}`;
  };
  const ARABIC_RANGE = 'U+0600-06FF,U+0750-077F,U+0870-088E,U+0890-0891,U+0897-08E1,U+08E3-08FF,U+200C-200E,U+2010-2011,U+204F,U+2E41,U+FB50-FDFF,U+FE70-FE74,U+FE76-FEFC';
  fontCss = [
    face('CVSans', 'ibm-plex-sans-latin-400-normal.woff2', 400),
    face('CVSans', 'ibm-plex-sans-latin-600-normal.woff2', 600),
    face('CVSans', 'ibm-plex-sans-arabic-arabic-400-normal.woff2', 400, ARABIC_RANGE),
    face('CVSans', 'ibm-plex-sans-arabic-arabic-600-normal.woff2', 600, ARABIC_RANGE)
  ].join('\n');
  return fontCss;
}

/**
 * Renders HTML to a PDF (size/margins from the document's @page rule).
 * @returns {Promise<{ buffer: Buffer, pages: number }>}
 */
async function renderPdf(html, { timeoutMs = 20000 } = {}) {
  const browser = await getBrowser();
  const page = await browser.newPage();
  try {
    await page.setJavaScriptEnabled(false);
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      const url = req.url();
      // The initial about:blank / setContent document and inline data: URIs only
      if (url.startsWith('data:') || url === 'about:blank') req.continue();
      else req.abort();
    });
    page.setDefaultTimeout(timeoutMs);
    await page.setContent(html, { waitUntil: 'load', timeout: timeoutMs });
    await page.evaluateHandle('document.fonts.ready').catch(() => {});
    const pdf = await page.pdf({
      format: 'A4',
      printBackground: true,
      // Page size + margins come from the document's @page rule. The footer is a
      // position:fixed element in the page (repeats on every printed page and
      // uses the embedded fonts, unlike Chromium's footerTemplate).
      preferCSSPageSize: true,
      displayHeaderFooter: false,
      timeout: timeoutMs
    });
    const buffer = Buffer.from(pdf);
    const doc = await PDFDocument.load(buffer, { updateMetadata: false });
    return { buffer, pages: doc.getPageCount() };
  } finally {
    await page.close().catch(() => {});
  }
}

/** Sets document metadata (title, author, keywords…) on a finished PDF. */
async function setPdfMetadata(buffer, meta) {
  const doc = await PDFDocument.load(buffer, { updateMetadata: false });
  if (meta.title) doc.setTitle(meta.title, { showInWindowTitleBar: true });
  if (meta.author) doc.setAuthor(meta.author);
  if (meta.subject) doc.setSubject(meta.subject);
  if (meta.keywords) doc.setKeywords(meta.keywords);
  if (meta.language) doc.setLanguage(meta.language);
  doc.setCreator(meta.creator || 'ashfaaqkt.com CV generator');
  doc.setProducer(meta.producer || 'ashfaaqkt.com');
  doc.setCreationDate(new Date());
  doc.setModificationDate(new Date());
  return Buffer.from(await doc.save({ useObjectStreams: false }));
}

module.exports = { renderPdf, setPdfMetadata, getFontCss };
