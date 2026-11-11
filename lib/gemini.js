/**
 * Server-only Gemini client.
 *
 * Safety rules:
 *  - The API key is read from process.env only, sent only in the
 *    `x-goog-api-key` header (never in a URL, so it can't leak into logs),
 *    and never included in thrown errors or log lines.
 *  - Callers get a GeminiError with a short, safe `code`, never Google's raw
 *    error body, so nothing internal reaches the browser.
 *  - Every call has a hard timeout and an output-token cap.
 */
const API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

const MODELS = {
  cv: process.env.GEMINI_MODEL_CV || 'gemini-3.5-flash',
  chat: process.env.GEMINI_MODEL_CHAT || 'gemini-3.5-flash-lite'
};

// Gemini 3.x models "think" before answering and thinking counts against
// maxOutputTokens. Keep it low so answers are never cut off.
const THINKING = { cv: 'low', chat: 'minimal' };

class GeminiError extends Error {
  constructor(code, status) {
    super(`Gemini request failed (${code})`);
    this.name = 'GeminiError';
    this.code = code;       // NOT_CONFIGURED | TIMEOUT | RATE_LIMITED | BLOCKED | BAD_RESPONSE | UPSTREAM
    this.status = status;   // upstream HTTP status, if any
  }
}

function getKey() {
  const key = process.env.GEMINI_API_KEY;
  if (!key || typeof key !== 'string' || key.trim().length < 20) throw new GeminiError('NOT_CONFIGURED');
  return key.trim();
}

const isConfigured = () => { try { getKey(); return true; } catch { return false; } };

/**
 * @param {object}   opts
 * @param {'cv'|'chat'} opts.task            which pinned model to use
 * @param {string}   opts.system             system instruction (rules)
 * @param {Array}    opts.contents           [{ role: 'user'|'model', text }]
 * @param {object}  [opts.schema]            JSON schema → forces JSON output, returns parsed object
 * @param {number}  [opts.maxOutputTokens]
 * @param {number}  [opts.temperature]
 * @param {number}  [opts.timeoutMs]
 * @returns {Promise<string|object>}         text, or parsed JSON when `schema` is given
 */
async function generate({ task, system, contents, schema, maxOutputTokens = 4096, temperature = 0.2, timeoutMs = 25000 }) {
  const key = getKey();
  const model = MODELS[task];
  if (!model) throw new Error(`gemini: unknown task "${task}"`);

  const body = {
    systemInstruction: { parts: [{ text: system }] },
    contents: contents.map((c) => ({ role: c.role === 'model' ? 'model' : 'user', parts: [{ text: String(c.text) }] })),
    generationConfig: {
      temperature,
      maxOutputTokens,
      thinkingConfig: { thinkingLevel: THINKING[task] },
      ...(schema ? { responseMimeType: 'application/json', responseSchema: schema } : {})
    }
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(`${API_BASE}/${encodeURIComponent(model)}:generateContent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
      body: JSON.stringify(body),
      signal: controller.signal
    });
  } catch (err) {
    throw new GeminiError(err.name === 'AbortError' ? 'TIMEOUT' : 'UPSTREAM');
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    // Log only the status, never the response body (it can echo request details)
    console.error(`[gemini] ${task} HTTP ${res.status}`);
    throw new GeminiError(res.status === 429 ? 'RATE_LIMITED' : 'UPSTREAM', res.status);
  }

  let data;
  try { data = await res.json(); } catch { throw new GeminiError('BAD_RESPONSE'); }

  const cand = data?.candidates?.[0];
  if (!cand || data?.promptFeedback?.blockReason || ['SAFETY', 'PROHIBITED_CONTENT', 'BLOCKLIST', 'SPII'].includes(cand.finishReason)) {
    throw new GeminiError('BLOCKED');
  }
  if (cand.finishReason === 'MAX_TOKENS') {
    console.error(`[gemini] ${task} output truncated (MAX_TOKENS)`);
    throw new GeminiError('BAD_RESPONSE');
  }
  // Skip any "thought" parts; only the final answer is returned
  const text = (cand.content?.parts || []).filter((p) => !p.thought).map((p) => p.text || '').join('').trim();
  if (!text) throw new GeminiError('BAD_RESPONSE');

  if (!schema) return text;
  try { return JSON.parse(text); } catch { throw new GeminiError('BAD_RESPONSE'); }
}

module.exports = { generate, isConfigured, GeminiError, MODELS };
