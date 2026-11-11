/** Validation for the "Generate tailored CV" form. Returns { error } or { job }. */

const TEXT_RE = /^[^<>{}\\$`]*$/;   // fields that end up printed on the PDF: no markup / template chars
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

const SENIORITY = ['intern', 'junior', 'mid', 'senior', 'any'];
const WORK_MODES = ['remote', 'hybrid', 'onsite', 'any'];

const clean = (v) => (typeof v === 'string' ? v.replace(CONTROL_RE, '').trim().replace(/[ \t]+/g, ' ') : '');

function validateCvRequest(body = {}) {
  const jobTitle = clean(body.jobTitle);
  const company = clean(body.company);
  const jobDescription = (typeof body.jobDescription === 'string' ? body.jobDescription : '')
    .replace(CONTROL_RE, '').replace(/\r\n?/g, '\n').replace(/\n{3,}/g, '\n\n').trim();

  let skills = Array.isArray(body.mustHaveSkills) ? body.mustHaveSkills
    : (typeof body.mustHaveSkills === 'string' ? body.mustHaveSkills.split(/[,\n،]/) : []);
  skills = [...new Set(skills.map(clean).filter(Boolean))];

  const seniority = SENIORITY.includes(body.seniority) ? body.seniority : 'any';
  const workMode = WORK_MODES.includes(body.workMode) ? body.workMode : 'any';
  const language = body.language === 'ar' ? 'ar' : (body.language === 'en' ? 'en' : null);
  const pages = Number(body.pages);

  if (jobTitle.length < 2 || jobTitle.length > 100 || !TEXT_RE.test(jobTitle)) return { error: 'INVALID_JOB_TITLE' };
  if (company.length < 2 || company.length > 100 || !TEXT_RE.test(company)) return { error: 'INVALID_COMPANY' };
  if (jobDescription.length < 80) return { error: 'JOB_DESCRIPTION_TOO_SHORT' };
  if (jobDescription.length > 8000) return { error: 'JOB_DESCRIPTION_TOO_LONG' };
  if (skills.length > 15 || skills.some((s) => s.length > 40 || !TEXT_RE.test(s))) return { error: 'INVALID_SKILLS' };
  if (!language) return { error: 'INVALID_LANGUAGE' };
  if (pages !== 1 && pages !== 2) return { error: 'INVALID_PAGES' };
  if (body.consent !== true) return { error: 'CONSENT_REQUIRED' };

  return { job: { jobTitle, company, jobDescription, mustHaveSkills: skills, seniority, workMode, language, pages } };
}

module.exports = { validateCvRequest, SENIORITY, WORK_MODES };
