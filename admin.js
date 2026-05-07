/* ═══════════════════════════════════════════
   ADMIN PANEL — admin.js
═══════════════════════════════════════════ */

const API = (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
  ? 'http://localhost:5000/api'
  : '/api';

/* ── XSS protection ── */
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/* ── Theme ── */
function applyTheme() {
  const saved = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
}
applyTheme();

/* ── Auth helpers ── */
function getToken() { return localStorage.getItem('admin_token'); }

async function apiFetch(path, opts = {}) {
  const { headers: extraHeaders, ...rest } = opts;
  const res = await fetch(API + path, {
    ...rest,
    headers: { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json', ...(extraHeaders || {}) }
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.message || `HTTP ${res.status}`);
  }
  return res.json();
}

/* ── DOM refs ── */
const board      = document.getElementById('adm-board');
const signoutBtn = document.getElementById('adm-signout');

/* ══════════════════════════════════════════
   AUTH — token set by popup on index.html
══════════════════════════════════════════ */

/* ══════════════════════════════════════════
   TABS state — must be declared before checkAuth IIFE
══════════════════════════════════════════ */
let activeTab = 'users';
const loaded = {};
let _usersPrefetch = null;

(function checkAuth() {
  const token = getToken();
  if (!token) { window.location.replace('index.html'); return; }

  /* Kick off users fetch immediately — no .catch() so errors surface in loadUsers */
  _usersPrefetch = apiFetch('/admin/users');

  board.hidden = false;

  if (signoutBtn) {
    signoutBtn.hidden = false;
    signoutBtn.onclick = function () {
      localStorage.removeItem('admin_token');
      window.location.href = 'index.html';
    };
  }

  /* Call loadUsers directly — avoids any ordering dependency */
  loaded['users'] = true;
  loadUsers();
})();

document.querySelectorAll('.adm-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.adm-tab').forEach(b => { b.classList.remove('active'); b.removeAttribute('aria-selected'); });
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');

    document.querySelectorAll('.adm-panel').forEach(p => p.hidden = true);
    const tab = btn.dataset.tab;
    activeTab = tab;
    document.getElementById('panel-' + tab).hidden = false;
    if (!loaded[tab]) loadPanel(tab);
  });
});

function loadPanel(tab) {
  loaded[tab] = true;
  if (tab === 'users')    loadUsers();
  if (tab === 'timeline') loadTimeline();
  if (tab === 'projects') loadProjects();
}

/* ══════════════════════════════════════════
   USERS TAB
══════════════════════════════════════════ */
let allUsers = [];

async function loadUsers() {
  const tbody = document.getElementById('u-tbody');
  try {
    const promise = _usersPrefetch || apiFetch('/admin/users');
    _usersPrefetch = null;
    const data = await promise;
    allUsers = Array.isArray(data) ? data : [];
    renderUsers(allUsers);
  } catch (err) {
    console.error('[admin] loadUsers error:', err);
    tbody.innerHTML = `<tr><td colspan="7" class="adm-loading" style="color:#ff6b6b">
      Failed to load users: ${esc(err.message)}
      <br><small style="opacity:0.7">Check that the backend server is running and your admin token is valid.</small>
    </td></tr>`;
  }
}

function renderUsers(list) {
  const tbody = document.getElementById('u-tbody');
  document.getElementById('u-count').textContent = list.length;

  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="adm-loading">No users found.</td></tr>';
    return;
  }

  tbody.innerHTML = list.map(u => {
    const date = u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '—';
    return `<tr>
      <td>${esc(date)}</td>
      <td>${esc(u.name || '—')}</td>
      <td>${esc(u.email || '—')}</td>
      <td>${esc(u.phone || '—')}</td>
      <td>${esc(u.category || u.role || '—')}</td>
      <td>${esc(u.company || '—')}</td>
      <td>
        <button class="adm-del-btn" onclick="deleteUser('${esc(u._id)}', '${esc(u.name || u.email)}')">
          Delete
        </button>
      </td>
    </tr>`;
  }).join('');
}

window.deleteUser = async function (id, label) {
  if (!confirm(`Delete user "${label}"? This cannot be undone.`)) return;
  try {
    await apiFetch(`/admin/users/${id}`, { method: 'DELETE' });
    allUsers = allUsers.filter(u => u._id !== id);
    applyUserFilters();
  } catch (err) {
    alert('Failed to delete: ' + err.message);
  }
};

function applyUserFilters() {
  const q = document.getElementById('u-search').value.toLowerCase();
  const cat = document.getElementById('u-filter').value;
  const filtered = allUsers.filter(u => {
    const matchQ = !q || (u.name || '').toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q);
    const matchCat = cat === 'all' || (u.category || u.role || '') === cat;
    return matchQ && matchCat;
  });
  renderUsers(filtered);
}

document.getElementById('u-search').addEventListener('input', applyUserFilters);

/* ── Custom category dropdown ── */
(function initCatFilter() {
  const wrap    = document.getElementById('u-filter-wrap');
  const trigger = document.getElementById('u-filter-trigger');
  const options = document.getElementById('u-filter-options');
  const hidden  = document.getElementById('u-filter');
  const label   = document.getElementById('u-filter-label');

  function open()  { wrap.classList.add('open');    trigger.setAttribute('aria-expanded', 'true'); }
  function close() { wrap.classList.remove('open'); trigger.setAttribute('aria-expanded', 'false'); }
  function toggle() { wrap.classList.contains('open') ? close() : open(); }

  trigger.addEventListener('click', (e) => { e.stopPropagation(); toggle(); });

  options.addEventListener('click', (e) => {
    const opt = e.target.closest('.adm-custom-option');
    if (!opt) return;
    const val = opt.dataset.value;

    /* update hidden input & label */
    hidden.value = val;
    label.textContent = opt.textContent.trim();

    /* update selected state */
    options.querySelectorAll('.adm-custom-option').forEach(o => o.classList.remove('adm-custom-option--selected'));
    opt.classList.add('adm-custom-option--selected');

    close();
    applyUserFilters();
  });

  /* close on outside click */
  document.addEventListener('click', (e) => {
    if (!wrap.contains(e.target)) close();
  });

  /* keyboard: Escape closes */
  trigger.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') close();
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
  });
})();

/* ══════════════════════════════════════════
   TIMELINE TAB
══════════════════════════════════════════ */
let allTimeline = [];

async function loadTimeline() {
  const list = document.getElementById('tl-list');
  list.innerHTML = '<div class="adm-empty">Loading…</div>';
  try {
    allTimeline = await apiFetch('/timeline');
    renderTimeline(allTimeline);
  } catch (err) {
    list.innerHTML = `<div class="adm-empty" style="color:#ff6b6b">Error: ${esc(err.message)}</div>`;
  }
}

function renderTimeline(items) {
  const list = document.getElementById('tl-list');
  if (!items.length) { list.innerHTML = '<div class="adm-empty">No timeline entries yet.</div>'; return; }

  list.innerHTML = items.map(item => {
    const typeClass = item.type === 'education' ? 'edu' : 'exp';
    const typeLabel = item.type === 'education' ? 'Education' : 'Experience';
    return `<div class="adm-item-card">
      <div class="adm-item-info">
        <p class="adm-item-title">${esc(item.title)}</p>
        <p class="adm-item-sub">${esc(item.company || item.institution || '')} · ${esc(item.period || '')}</p>
        <p class="adm-item-meta"><span class="adm-type-pill ${typeClass}">${typeLabel}</span></p>
      </div>
      <div class="adm-item-actions">
        <button class="adm-edit-btn" onclick="openTimelineForm('${esc(item._id)}')">Edit</button>
        <button class="adm-del-btn" onclick="deleteTimeline('${esc(item._id)}', '${esc(item.title)}')">Delete</button>
      </div>
    </div>`;
  }).join('');
}

document.getElementById('tl-add-btn').addEventListener('click', () => openTimelineForm(null));
document.getElementById('tl-cancel').addEventListener('click', () => { document.getElementById('tl-form-wrap').hidden = true; });

window.openTimelineForm = function (id) {
  const formWrap = document.getElementById('tl-form-wrap');
  const form = document.getElementById('tl-form');
  document.getElementById('tl-err').textContent = '';
  document.getElementById('tl-pdf-status').textContent = '';
  document.getElementById('tl-pdf-status').className = 'adm-file-status';

  if (!id) {
    document.getElementById('tl-form-title').textContent = 'Add Timeline Entry';
    form.reset();
    document.getElementById('tl-id').value = '';
  } else {
    const item = allTimeline.find(t => t._id === id);
    if (!item) return;
    document.getElementById('tl-form-title').textContent = 'Edit Timeline Entry';
    document.getElementById('tl-id').value = item._id;
    document.getElementById('tl-title').value = item.title || '';
    document.getElementById('tl-titleAr').value = item.titleAr || '';
    document.getElementById('tl-company').value = item.company || item.institution || '';
    document.getElementById('tl-period').value = item.period || '';
    document.getElementById('tl-type').value = item.type || 'experience';
    document.getElementById('tl-desc').value = item.description || '';
    document.getElementById('tl-descAr').value = item.descriptionAr || '';
  }

  formWrap.hidden = false;
  formWrap.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

document.getElementById('tl-form').addEventListener('submit', async function (e) {
  e.preventDefault();
  const errEl = document.getElementById('tl-err');
  const statusEl = document.getElementById('tl-pdf-status');
  errEl.textContent = '';

  const id = document.getElementById('tl-id').value;
  const pdfFile = document.getElementById('tl-pdf').files[0];
  let pdfPath = null;

  /* Upload PDF first if provided */
  if (pdfFile) {
    statusEl.textContent = 'Uploading PDF…';
    statusEl.className = 'adm-file-status';
    try {
      const fd = new FormData();
      fd.append('pdf', pdfFile);
      const res = await fetch(API + '/admin/upload-pdf', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${getToken()}` },
        body: fd
      });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).message || 'Upload failed');
      const data = await res.json();
      pdfPath = data.path;
      statusEl.textContent = 'PDF uploaded: ' + pdfPath;
      statusEl.className = 'adm-file-status ok';
    } catch (err) {
      statusEl.textContent = 'PDF upload failed: ' + err.message;
      statusEl.className = 'adm-file-status err';
      return;
    }
  }

  const payload = {
    title:         document.getElementById('tl-title').value.trim(),
    titleAr:       document.getElementById('tl-titleAr').value.trim(),
    company:       document.getElementById('tl-company').value.trim(),
    period:        document.getElementById('tl-period').value.trim(),
    type:          document.getElementById('tl-type').value,
    description:   document.getElementById('tl-desc').value.trim(),
    descriptionAr: document.getElementById('tl-descAr').value.trim(),
  };
  if (pdfPath) payload.pdfPath = pdfPath;

  if (!payload.title) { errEl.textContent = 'Title (EN) is required.'; return; }

  try {
    if (id) {
      const updated = await apiFetch(`/admin/timeline/${id}`, {
        method: 'PUT', body: JSON.stringify(payload),
        headers: { 'Content-Type': 'application/json' }
      });
      allTimeline = allTimeline.map(t => t._id === id ? updated : t);
    } else {
      const created = await apiFetch('/admin/timeline', {
        method: 'POST', body: JSON.stringify(payload),
        headers: { 'Content-Type': 'application/json' }
      });
      allTimeline.unshift(created);
    }
    renderTimeline(allTimeline);
    document.getElementById('tl-form-wrap').hidden = true;
  } catch (err) {
    errEl.textContent = err.message;
  }
});

window.deleteTimeline = async function (id, label) {
  if (!confirm(`Delete "${label}"?`)) return;
  try {
    await apiFetch(`/admin/timeline/${id}`, { method: 'DELETE' });
    allTimeline = allTimeline.filter(t => t._id !== id);
    renderTimeline(allTimeline);
  } catch (err) {
    alert('Failed to delete: ' + err.message);
  }
};

/* ══════════════════════════════════════════
   PROJECTS TAB
══════════════════════════════════════════ */
let allProjects = [];

async function loadProjects() {
  const list = document.getElementById('pr-list');
  list.innerHTML = '<div class="adm-empty">Loading…</div>';
  try {
    allProjects = await apiFetch('/projects');
    renderProjects(allProjects);
  } catch (err) {
    list.innerHTML = `<div class="adm-empty" style="color:#ff6b6b">Error: ${esc(err.message)}</div>`;
  }
}

function renderProjects(items) {
  const list = document.getElementById('pr-list');
  if (!items.length) { list.innerHTML = '<div class="adm-empty">No projects yet.</div>'; return; }

  list.innerHTML = items.map(p => {
    const thumb = p.image
      ? `<img src="${esc(p.image)}" alt="" class="adm-item-thumb" />`
      : '';
    return `<div class="adm-item-card">
      ${thumb}
      <div class="adm-item-info">
        <p class="adm-item-title">${esc(p.title)}</p>
        <p class="adm-item-sub">${esc((p.tags || []).join(', '))}</p>
        ${p.badge ? `<p class="adm-item-meta"><span class="adm-type-pill exp">${esc(p.badge)}</span></p>` : ''}
      </div>
      <div class="adm-item-actions">
        <button class="adm-edit-btn" onclick="openProjectForm('${esc(p._id)}')">Edit</button>
        <button class="adm-del-btn" onclick="deleteProject('${esc(p._id)}', '${esc(p.title)}')">Delete</button>
      </div>
    </div>`;
  }).join('');
}

document.getElementById('pr-add-btn').addEventListener('click', () => openProjectForm(null));
document.getElementById('pr-cancel').addEventListener('click', () => { document.getElementById('pr-form-wrap').hidden = true; });

/* Image preview */
document.getElementById('pr-image').addEventListener('change', function () {
  const preview = document.getElementById('pr-img-preview');
  const file = this.files[0];
  if (!file) { preview.innerHTML = ''; return; }
  const url = URL.createObjectURL(file);
  preview.innerHTML = `<img src="${url}" alt="preview" />`;
});

window.openProjectForm = function (id) {
  const formWrap = document.getElementById('pr-form-wrap');
  const form = document.getElementById('pr-form');
  document.getElementById('pr-err').textContent = '';
  document.getElementById('pr-img-preview').innerHTML = '';

  if (!id) {
    document.getElementById('pr-form-title').textContent = 'Add Project';
    form.reset();
    document.getElementById('pr-id').value = '';
  } else {
    const p = allProjects.find(x => x._id === id);
    if (!p) return;
    document.getElementById('pr-form-title').textContent = 'Edit Project';
    document.getElementById('pr-id').value = p._id;
    document.getElementById('pr-title').value = p.title || '';
    document.getElementById('pr-titleAr').value = p.titleAr || '';
    document.getElementById('pr-desc').value = p.description || '';
    document.getElementById('pr-descAr').value = p.descriptionAr || '';
    document.getElementById('pr-github').value = p.github || '';
    document.getElementById('pr-demo').value = p.demo || '';
    document.getElementById('pr-tags').value = (p.tags || []).join(', ');
    document.getElementById('pr-badge').value = p.badge || '';
    if (p.image) {
      document.getElementById('pr-img-preview').innerHTML = `<img src="${esc(p.image)}" alt="current" />`;
    }
  }

  formWrap.hidden = false;
  formWrap.scrollIntoView({ behavior: 'smooth', block: 'start' });
};

document.getElementById('pr-form').addEventListener('submit', async function (e) {
  e.preventDefault();
  const errEl = document.getElementById('pr-err');
  errEl.textContent = '';

  const id = document.getElementById('pr-id').value;
  const imageFile = document.getElementById('pr-image').files[0];

  const fd = new FormData();
  fd.append('title',         document.getElementById('pr-title').value.trim());
  fd.append('titleAr',       document.getElementById('pr-titleAr').value.trim());
  fd.append('description',   document.getElementById('pr-desc').value.trim());
  fd.append('descriptionAr', document.getElementById('pr-descAr').value.trim());
  fd.append('github',        document.getElementById('pr-github').value.trim());
  fd.append('demo',          document.getElementById('pr-demo').value.trim());
  fd.append('tags',          document.getElementById('pr-tags').value.trim());
  fd.append('badge',         document.getElementById('pr-badge').value.trim());
  if (imageFile) fd.append('image', imageFile);

  if (!fd.get('title')) { errEl.textContent = 'Title (EN) is required.'; return; }

  try {
    const endpoint = id ? `/admin/projects/${id}` : '/admin/projects';
    const method   = id ? 'PUT' : 'POST';
    const res = await fetch(API + endpoint, {
      method,
      headers: { 'Authorization': `Bearer ${getToken()}` },
      body: fd
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).message || `HTTP ${res.status}`);
    const saved = await res.json();

    if (id) {
      allProjects = allProjects.map(p => p._id === id ? saved : p);
    } else {
      allProjects.unshift(saved);
    }
    renderProjects(allProjects);
    document.getElementById('pr-form-wrap').hidden = true;
  } catch (err) {
    errEl.textContent = err.message;
  }
});

window.deleteProject = async function (id, label) {
  if (!confirm(`Delete project "${label}"?`)) return;
  try {
    await apiFetch(`/admin/projects/${id}`, { method: 'DELETE' });
    allProjects = allProjects.filter(p => p._id !== id);
    renderProjects(allProjects);
  } catch (err) {
    alert('Failed to delete: ' + err.message);
  }
};

/* ══════════════════════════════════════════
   SETTINGS TAB — Profile Picture
══════════════════════════════════════════ */
document.getElementById('settings-pp-form').addEventListener('submit', async function (e) {
  e.preventDefault();
  const errEl = document.getElementById('settings-pp-err');
  errEl.textContent = '';
  const file = document.getElementById('settings-pp-file').files[0];
  if (!file) { errEl.textContent = 'Please choose a photo.'; return; }

  const fd = new FormData();
  fd.append('photo', file);

  try {
    const res = await fetch(API + '/admin/profile-picture', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${getToken()}` },
      body: fd
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).message || 'Upload failed');
    const data = await res.json();
    document.getElementById('settings-pp-img').src = data.path + '?t=' + Date.now();
    errEl.style.color = '#4ade80';
    errEl.textContent = 'Profile picture updated!';
  } catch (err) {
    errEl.style.color = '#ff6b6b';
    errEl.textContent = err.message;
  }
});

/* ══════════════════════════════════════════
   ARABIC TRANSLATOR (MyMemory API)
══════════════════════════════════════════ */
document.querySelectorAll('.adm-tr-btn').forEach(btn => {
  btn.addEventListener('click', async function () {
    const srcId = this.dataset.src;
    const dstId = this.dataset.dst;
    const srcEl = document.getElementById(srcId);
    const dstEl = document.getElementById(dstId);
    if (!srcEl || !dstEl) return;

    const text = srcEl.value.trim();
    if (!text) return;

    this.disabled = true;
    this.textContent = '…';

    try {
      const url = `https://api.mymemory.translated.net/get?q=${encodeURIComponent(text)}&langpair=en|ar`;
      const res = await fetch(url);
      const data = await res.json();
      const translation = data?.responseData?.translatedText;
      if (translation) dstEl.value = translation;
    } catch (_) {
      /* fail silently */
    } finally {
      this.disabled = false;
      this.textContent = '↔ AR';
    }
  });
});
