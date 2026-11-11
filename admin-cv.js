/* ═══════════════════════════════════════════
   ADMIN — CV Generations tab (uses esc() and apiFetch() from admin.js)
═══════════════════════════════════════════ */
(function () {
  'use strict';
  const tab = document.querySelector('.adm-tab[data-tab="cvgens"]');
  const tbody = document.getElementById('cg-tbody');
  if (!tab || !tbody) return;

  let all = [];
  let loadedOnce = false;

  const fmt = (d) => (d ? new Date(d).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');

  async function load() {
    tbody.innerHTML = '<tr><td colspan="7" class="adm-loading">Loading…</td></tr>';
    try {
      const data = await apiFetch('/admin/cv-generations');
      all = Array.isArray(data) ? data : [];
      applyFilter();
    } catch (err) {
      tbody.innerHTML = `<tr><td colspan="7" class="adm-loading" style="color:#ff6b6b">Failed to load: ${esc(err.message)}</td></tr>`;
    }
  }

  function applyFilter() {
    const q = document.getElementById('cg-search').value.trim().toLowerCase();
    const list = !q ? all : all.filter((g) => [g.ref, g.userName, g.userEmail, g.job?.company, g.job?.jobTitle]
      .some((v) => String(v || '').toLowerCase().includes(q)));
    render(list);
  }

  function render(list) {
    document.getElementById('cg-count').textContent = all.length;
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="adm-loading">No CV generations yet.</td></tr>';
      return;
    }
    tbody.innerHTML = list.map((g) => {
      const j = g.job || {};
      const canPdf = g.status === 'ready' || g.status === 'downloaded';
      return `<tr>
        <td>${esc(fmt(g.createdAt))}</td>
        <td class="cg-mono">${esc(g.ref)}</td>
        <td>${esc(g.userName || '—')}<span class="cg-sub">${esc(g.userEmail || '')}</span></td>
        <td>${esc(j.company || '—')}<span class="cg-sub">${esc(j.jobTitle || '')}</span></td>
        <td class="cg-mono">${esc((j.language || '').toUpperCase())} · ${esc(String(j.pages || '—'))}p</td>
        <td><span class="cg-status cg-status--${esc(g.status)}">${esc(g.status)}</span>${g.failure ? `<span class="cg-sub">${esc(g.failure)}</span>` : ''}${g.countsTowardQuota === false ? '<span class="cg-sub">quota reset</span>' : ''}</td>
        <td><div class="cg-actions">
          <button type="button" class="adm-btn-ghost" data-act="view" data-ref="${esc(g.ref)}">View</button>
          ${canPdf ? `<button type="button" class="adm-btn-ghost" data-act="pdf" data-ref="${esc(g.ref)}">PDF</button>` : ''}
          <button type="button" class="adm-del-btn" data-act="del" data-ref="${esc(g.ref)}">Delete</button>
        </div></td>
      </tr>`;
    }).join('');
  }

  async function view(ref) {
    const dlg = document.getElementById('cg-dialog');
    const bodyEl = document.getElementById('cg-dialog-body');
    document.getElementById('cg-dialog-title').textContent = ref;
    bodyEl.innerHTML = '<p>Loading…</p>';
    if (typeof dlg.showModal === 'function') dlg.showModal(); else dlg.setAttribute('open', '');
    try {
      const g = await apiFetch(`/admin/cv-generations/${encodeURIComponent(ref)}`);
      const j = g.job || {};
      const li = (arr) => (arr && arr.length ? `<ul>${arr.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '<p>—</p>');
      const rejected = g.validator?.rejected || [];
      bodyEl.innerHTML = `
        <dl class="cg-kv">
          <dt>Requested by</dt><dd>${esc(g.userName)} · ${esc(g.userEmail)}</dd>
          <dt>Created</dt><dd>${esc(fmt(g.createdAt))} · ${esc(String(Math.round((g.durationMs || 0) / 100) / 10))}s · ${esc(g.model || '')}</dd>
          <dt>Status</dt><dd>${esc(g.status)}${g.failure ? ' (' + esc(g.failure) + ')' : ''}${g.downloadedAt ? ' · downloaded ' + esc(fmt(g.downloadedAt)) : ''}</dd>
          <dt>Role</dt><dd>${esc(j.jobTitle)} at ${esc(j.company)}</dd>
          <dt>Options</dt><dd>${esc((j.language || '').toUpperCase())} · ${esc(String(j.pages))} page(s) requested · ${esc(String(g.pages || '—'))} produced · ${esc(j.seniority)} · ${esc(j.workMode)}</dd>
          <dt>Must-have skills</dt><dd>${esc((j.mustHaveSkills || []).join(', ') || '—')}</dd>
          <dt>IP</dt><dd class="cg-mono">${esc(g.ip || '—')}</dd>
        </dl>
        <h4>Matched requirements</h4>${li(g.match?.matched)}
        <h4>Not in profile (shown as gaps)</h4>${li(g.match?.missing)}
        <h4>Validator — AI lines rejected (${rejected.length})</h4>
        ${rejected.length ? `<ul>${rejected.map((r) => `<li><strong>${esc(r.where)}</strong>: ${esc(r.reason)}<br><small>${esc(r.text)}</small></li>`).join('')}</ul>` : '<p>None — every AI line passed the fact check.</p>'}
        <h4>Job description</h4><pre>${esc(j.jobDescription || '')}</pre>
        ${g.user ? `<h4>Quota</h4><button type="button" class="adm-btn-ghost" id="cg-reset" data-user="${esc(g.user)}">Reset this user's quota for this month</button>` : ''}`;
      const reset = document.getElementById('cg-reset');
      if (reset) reset.addEventListener('click', async () => {
        if (!confirm('Reset this user\'s CV quota for the current month?')) return;
        try {
          const r = await apiFetch(`/admin/cv-quota/${encodeURIComponent(reset.dataset.user)}/reset`, { method: 'POST', body: '{}' });
          reset.textContent = `Quota reset (${r.updated} record${r.updated === 1 ? '' : 's'})`;
          reset.disabled = true;
          load();
        } catch (err) { alert('Failed: ' + err.message); }
      });
    } catch (err) {
      bodyEl.innerHTML = `<p style="color:#ff6b6b">Failed to load: ${esc(err.message)}</p>`;
    }
  }

  async function pdf(ref, btn) {
    const label = btn.textContent;
    btn.textContent = '…'; btn.disabled = true;
    try {
      const res = await fetch(`${API}/admin/cv-generations/${encodeURIComponent(ref)}/pdf`, { headers: { Authorization: `Bearer ${getToken()}` } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      const cd = res.headers.get('Content-Disposition') || '';
      const name = (/filename="([^"]+)"/.exec(cd) || [])[1] || `${ref}.pdf`;
      const url = URL.createObjectURL(blob);
      const a = Object.assign(document.createElement('a'), { href: url, download: name });
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (err) {
      alert('Could not render PDF: ' + err.message);
    } finally {
      btn.textContent = label; btn.disabled = false;
    }
  }

  async function del(ref) {
    if (!confirm(`Delete generation ${ref}? This cannot be undone.`)) return;
    try {
      await apiFetch(`/admin/cv-generations/${encodeURIComponent(ref)}`, { method: 'DELETE' });
      all = all.filter((g) => g.ref !== ref);
      applyFilter();
    } catch (err) { alert('Failed to delete: ' + err.message); }
  }

  tbody.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const { act, ref } = btn.dataset;
    if (act === 'view') view(ref);
    else if (act === 'pdf') pdf(ref, btn);
    else if (act === 'del') del(ref);
  });
  document.getElementById('cg-search').addEventListener('input', applyFilter);
  document.getElementById('cg-refresh').addEventListener('click', load);
  document.getElementById('cg-dialog-close').addEventListener('click', () => document.getElementById('cg-dialog').close());
  tab.addEventListener('click', () => { if (!loadedOnce) { loadedOnce = true; load(); } });
})();
