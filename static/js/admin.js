// Admin.js
(async function () {
    function renderIngest(rows, el) {
    if (!el) return;
    el.innerHTML = '';
    if (!rows || !rows.length) {
      el.innerHTML = '<div class="text-gray-500">No BRidge events yet.</div>';
      return;
    }
    for (const r of rows) {
      const d = new Date(r.created_at);
      const item = document.createElement('div');
      item.className = 'border rounded-lg p-3 bg-white/50';
      item.innerHTML = `
        <div class="flex items-center justify-between">
          <div class="font-mono text-xs text-gray-500">${d.toLocaleString()}</div>
          <span class="text-xs px-2 py-0.5 rounded bg-gray-100">${r.src || 'bridge'}</span>
        </div>
        <div class="mt-1 font-semibold break-all">${r.event_type || '(event)'}</div>
        <pre class="mt-1 overflow-x-auto text-xs bg-gray-50 p-2 rounded">${JSON.stringify(r.payload || {}, null, 2)}</pre>
      `;
      el.appendChild(item);
    }
  }
  const who = await requireRole(['admin']);
  if (!who) return;

  // Session banner
  const banner = document.querySelector('#whoami');
  if (banner) banner.textContent = `Signed in as ${who.email} (${who.role})`;

  // Load profiles
  const profilesBox = document.querySelector('#profiles-box');
  if (profilesBox) {
    try {
      const rows = await loadProfiles({ limit: 12 });
      renderProfiles(rows, profilesBox);
    } catch (e) {
      profilesBox.textContent = 'Failed to load profiles.';
    }
  }

  // Reviews by day (simple text proof)
  const reviewsBox = document.querySelector('#reviews-by-day');
  if (reviewsBox) {
    try {
      const res = await fetch('/analytics/reviews_by_day?days=14', { credentials: 'include' });
      const data = await res.json();
      if (Array.isArray(data) && data.length) {
        reviewsBox.innerHTML = data
          .map(r => `<div class="flex justify-between"><span>${new Date(r.day).toLocaleDateString()}</span><span class="font-semibold">${r.cnt}</span></div>`)
          .join('');
      } else {
        reviewsBox.textContent = 'No recent reviews.';
      }
    } catch {
      reviewsBox.textContent = 'Failed to load analytics.';
    }
  }

  // Nightly dump button → proves admin-only action + export path comes back
  const dumpBtn = document.querySelector('#run-dump');
  const dumpOut = document.querySelector('#dump-out');
  if (dumpBtn && dumpOut) {
    dumpBtn.addEventListener('click', async () => {
      dumpBtn.disabled = true; dumpOut.textContent = 'Running…';
      try {
        const r = await fetch('/admin/run_nightly_dump', { method: 'POST', credentials: 'include' });
        const j = await r.json();
        if (j.ok) {
          dumpOut.innerHTML = `Dump ready: <code>${j.file_path}</code> • ID: ${j.dump_id}`;
        } else {
          dumpOut.textContent = 'Dump failed.';
        }
      } catch {
        dumpOut.textContent = 'Dump failed.';
      } finally {
        dumpBtn.disabled = false;
      }
    });
  }

  // Live BRidge events
  const ingestBox = document.querySelector('#ingest-list');
  const refreshBtn = document.querySelector('#refresh-ingest');
  async function loadIngest() {
    try {
      const r = await fetch('/ingest/recent_bridge?limit=25', { credentials: 'include' });
      const j = await r.json();
      renderIngest(j, ingestBox);
    } catch (e) {
      if (ingestBox) ingestBox.textContent = 'Failed to load BRidge events.';
    }
  }
  if (ingestBox) {
    await loadIngest();
    if (refreshBtn) refreshBtn.addEventListener('click', loadIngest);
  }
})();
