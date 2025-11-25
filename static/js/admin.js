// Admin: gate, show quick proof panels (profiles + reviews/day + dump button)
(async function () {
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
})();
