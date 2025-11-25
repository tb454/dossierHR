// Manager: gate and list profiles (same renderer)
(async function () {
  const who = await requireRole(['manager','admin']);
  if (!who) return;
  const banner = document.querySelector('#whoami');
  if (banner) banner.textContent = `Signed in as ${who.email} (${who.role})`;

  const search = document.querySelector('#search');
  const box = document.querySelector('#profiles-box');

  async function refresh(q='') {
    try {
      const rows = await loadProfiles({ q, limit: 20 });
      renderProfiles(rows, box);
    } catch {
      box.textContent = 'Failed to load profiles.';
    }
  }

  await refresh();
  if (search) {
    search.addEventListener('input', () => refresh(search.value.trim()));
  }
})();
