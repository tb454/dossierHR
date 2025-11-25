// Employee: show session + a tiny message. (You can expand later.)
(async function () {
  const who = await requireRole(['employee','manager','admin']);
  if (!who) return;

  const banner = document.querySelector('#whoami');
  if (banner) banner.textContent = `Signed in as ${who.email} (${who.role})`;

  const box = document.querySelector('#employee-proof');
  if (box) {
    box.innerHTML = `
      <div class="rounded-2xl bg-white shadow p-4">
        <div class="font-semibold mb-1">Dossier is ingest-ready</div>
        <div class="text-sm text-gray-600">Your session is active and the backend endpoints are live.</div>
      </div>`;
  }
})();
