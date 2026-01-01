//viewer.js
// Load profiles from backend (NOT a static json file)
async function loadProfiles({ q = null, limit = 12, offset = 0 } = {}) {
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  params.set("limit", String(limit));
  params.set("offset", String(offset));

  const res = await fetch(`/profiles?${params.toString()}`, { credentials: "include" });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(txt || "Failed to load profiles");
  }
  return await res.json();
}


function renderProfiles(profiles, container) {
  container.innerHTML = "";
  (profiles || []).forEach(p => {
    const card = document.createElement("div");
    card.className = "bg-white rounded-xl shadow p-4 flex flex-col";

    const overviewId = `overview-${p.id}`;
    const contactId = `contact-${p.id}`;

    const name = p.display_name || p.name || "(unnamed)";
    const website = p.external_ref || "";
    const pic = p.picture_url || "";
    const created = p.created_at ? new Date(p.created_at).toLocaleString() : "";

    card.innerHTML = `
      <div class="flex items-start gap-3">
        ${pic ? `<img src="${pic}" class="w-10 h-10 rounded-full object-cover" />` : `<div class="w-10 h-10 rounded-full bg-gray-200"></div>`}
        <div class="min-w-0">
          <h2 class="text-lg font-semibold mb-0.5 truncate">${name}</h2>
          <div class="text-xs text-gray-500 font-mono truncate">${p.id || ""}</div>
        </div>
      </div>

      <div class="flex space-x-2 mt-3">
        <button class="px-3 py-1 text-white bg-blue-600 rounded" data-target="${overviewId}">Overview</button>
        <button class="px-3 py-1 text-gray-800 bg-gray-200 rounded" data-target="${contactId}">Links</button>
      </div>

      <div id="${overviewId}" class="mt-3">
        <ul class="space-y-1 text-sm">
          <li><span class="text-gray-500">Created:</span> ${created || "-"}</li>
          <li><span class="text-gray-500">Deleted:</span> ${p.deleted_at ? new Date(p.deleted_at).toLocaleString() : "—"}</li>
        </ul>
      </div>

      <div id="${contactId}" class="mt-3 hidden text-sm space-y-1">
        <div><span class="text-gray-500">Website:</span> ${
          website
            ? `<a class="text-blue-600 underline break-all" href="${website}" target="_blank" rel="noopener">${website}</a>`
            : "—"
        }</div>
      </div>
    `;

    // Tab toggles
    card.querySelectorAll("button[data-target]").forEach(btn => {
      btn.addEventListener("click", () => {
        card.querySelectorAll(`[id^="overview-"], [id^="contact-"]`).forEach(el => el.classList.add("hidden"));
        const tgt = btn.getAttribute("data-target");
        const el = card.querySelector(`#${tgt}`);
        if (el) el.classList.remove("hidden");
      });
    });

    container.appendChild(card);
  });

  if (!profiles || !profiles.length) {
    container.innerHTML = `<div class="text-gray-500 text-sm">No profiles yet.</div>`;
  }
}

// Expose helpers globally (admin.js calls them directly)
window.loadProfiles = loadProfiles;
window.renderProfiles = renderProfiles;
