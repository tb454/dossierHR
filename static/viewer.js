async function loadProfiles() {
  const res = await fetch("/static/profiles.json");
  if (!res.ok) throw new Error("Failed to load profiles.json");
  return await res.json();
}

function renderProfiles(profiles, container) {
  container.innerHTML = "";
  profiles.forEach(p => {
    const card = document.createElement("div");
    card.className = "bg-white rounded-xl shadow p-4 flex flex-col";

    const overviewId = `overview-${p.id}`;
    const contactId = `contact-${p.id}`;

    card.innerHTML = `
      <h2 class="text-lg font-semibold mb-1">${p.name}</h2>
      <p class="text-sm text-gray-600 mb-2">${p.title}</p>
      <p class="text-sm mb-3">📍 ${p.location}</p>

      <div class="flex space-x-2">
        <button class="px-3 py-1 text-white bg-blue-600 rounded" data-target="${overviewId}">Overview</button>
        <button class="px-3 py-1 text-gray-800 bg-gray-200 rounded" data-target="${contactId}">Contact</button>
      </div>

      <div id="${overviewId}" class="mt-3">
        <ul class="space-y-1 text-sm">
          <li>⭐ Trust Score: ${p.trustScore}</li>
          <li>📝 Last Review: ${p.latestReview}</li>
          <li>🎓 Certs: ${p.certs}</li>
          <li>⚠️ Risk Level: ${p.risk}</li>
          <li>📈 Next Milestone: ${p.milestone}</li>
        </ul>
      </div>

      <div id="${contactId}" class="mt-3 hidden text-sm">
        <p>📧 ${p.email}</p>
        <p>🕒 Shift: ${p.shift}</p>
      </div>
    `;

    // Tab toggles
    card.querySelectorAll("button[data-target]").forEach(btn => {
      btn.addEventListener("click", () => {
        card.querySelectorAll(`[id^="overview-"], [id^="contact-"]`).forEach(el => el.classList.add("hidden"));
        const tgt = btn.getAttribute("data-target");
        card.querySelector(`#${tgt}`).classList.remove("hidden");
      });
    });

    container.appendChild(card);
  });
}
