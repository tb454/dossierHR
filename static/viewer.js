// viewer.js
fetch('dossierHRProfiles.json')
  .then(res => res.json())
  .then(profiles => {
    const container = document.getElementById('profile-container');
    profiles.forEach(p => {
      const card = document.createElement('div');
      card.className = 'bg-white rounded-lg shadow p-4 flex flex-col';
      card.innerHTML = `
        <h2 class="text-xl font-semibold mb-1">${p.name}</h2>
        <p class="text-sm text-gray-600 mb-2">${p.title}</p>
        <p class="text-sm mb-3">📍 ${p.location}</p>
        <div class="flex space-x-2">
          <button onclick="showSection('overview-${p.id}')" class="px-3 py-1 text-white bg-blue-500 rounded">Overview</button>
          <button onclick="showSection('contact-${p.id}')" class="px-3 py-1 text-gray-700 bg-gray-200 rounded">Contact</button>
        </div>
        <div id="overview-${p.id}" class="mt-3">
          <ul class="space-y-1 text-sm">
            <li>⭐ Trust Score: ${p.trustScore}</li>
            <li>📝 Last Review: ${p.latestReview}</li>
            <li>🎓 Certs: ${p.certs}</li>
            <li>⚠️ Risk Level: ${p.risk}</li>
            <li>📈 Next Milestone: ${p.milestone}</li>
          </ul>
        </div>
        <div id="contact-${p.id}" class="mt-3 hidden text-sm">
          <p>📧 ${p.email}</p>
          <p>🕒 Shift: ${p.shift}</p>
        </div>
      `;
      container.appendChild(card);
    });
  })
  .catch(err => console.error('Failed loading profiles:', err));

function showSection(id) {
  // hide all overview/contact sections
  document.querySelectorAll('[id^="overview-"], [id^="contact-"]').forEach(el => el.classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
}
