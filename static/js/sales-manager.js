// static/js/sales-manager.js
import { reqJSON, esc, money } from "./sales-common.js";

document.addEventListener("DOMContentLoaded", async () => {
  // Gate: allow sales_manager + admin
  const who = await window.Auth.requireRole(['sales_manager','sales-manager','salesmanager','admin']);
  if (!who) return;

  const whoEl = document.getElementById("whoami");
  if (whoEl) whoEl.textContent = `Signed in as ${who.email} (${who.role})`;

  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) logoutBtn.addEventListener("click", () => window.Auth.logout());

  try {
    const r = await reqJSON("/admin/sales/dashboard");

    document.getElementById("pipe").innerHTML = `
      <table class="w-full text-sm">
        <thead><tr class="text-left text-zinc-500"><th class="py-2">Stage</th><th>Count</th></tr></thead>
        <tbody>${(r.pipeline||[]).map(x => `<tr class="border-t"><td class="py-2">${esc(x.stage)}</td><td>${x.cnt}</td></tr>`).join("")}</tbody>
      </table>
    `;

    document.getElementById("onb").innerHTML = `
      <table class="w-full text-sm">
        <thead><tr class="text-left text-zinc-500"><th class="py-2">Status</th><th>Count</th></tr></thead>
        <tbody>${(r.onboarding||[]).map(x => `<tr class="border-t"><td class="py-2">${esc(x.status)}</td><td>${x.cnt}</td></tr>`).join("")}</tbody>
      </table>
    `;

    document.getElementById("comm").innerHTML =
      `<div class="text-2xl font-bold">${money(r.pending_commission_cents)}</div>`;

  } catch (err) {
    document.getElementById("pipe").textContent = "Not authorized.";
    document.getElementById("onb").textContent = "Not authorized.";
    document.getElementById("comm").textContent = "Not authorized.";
  }
});

