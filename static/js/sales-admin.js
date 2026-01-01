// static/js/sales-admin.js
import { reqJSON, esc } from "./sales-common.js";

async function loadReps() {
  const el = document.getElementById("reps");
  const out = await reqJSON("/admin/sales/reps?limit=50");
  const reps = out.reps || [];
  if (!reps.length) { el.textContent = "No reps."; return; }
  el.innerHTML = `
    <table class="w-full text-sm">
      <thead><tr class="text-left text-zinc-500">
        <th class="py-2">id</th><th>email</th><th>status</th><th>role</th><th>code</th>
      </tr></thead>
      <tbody>
        ${reps.map(r => `
          <tr class="border-t">
            <td class="py-2 text-xs">${esc(r.id)}</td>
            <td>${esc(r.email)}</td>
            <td>${esc(r.status)}</td>
            <td>${esc(r.role)}</td>
            <td>${esc(r.referral_code)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("invForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const outEl = document.getElementById("invOut");
    outEl.textContent = "Creating invite...";
    try {
      const data = Object.fromEntries(new FormData(e.target).entries());
      const r = await reqJSON("/admin/sales/invite", { method:"POST", body: JSON.stringify(data) });
      outEl.innerHTML = `✅ Invite link: <code>${esc(r.invite_url)}</code>`;
    } catch (err) {
      outEl.textContent = "❌ " + (err.message || "Error");
    }
  });

  document.getElementById("apprForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const outEl = document.getElementById("apprOut");
    outEl.textContent = "Approving...";
    try {
      const data = Object.fromEntries(new FormData(e.target).entries());
      const rep_id = data.rep_id;
      delete data.rep_id;
      await reqJSON(`/admin/sales/reps/${rep_id}/approve`, { method:"POST", body: JSON.stringify(data) });
      outEl.textContent = "✅ Approved.";
      await loadReps();
    } catch (err) {
      outEl.textContent = "❌ " + (err.message || "Error");
    }
  });

  document.getElementById("revForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const outEl = document.getElementById("revOut");
    outEl.textContent = "Posting revenue...";
    try {
      const data = Object.fromEntries(new FormData(e.target).entries());
      data.amount_cents = parseInt(data.amount_cents, 10);
      const r = await reqJSON("/admin/sales/revenue/post", { method:"POST", body: JSON.stringify(data) });
      outEl.textContent = "✅ Revenue posted. Commission " + (r.commission_created ? "created" : "NOT created");
    } catch (err) {
      outEl.textContent = "❌ " + (err.message || "Error");
    }
  });

  document.getElementById("assetForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const outEl = document.getElementById("assetOut");
    outEl.textContent = "Saving...";
    try {
      const data = Object.fromEntries(new FormData(e.target).entries());
      await reqJSON("/admin/sales/assets", { method:"POST", body: JSON.stringify(data) });
      outEl.textContent = "✅ Saved.";
    } catch (err) {
      outEl.textContent = "❌ " + (err.message || "Error");
    }
  });

  loadReps();
});
