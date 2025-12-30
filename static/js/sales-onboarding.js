import { reqJSON, esc } from "./sales-common.js";

let currentCompanyId = null;

async function loadChecklist(companyId) {
  currentCompanyId = companyId;
  const meta = document.getElementById("chkMeta");
  const stepsEl = document.getElementById("steps");

  const got = await reqJSON("/sales/onboarding?company_id=" + encodeURIComponent(companyId));
  if (!got.checklist) {
    await reqJSON("/sales/onboarding/create?company_id=" + encodeURIComponent(companyId), { method:"POST" });
  }
  const got2 = await reqJSON("/sales/onboarding?company_id=" + encodeURIComponent(companyId));

  meta.innerHTML = `Checklist status: <b>${esc(got2.checklist.status)}</b>`;
  const steps = got2.steps || [];
  stepsEl.innerHTML = steps.length ? `
    <table class="w-full text-sm">
      <thead><tr class="text-left text-zinc-500"><th class="py-2">Step</th><th>Status</th><th></th></tr></thead>
      <tbody>
        ${steps.map(s => `
          <tr class="border-t">
            <td class="py-2">${esc(s.label)}</td>
            <td>
              <select class="stepSel border rounded p-1 text-xs" data-id="${esc(s.id)}">
                ${["todo","doing","done","blocked"].map(st => `<option value="${st}" ${s.status===st?"selected":""}>${st}</option>`).join("")}
              </select>
            </td>
            <td><button class="blk underline text-xs" data-id="${esc(s.id)}">blocker</button></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  ` : "No steps.";
  document.querySelectorAll(".stepSel").forEach(sel => {
    sel.addEventListener("change", async (e) => {
      await reqJSON("/sales/onboarding/step/" + e.target.getAttribute("data-id"), { method:"PATCH", body: JSON.stringify({ status: e.target.value }) });
      await loadChecklist(currentCompanyId);
    });
  });
  document.querySelectorAll(".blk").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      const stepId = e.target.getAttribute("data-id");
      const notes = prompt("Blocker notes:");
      if (!notes) return;
      await reqJSON("/sales/onboarding/step/" + stepId, { method:"PATCH", body: JSON.stringify({ status:"blocked", blocker_notes: notes }) });
      await loadChecklist(currentCompanyId);
    });
  });
}

async function searchCompanies() {
  const q = document.getElementById("companyQ").value.trim();
  const out = await reqJSON("/sales/companies?q=" + encodeURIComponent(q));
  const rows = out.companies || [];
  const el = document.getElementById("companies");
  if (!rows.length) { el.textContent = "No companies."; return; }
  el.innerHTML = rows.map(c => `
    <div class="border-t py-2 flex items-center justify-between">
      <div><div class="font-medium">${esc(c.name)}</div><div class="text-xs text-zinc-500">${esc(c.domain||"")}</div></div>
      <button class="load border rounded-lg px-3 py-1 text-xs" data-id="${esc(c.id)}">Load</button>
    </div>
  `).join("");
  document.querySelectorAll(".load").forEach(b => {
    b.addEventListener("click", async (e) => {
      await loadChecklist(e.target.getAttribute("data-id"));
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("search").addEventListener("click", searchCompanies);
});
