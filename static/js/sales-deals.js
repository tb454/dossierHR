import { reqJSON, esc, money } from "./sales-common.js";

async function loadDeals() {
  const q = document.getElementById("q").value.trim();
  const stage = document.getElementById("stage").value;
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (stage) params.set("stage", stage);

  const out = await reqJSON("/sales/deals?" + params.toString());
  const deals = out.deals || [];
  const el = document.getElementById("list");

  if (!deals.length) { el.textContent = "No deals."; return; }

  el.innerHTML = `
    <table class="w-full text-sm">
      <thead><tr class="text-left text-zinc-500">
        <th class="py-2">Company</th><th>Stage</th><th>Plan</th><th>MRR</th><th>Prob</th><th></th>
      </tr></thead>
      <tbody>
        ${deals.map(d => `
          <tr class="border-t">
            <td class="py-2">
              <div class="font-medium">${esc(d.company_name)}</div>
              <div class="text-xs text-zinc-500">${esc(d.domain||"")}</div>
            </td>
            <td>
              <select class="stageSel border rounded p-1 text-xs" data-id="${esc(d.id)}">
                ${["new","contacted","qualified","demo_scheduled","demo_done","proposal","negotiation","closed_won","closed_lost"]
                  .map(s => `<option value="${s}" ${d.stage===s?"selected":""}>${s}</option>`).join("")}
              </select>
            </td>
            <td>${esc(d.proposed_plan||"-")}</td>
            <td>${d.expected_mrr_cents ? money(d.expected_mrr_cents) : "-"}</td>
            <td>${esc(d.probability)}</td>
            <td><button class="editBtn underline text-xs" data-id="${esc(d.id)}">edit</button></td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;

  document.querySelectorAll(".stageSel").forEach(s => {
    s.addEventListener("change", async (e) => {
      await reqJSON(`/sales/deals/${e.target.getAttribute("data-id")}`, { method:"PATCH", body: JSON.stringify({ stage: e.target.value }) });
      await loadDeals();
    });
  });

  document.querySelectorAll(".editBtn").forEach(b => {
    b.addEventListener("click", async (e) => {
      const id = e.target.getAttribute("data-id");
      const proposed_plan = prompt("Plan (starter/standard/enterprise):");
      const expected_mrr_cents = prompt("Expected MRR cents (e.g. 1000000 for $10,000):");
      const probability = prompt("Probability 0-100:", "50");
      await reqJSON(`/sales/deals/${id}`, { method:"PATCH", body: JSON.stringify({
        proposed_plan: proposed_plan || null,
        expected_mrr_cents: expected_mrr_cents ? parseInt(expected_mrr_cents,10) : null,
        probability: probability ? parseInt(probability,10) : null
      })});
      await loadDeals();
    });
  });
}

async function searchCompanies() {
  const q = document.getElementById("companySearch").value.trim();
  if (!q) return;
  const out = await reqJSON("/sales/companies?q=" + encodeURIComponent(q));
  const rows = out.companies || [];
  const el = document.getElementById("companies");
  if (!rows.length) { el.textContent = "No companies."; return; }

  el.innerHTML = rows.map(c => `
    <div class="border-t py-2 flex items-center justify-between">
      <div>
        <div class="font-medium">${esc(c.name)}</div>
        <div class="text-xs text-zinc-500">${esc(c.domain||"")}</div>
      </div>
      <button class="mkDeal border rounded-lg px-3 py-1 text-xs" data-id="${esc(c.id)}">Create Deal</button>
    </div>
  `).join("");

  document.querySelectorAll(".mkDeal").forEach(b => {
    b.addEventListener("click", async (e) => {
      const company_id = e.target.getAttribute("data-id");
      await reqJSON("/sales/deals", { method:"POST", body: JSON.stringify({ company_id }) });
      alert("Deal created.");
      await loadDeals();
    });
  });
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("refresh").addEventListener("click", loadDeals);
  document.getElementById("searchBtn").addEventListener("click", searchCompanies);
  loadDeals();
});
