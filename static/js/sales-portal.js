async function reqJSON(url, opts = {}) {
  const res = await fetch(url, {
    credentials: "include",
    ...opts,
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  const txt = await res.text();
  let json;
  try { json = JSON.parse(txt); } catch { json = { raw: txt }; }
  if (!res.ok) throw new Error(json.detail || txt || "Request failed");
  return json;
}

function money(cents) {
  const v = Number(cents || 0) / 100;
  return v.toLocaleString(undefined, { style: "currency", currency: "USD" });
}

function esc(s) {
  return String(s || "").replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

async function loadLeads() {
  const leadsEl = document.getElementById("leads");
  const q = document.getElementById("leadSearch").value.trim();
  const stage = document.getElementById("leadStage").value;

  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (stage) params.set("stage", stage);

  const out = await reqJSON("/sales/leads?" + params.toString());
  const leads = out.leads || [];

  if (!leads.length) {
    leadsEl.textContent = "No leads yet.";
    return;
  }

  leadsEl.innerHTML = `
    <div class="overflow-auto">
      <table class="w-full text-xs">
        <thead><tr class="text-left text-zinc-500">
          <th class="py-2">Company</th><th>Stage</th><th>Contact</th><th></th>
        </tr></thead>
        <tbody>
          ${leads.map(l => `
            <tr class="border-t align-top">
              <td class="py-2">
                <div class="font-medium">${esc(l.company_name)}</div>
                <div class="text-zinc-500">${esc(l.city)}${l.state ? ", " + esc(l.state) : ""}</div>
                ${l.notes ? `<div class="text-zinc-500 mt-1">${esc(l.notes)}</div>` : ""}
              </td>
              <td class="py-2">
                <select data-lead-id="${esc(l.id)}" class="leadStageSel border rounded p-1 text-xs">
                  ${["new","contacted","demo","sent_invoice","closed_won","closed_lost"].map(s =>
                    `<option value="${s}" ${l.stage===s ? "selected":""}>${s}</option>`
                  ).join("")}
                </select>
              </td>
              <td class="py-2 text-zinc-600">
                <div>${esc(l.contact_name)}</div>
                <div>${esc(l.contact_email)}</div>
                <div>${esc(l.contact_phone)}</div>
                <div>${esc(l.website)}</div>
              </td>
              <td class="py-2">
                <button data-act-id="${esc(l.id)}" class="logActBtn underline text-xs">log</button>
              </td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;

  // stage change handlers
  document.querySelectorAll(".leadStageSel").forEach(sel => {
    sel.addEventListener("change", async (e) => {
      const leadId = e.target.getAttribute("data-lead-id");
      const newStage = e.target.value;
      try {
        await reqJSON(`/sales/leads/${leadId}`, { method: "PATCH", body: JSON.stringify({ stage: newStage }) });
      } catch (err) {
        alert(err.message || "Failed to update stage");
      }
    });
  });

  // quick activity log handler
  document.querySelectorAll(".logActBtn").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      const leadId = e.target.getAttribute("data-act-id");
      const notes = prompt("Activity note (call/email/demo/etc):");
      if (!notes) return;
      try {
        await reqJSON(`/sales/leads/${leadId}/activity`, {
          method: "POST",
          body: JSON.stringify({ activity_type: "note", notes })
        });
        alert("Logged.");
      } catch (err) {
        alert(err.message || "Failed to log activity");
      }
    });
  });
}

async function loadAccountsAndLedger() {
  const accountsEl = document.getElementById("accounts");
  const ledgerEl = document.getElementById("ledger");

  const ac = await reqJSON("/sales/accounts");
  const accounts = ac.accounts || [];
  accountsEl.innerHTML = accounts.length ? `
    <div class="overflow-auto">
      <table class="w-full text-sm">
        <thead><tr class="text-left text-zinc-500">
          <th class="py-2">Account</th><th>Plan</th><th>Status</th><th>First Paid</th>
        </tr></thead>
        <tbody>
          ${accounts.map(a => `
            <tr class="border-t">
              <td class="py-2">${esc(a.company_name || a.bridge_account_id)}</td>
              <td>${esc(a.plan_tier || "-")}</td>
              <td>${esc(a.status || "-")}</td>
              <td>${a.first_paid_at ? new Date(a.first_paid_at).toLocaleDateString() : "-"}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>` : "No owned accounts yet.";

  const led = await reqJSON("/sales/ledger?limit=200");
  const rows = led.ledger || [];
  ledgerEl.innerHTML = rows.length ? `
    <div class="overflow-auto">
      <table class="w-full text-sm">
        <thead><tr class="text-left text-zinc-500">
          <th class="py-2">Account</th><th>Type</th><th>Amount</th><th>Status</th><th>Earn Date</th>
        </tr></thead>
        <tbody>
          ${rows.map(r => `
            <tr class="border-t">
              <td class="py-2">${esc(r.bridge_account_id)}</td>
              <td>${esc(r.line_type)}</td>
              <td>${money(r.amount_cents)}</td>
              <td>${esc(r.vesting_status)}</td>
              <td>${r.scheduled_earn_date ? new Date(r.scheduled_earn_date).toLocaleDateString() : "-"}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>` : "No commissions yet.";
}

document.addEventListener("DOMContentLoaded", async () => {
  const repMeta = document.getElementById("repMeta");
  const leadForm = document.getElementById("leadForm");
  const leadResult = document.getElementById("leadResult");

  try {
    const me = await reqJSON("/sales/me");
    const rep = me.rep || {};
    repMeta.innerHTML = `Logged in as <b>${esc(rep.email)}</b> • Code: <b>${esc(rep.referral_code)}</b> • Status: <b>${esc(rep.status)}</b>`;

    // Create lead
    leadForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      leadResult.textContent = "Saving...";
      const data = Object.fromEntries(new FormData(leadForm).entries());
      try {
        await reqJSON("/sales/leads", { method: "POST", body: JSON.stringify(data) });
        leadForm.reset();
        leadResult.textContent = "✅ Lead created.";
        await loadLeads();
      } catch (err) {
        leadResult.textContent = "❌ " + (err.message || "Failed");
      }
    });

    document.getElementById("leadSearch").addEventListener("input", () => {
      // cheap debounce
      clearTimeout(window.__leadT);
      window.__leadT = setTimeout(loadLeads, 250);
    });
    document.getElementById("leadStage").addEventListener("change", loadLeads);

    await loadLeads();
    await loadAccountsAndLedger();

  } catch (err) {
    repMeta.textContent = "Not authorized. Login first.";
    document.getElementById("leads").textContent = "—";
    document.getElementById("accounts").textContent = "—";
    document.getElementById("ledger").textContent = "—";
  }
});
