import { reqJSON, esc } from "./sales-common.js";

function getScope(){
  const el = document.getElementById("scope");
  return el ? el.value : "mine";
}

async function load() {
  const q = document.getElementById("q").value.trim();
  const stage = document.getElementById("stage").value;
  const scope = getScope();

  const params = new URLSearchParams();
  if (q) params.set("q", q);
  if (stage) params.set("stage", stage);

  // House queue defaults to 50 max on the UI
  if (scope === "house") params.set("limit", "50");

  const url = (scope === "house")
    ? ("/sales/house_queue?" + params.toString())
    : ("/sales/leads?" + params.toString());

  const out = await reqJSON(url);
  const leads = out.leads || [];
  const el = document.getElementById("list");

  if (!leads.length) {
    el.textContent = (scope === "house") ? "House queue is empty." : "No leads.";
    return;
  }

  const isHouse = (scope === "house");

  el.innerHTML = `
    <table class="w-full text-sm">
      <thead><tr class="text-left text-zinc-500">
        <th class="py-2">Company</th>
        <th>${isHouse ? "Queue" : "Stage"}</th>
        <th>Contact</th>
        <th>Follow-up</th>
        <th></th>
      </tr></thead>
      <tbody>
        ${leads.map(l => `
          <tr class="border-t align-top">
            <td class="py-2">
              <div class="font-medium">${esc(l.company_name)}</div>
              <div class="text-xs text-zinc-500">${esc(l.domain || "")}</div>
              <div class="text-xs text-zinc-500">${esc(l.city||"")}${l.state?(", "+esc(l.state)):""}</div>
            </td>

            <td class="py-2">
              ${
                isHouse
                  ? `<div class="text-xs text-zinc-600">unclaimed</div>`
                  : `
                    <select data-id="${esc(l.id)}" class="stageSel border rounded p-1 text-xs">
                      ${["new","contacted","qualified","demo_scheduled","demo_done","proposal","negotiation","closed_won","closed_lost"]
                        .map(s => `<option value="${s}" ${l.stage===s?"selected":""}>${s}</option>`).join("")}
                    </select>
                    <div class="mt-2">
                      <button data-act="${esc(l.id)}" class="logBtn underline text-xs">log</button>
                    </div>
                  `
              }
            </td>

            <td class="py-2 text-xs text-zinc-600">
              <div>${esc(l.contact_name||"")}</div>
              <div>${esc(l.contact_email||"")}</div>
              <div>${esc(l.contact_phone||"")}</div>
            </td>

            <td class="py-2 text-xs text-zinc-600">${l.next_follow_up_at ? new Date(l.next_follow_up_at).toLocaleDateString() : "-"}</td>

            <td class="py-2 text-xs">
              ${
                isHouse
                  ? `<button data-claim="${esc(l.id)}" class="claimBtn underline">claim</button>`
                  : `<button data-task="${esc(l.id)}" class="taskBtn underline">task</button>`
              }
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;

  // My Leads: stage edits + activity logs + tasks
  if (!isHouse) {
    document.querySelectorAll(".stageSel").forEach(s => {
      s.addEventListener("change", async (e) => {
        const id = e.target.getAttribute("data-id");
        await reqJSON(`/sales/leads/${id}`, { method:"PATCH", body: JSON.stringify({ stage: e.target.value }) });
      });
    });

    document.querySelectorAll(".logBtn").forEach(b => {
      b.addEventListener("click", async (e) => {
        const id = e.target.getAttribute("data-act");
        const type = prompt("Type: call/email/demo/note/text/other", "call");
        if (!type) return;
        const notes = prompt("Notes:");
        if (!notes) return;
        const follow = prompt("Follow-up date YYYY-MM-DD (optional):");
        const follow_up_at = follow ? (follow.trim() + "T09:00:00") : null;
        await reqJSON(`/sales/leads/${id}/activity`, { method:"POST", body: JSON.stringify({ activity_type: type, notes, follow_up_at }) });
        await load();
      });
    });

    document.querySelectorAll(".taskBtn").forEach(b => {
      b.addEventListener("click", async (e) => {
        const leadId = e.target.getAttribute("data-task");
        const title = prompt("Task title:");
        if (!title) return;
        const due = prompt("Due date YYYY-MM-DD:", new Date().toISOString().slice(0,10));
        if (!due) return;
        await reqJSON("/sales/tasks", { method:"POST", body: JSON.stringify({ title, due_at: due + "T17:00:00", lead_id: leadId }) });
        alert("Task created.");
      });
    });
  }

  // House Queue: claim
  if (isHouse) {
    document.querySelectorAll(".claimBtn").forEach(b => {
      b.addEventListener("click", async (e) => {
        const id = e.target.getAttribute("data-claim");
        if (!confirm("Claim this lead?")) return;
        try {
          await reqJSON(`/sales/house_queue/${id}/claim`, { method:"POST" });
          alert("✅ Claimed. It’s now in My Leads.");
          // auto-switch to My Leads
          const scopeEl = document.getElementById("scope");
          if (scopeEl) scopeEl.value = "mine";
          await load();
        } catch (err) {
          // backend will return 409 if already claimed OR if you hit the 50-lead max
          alert("❌ " + (err.message || "Could not claim"));
          await load();
        }
      });
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // Inject Scope dropdown into the toolbar (no HTML changes needed)
  const stageEl = document.getElementById("stage");
  if (stageEl && !document.getElementById("scope")) {
    const scope = document.createElement("select");
    scope.id = "scope";
    scope.className = "border rounded-lg p-2 text-sm";
    scope.innerHTML = `
      <option value="mine">My Leads</option>
      <option value="house">House Queue (50 max)</option>
    `;
    stageEl.parentElement.insertBefore(scope, stageEl);
    scope.addEventListener("change", load);
  }

  document.getElementById("refresh").addEventListener("click", load);
  document.getElementById("q").addEventListener("input", () => { clearTimeout(window.__t); window.__t=setTimeout(load,250); });
  document.getElementById("stage").addEventListener("change", load);

  document.getElementById("leadForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const out = document.getElementById("leadOut");
    out.textContent = "Saving...";
    try {
      const data = Object.fromEntries(new FormData(e.target).entries());
      const r = await reqJSON("/sales/leads", { method:"POST", body: JSON.stringify(data) });
      out.textContent = r.duplicate_of ? "✅ Lead created (duplicate detected)." : "✅ Lead created.";
      e.target.reset();
      await load();
    } catch (err) {
      out.textContent = "❌ " + (err.message || "Error");
    }
  });

  load();
});
