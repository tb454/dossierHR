import { reqJSON, esc, money } from "./sales-common.js";

document.addEventListener("DOMContentLoaded", async () => {
  const meta = document.getElementById("meta");
  try {
    const dash = await reqJSON("/sales/dashboard");
    meta.textContent = "Logged in (sales session).";

    document.getElementById("leadsDue").textContent = dash.leads_due;
    document.getElementById("tasksDue").textContent = dash.tasks_due;
    document.getElementById("onboardingRed").textContent = dash.onboarding_red;
    document.getElementById("pendingComm").textContent = money(dash.pending_commission_cents);

    const pipe = dash.pipeline || [];
    document.getElementById("pipeline").innerHTML = pipe.length ? `
      <table class="w-full text-sm">
        <thead><tr class="text-left text-zinc-500"><th class="py-2">Stage</th><th>Count</th></tr></thead>
        <tbody>${pipe.map(r => `<tr class="border-t"><td class="py-2">${esc(r.stage)}</td><td>${r.cnt}</td></tr>`).join("")}</tbody>
      </table>` : "No deals yet.";

    const tasks = await reqJSON("/sales/tasks/due?days_ahead=0");
    const rows = tasks.tasks || [];
    document.getElementById("tasks").innerHTML = rows.length ? rows.map(t =>
      `<div class="border-t py-2"><div class="font-medium">${esc(t.title)}</div><div class="text-xs text-zinc-500">${new Date(t.due_at).toLocaleString()}</div></div>`
    ).join("") : "No tasks due today.";
  } catch (err) {
    meta.textContent = "Not authorized. Login first.";
  }
});
