import { reqJSON, esc } from "./sales-common.js";

document.addEventListener("DOMContentLoaded", () => {
  const f = document.getElementById("f");
  const out = document.getElementById("out");

  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    out.textContent = "Submitting...";
    try {
      const data = Object.fromEntries(new FormData(f).entries());
      const r = await reqJSON("/sales/apply", { method: "POST", body: JSON.stringify(data) });
      if (r.already_exists) {
        out.innerHTML = `✅ Already applied. Status: <b>${esc(r.status)}</b> • Code: <b>${esc(r.referral_code)}</b>`;
      } else {
        out.innerHTML = `✅ Submitted. Status: <b>${esc(r.rep.status)}</b> • Code: <b>${esc(r.rep.referral_code)}</b>`;
      }
    } catch (err) {
      out.textContent = "❌ " + (err.message || "Error");
    }
  });
});
