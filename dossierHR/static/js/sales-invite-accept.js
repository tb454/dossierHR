import { reqJSON, qs } from "./sales-common.js";

document.addEventListener("DOMContentLoaded", () => {
  const f = document.getElementById("f");
  const out = document.getElementById("out");
  const tokenQ = qs("token");
  if (tokenQ) document.getElementById("token").value = tokenQ;

  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    out.textContent = "Submitting...";
    try {
      const payload = {
        token: document.getElementById("token").value.trim(),
        legal_name: document.getElementById("legal_name").value.trim(),
        phone: document.getElementById("phone").value.trim() || null,
        territory: document.getElementById("territory").value.trim() || null,
        vertical: document.getElementById("vertical").value || null,
        password: document.getElementById("password").value,
      };
      await reqJSON("/sales/invite/accept", { method: "POST", body: JSON.stringify(payload) });
      out.innerHTML = `✅ Invite accepted. Go login at <a class="underline" href="/static/login.html">login</a> then open <a class="underline" href="/dashboard/sales">Sales Portal</a>.`;
    } catch (err) {
      out.textContent = "❌ " + (err.message || "Error");
    }
  });
});
