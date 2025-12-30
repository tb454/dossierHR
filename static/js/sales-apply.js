async function postJSON(url, data) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
    credentials: "include",
  });
  const txt = await res.text();
  let json;
  try { json = JSON.parse(txt); } catch { json = { raw: txt }; }
  if (!res.ok) throw new Error(json.detail || txt || "Request failed");
  return json;
}

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("applyForm");
  const result = document.getElementById("result");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    result.textContent = "Submitting...";
    result.className = "mt-4 text-sm text-zinc-600";

    const data = Object.fromEntries(new FormData(form).entries());

    try {
      const out = await postJSON("/sales/apply", data);
      const rep = out.rep || {};
      result.className = "mt-4 text-sm text-green-700";
      result.innerHTML =
        `✅ Submitted. Status: <b>${rep.status || out.status || "candidate"}</b><br/>` +
        `Your referral code: <b>${rep.referral_code || out.referral_code || ""}</b><br/>` +
        `If you already applied, this will show your existing code.`;
    } catch (err) {
      result.className = "mt-4 text-sm text-red-700";
      result.textContent = "❌ " + (err.message || "Error");
    }
  });
});
