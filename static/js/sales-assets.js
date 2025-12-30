import { reqJSON, esc } from "./sales-common.js";

document.addEventListener("DOMContentLoaded", async () => {
  const el = document.getElementById("list");
  try {
    const out = await reqJSON("/sales/assets");
    const a = out.assets || [];
    if (!a.length) { el.textContent = "No assets yet."; return; }
    el.innerHTML = a.map(x => `
      <div class="border-t py-3">
        <div class="font-medium">${esc(x.name)} <span class="text-xs text-zinc-500">(${esc(x.asset_type)})</span></div>
        <div class="text-xs text-zinc-500">${esc(x.notes||"")}</div>
        <a class="underline text-sm" href="${esc(x.url)}" target="_blank" rel="noreferrer">Open</a>
      </div>
    `).join("");
  } catch (err) {
    el.textContent = "Not authorized.";
  }
});
