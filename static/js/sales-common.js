export async function reqJSON(url, opts = {}) {
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

export function esc(s) {
  return String(s || "").replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

export function money(cents) {
  const v = Number(cents || 0) / 100;
  return v.toLocaleString(undefined, { style: "currency", currency: "USD" });
}

export function qs(name) {
  return new URLSearchParams(window.location.search).get(name);
}
