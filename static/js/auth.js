// /static/js/auth.js

(function () {
  const DEFAULT_LOGIN = "/static/login.html";

  function normRole(r) {
    return (r || "").toString().toLowerCase().replace(/-/g, "_");
  }

  async function jsonFetch(path, opts = {}) {
    const res = await fetch(path, {
      credentials: "include",
      headers: { "Accept": "application/json", ...(opts.headers || {}) },
      ...opts,
    });
    return res;
  }

  async function me() {
    const r = await jsonFetch("/me");
    if (!r.ok) return { ok: false };
    const j = await r.json();
    return j && j.ok ? j : { ok: false };
  }

  async function login(email, password) {
    const r = await jsonFetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!r.ok) {
      let msg = "Invalid credentials";
      try {
        const j = await r.json();
        msg = j?.detail || j?.message || msg;
      } catch {}
      throw new Error(msg);
    }

    const data = await r.json();
    const target = data?.redirect || "/static/employee.html";
    location.href = target;
    return data;
  }

  async function logout() {
    try {
      await jsonFetch("/logout", { method: "POST" });
    } catch {}
    location.href = DEFAULT_LOGIN;
  }

  // Client-side gate for pages
  async function requireRole(allowedRoles) {
    const who = await me();
    if (!who.ok) {
      location.href = DEFAULT_LOGIN;
      return null;
    }

    const role = normRole(who.role);
    const allowed = (allowedRoles || []).map(normRole);

    if (allowed.length && !allowed.includes(role)) {
      // logged in but wrong role → bounce to their real landing page
      const target = who.redirect || "/static/employee.html";
      location.href = target;
      return null;
    }

    return who;
  }

  // expose
  window.Auth = { me, login, logout, requireRole };

  // Back-compat: admin.js calls requireRole(...) directly
  window.requireRole = requireRole;
})();
