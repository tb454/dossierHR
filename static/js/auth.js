// /static/js/auth.js

async function fetchJSON(url, opts = {}) {
  const res = await fetch(url, {
    credentials: 'include',
    headers: { 'Accept': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  // Try to parse JSON even on error to read {detail:...}
  let data = null;
  try { data = await res.json(); } catch (_) {}
  if (!res.ok) {
    const msg = (data && (data.detail || data.error)) || `HTTP ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data ?? {};
}

function onLoginPage() {
  return location.pathname.endsWith('/static/login.html') || location.pathname.endsWith('/login.html');
}

// Returns { ok, email, role } or { ok:false } when not logged in
async function getMe() {
  try {
    const me = await fetchJSON('/me');
    if (!me || me.ok !== true || !me.role) return { ok: false };
    return me;
  } catch (e) {
    if (e && (e.status === 401 || e.status === 403)) return { ok: false };
    console.error('getMe failed:', e);
    return { ok: false };
  }
}

// Ensure the current user has one of the allowed roles.
// If not logged in → go to login (but never bounce if you’re already on login).
// If role exists but isn’t allowed → send them to their correct dashboard.
async function requireRole(allowedRoles = []) {
  const who = await getMe();
  const role = who?.role;

  // Not logged in
  if (!who || who.ok !== true || !role) {
    if (!onLoginPage()) location.href = '/static/login.html';
    return null;
  }

  // Role not allowed -> bounce them to THEIR server-provided dashboard
  if (Array.isArray(allowedRoles) && allowedRoles.length > 0 && !allowedRoles.includes(role)) {
    const dest = who.redirect || '/dashboard/employee';
    location.href = dest;
    return null;
  }

  return who;
}

// Convenience: perform login and smart-redirect to the right dashboard
async function login(email, password) {
  const data = await fetchJSON('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  // Server decides destination. No gotoDashboard() needed.
  const dest = data.redirect || '/dashboard/employee';
  location.href = dest;
  return data;
}

// Convenience: logout and go back to login
async function logout() {
  try { await fetchJSON('/logout', { method: 'POST' }); } catch (_) {}
  location.href = '/static/login.html';
}

// Export to window for inline handlers if you want:
window.Auth = { getMe, requireRole, login, logout };
window.getMe = getMe;
window.requireRole = requireRole;
window.logout = logout;