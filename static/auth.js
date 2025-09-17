async function getMe() {
  const res = await fetch("/me", { credentials: "include" });
  const data = await res.json().catch(() => ({}));
  return data || {};
}

async function requireRole(allowedRoles) {
  const me = await getMe();
  if (!me || !me.ok || !me.role) {
    location.href = "/static/login.html";
    return;
  }
  if (!allowedRoles.includes(me.role)) {
    // Redirect to correct dashboard if role mismatch
    if (me.role === "admin") location.href = "/static/admin.html";
    else if (me.role === "manager") location.href = "/static/manager.html";
    else location.href = "/static/employee.html";
    return;
  }
  return me;
}
