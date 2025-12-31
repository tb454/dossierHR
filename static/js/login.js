// Handles login form + smart redirect
(async function () {
  const form = document.querySelector('#loginForm'); // <-- FIX
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = form.querySelector('input[name="email"]').value.trim();
    const password = form.querySelector('input[name="password"]').value;

    const btn = form.querySelector('button');              // <-- FIX (don’t require [type="submit"])
    const err = form.querySelector('.login-error');

    if (err) { err.classList.add('hidden'); err.textContent = ''; }
    if (btn) btn.disabled = true;

    try {
      await Auth.login(email, password); // should redirect inside Auth.login
    } catch (ex) {
      if (err) {
        err.textContent = (ex && ex.message) || 'Login failed';
        err.classList.remove('hidden'); // <-- FIX (actually show it)
      }
      if (btn) btn.disabled = false;
    }
  });
})();
