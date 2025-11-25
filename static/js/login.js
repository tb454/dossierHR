// Handles login form + smart redirect
(async function () {
  const form = document.querySelector('#login-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = form.querySelector('input[name="email"]').value.trim();
    const password = form.querySelector('input[name="password"]').value;
    const btn = form.querySelector('button[type="submit"]');
    const err = form.querySelector('.login-error');

    btn.disabled = true; err.textContent = '';
    try {
      await Auth.login(email, password); // redirects inside
    } catch (ex) {
      err.textContent = (ex && ex.message) || 'Login failed';
      btn.disabled = false;
    }
  });
})();
