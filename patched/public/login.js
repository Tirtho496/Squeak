const registerForm = document.getElementById('register-form');
const loginForm = document.getElementById('login-form');
const flash = document.getElementById('flash');
let csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

function showFlash(message, variant = 'info') {
  if (!flash) return;
  flash.textContent = message;
  flash.dataset.variant = variant;
}

function formDataToObject(form) {
  return Object.fromEntries(new FormData(form));
}

function updateCsrf(token) {
  if (!token) return;
  csrfToken = token;
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) meta.setAttribute('content', token);
}

async function sendJson(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-csrf-token': csrfToken,
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (data.csrfToken) {
    updateCsrf(data.csrfToken);
  }
  if (!response.ok) {
    throw new Error(data.message || 'Something went wrong.');
  }
  return data;
}

async function handleRegister(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = formDataToObject(form);
  try {
    await sendJson('/signup', payload);
    if (typeof form.reset === 'function') {
      form.reset();
    }
    alert('Sign up successful! You are now signed in.');
    window.location.href = '/';
  } catch (err) {
    showFlash(err.message, 'error');
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const payload = formDataToObject(form);
  try {
    await sendJson('/signin', payload);
    if (typeof form.reset === 'function') {
      form.reset();
    }
    alert('Sign in successful!');
    window.location.href = '/';
  } catch (err) {
    showFlash(err.message, 'error');
  }
}

async function checkSession() {
  try {
    const result = await fetch('/session').then((res) => res.json());
    if (result && result.authenticated) {
      window.location.replace('/');
    }
  } catch (err) {
    console.error(err);
  }
}

registerForm?.addEventListener('submit', handleRegister);
loginForm?.addEventListener('submit', handleLogin);

checkSession();
