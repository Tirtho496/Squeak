const sessionUser = document.getElementById('session-user');
const logoutBtn = document.getElementById('logout-btn');
const flash = document.getElementById('flash');
const squeakForm = document.getElementById('squeak-form');
const squeakContent = document.getElementById('squeak-content');
const squeakCounter = document.getElementById('squeak-counter');
const recipientSelect = document.getElementById('recipient-select');
const publicList = document.getElementById('squeaks-public');
const privateList = document.getElementById('squeaks-private');
const refreshBtn = document.getElementById('refresh-btn');
let csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';

function updateCsrf(newToken) {
  if (!newToken) return;
  csrfToken = newToken;
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) meta.setAttribute('content', newToken);
}

function showFlash(message, variant = 'info') {
  if (!flash) return;
  flash.textContent = message;
  flash.dataset.variant = variant;
}

function renderList(target, items, emptyMessage) {
  if (!target) return;
  target.innerHTML = '';
  if (!items || items.length === 0) {
    const li = document.createElement('li');
    li.className = 'squeak';
    li.textContent = emptyMessage;
    target.appendChild(li);
    return;
  }
  items.forEach((item) => {
    const li = document.createElement('li');
    li.className = 'squeak';

    const meta = document.createElement('div');
    meta.className = 'squeak-meta';

    const strong = document.createElement('strong');
    strong.className = 'squeak-user';
    strong.textContent = item.name || item.username || '';

    const time = document.createElement('time');
    time.textContent = item.time || '';

    const span = document.createElement('span');
    span.className = 'recipient';
    span.textContent = `@${item.recipient || 'all'}`;

    meta.appendChild(strong);
    meta.appendChild(time);
    meta.appendChild(span);

    const body = document.createElement('p');
    body.className = 'squeak-body';
    body.textContent = item.squeak || item.content || '';

    li.appendChild(meta);
    li.appendChild(body);
    target.appendChild(li);
  });
}

async function fetchSession() {
  try {
    const session = await fetch('/session').then((res) => res.json());
    updateCsrf(session?.csrfToken);
    if (session && session.authenticated) {
      sessionUser.textContent = session.user.username;
    } else {
      window.location.replace('/');
    }
  } catch (err) {
    console.error(err);
    window.location.replace('/');
  }
}

async function loadUsers() {
  try {
    const result = await fetch('/users').then((res) => res.json());
    updateCsrf(result?.csrfToken);
    const users = result.users || window._squeakUsers || [];
    if (recipientSelect) {
      if (recipientSelect.dataset.loaded === '1') return;
      // keep the @ Everyone option, remove the rest
      Array.from(recipientSelect.options)
        .filter((opt) => opt.value !== 'all')
        .forEach((opt) => opt.remove());
      users.forEach((u) => {
        const value = (u.username || u || '').trim();
        if (!value) return;
        const opt = document.createElement('option');
        opt.value = value;
        opt.textContent = `@ ${value}`;
        recipientSelect.appendChild(opt);
      });
      recipientSelect.dataset.loaded = '1';
    }
  } catch (err) {
    console.warn('Could not load users', err);
  }
}

async function loadSqueaks(targetUser) {
  try {
    const params = targetUser ? `?user=${encodeURIComponent(targetUser)}` : '';
    const result = await fetch(`/squeaks${params}`).then((res) => res.json());
    updateCsrf(result?.csrfToken);
    renderList(publicList, result.squeaks, 'No squeaks yet. Be the first one!');
    renderList(privateList, result.squeals, 'No private squeals for you yet.');
  } catch (err) {
    console.error(err);
    showFlash('Unable to load squeaks.', 'error');
  }
}

async function handleLogout() {
  try {
    await fetch('/signout', {
      method: 'POST',
      headers: { 'x-csrf-token': csrfToken },
    });
    window.location.replace('/');
  } catch (err) {
    showFlash('Failed to sign out. Try again.', 'error');
  }
}

async function handleSqueakSubmit(event) {
  event.preventDefault();
  if (!squeakForm) return;
  const formData = new FormData(squeakForm);
  try {
    const response = await fetch('/squeak', {
      method: 'POST',
      headers: { 'x-csrf-token': csrfToken },
      body: new URLSearchParams(formData),
    });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.message || 'Unable to post squeak.');
    }
    if (squeakContent) {
      squeakContent.value = '';
    }
    updateCounter();
    await loadSqueaks();
  } catch (err) {
    showFlash(err.message, 'error');
  }
}

function updateCounter() {
  if (!squeakContent || !squeakCounter) return;
  squeakCounter.textContent = `${squeakContent.value.length} / ${squeakContent.maxLength}`;
}

function init() {
  fetchSession();
  loadUsers();
  if (window._initialSqueaks || window._initialSqueals) {
    renderList(publicList, window._initialSqueaks, 'No squeaks yet. Be the first one!');
    renderList(privateList, window._initialSqueals, 'No private squeals for you yet.');
  } else {
    loadSqueaks();
  }
  logoutBtn?.addEventListener('click', handleLogout);
  squeakForm?.addEventListener('submit', handleSqueakSubmit);
  squeakContent?.addEventListener('input', updateCounter);
  refreshBtn?.addEventListener('click', () => loadSqueaks());
  updateCounter();
}

document.addEventListener('DOMContentLoaded', init);
