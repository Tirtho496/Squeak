const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');
const mustacheExpress = require('mustache-express');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = process.env.PORT || 3444;
const DB_NAME = process.env.DB_NAME || 'squeak_patched';
const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017';

const COOKIE_NAME = 'squeak_session';
const CSRF_COOKIE = 'XSRF-TOKEN';
const SESSION_TTL_MS = 1000 * 60 * 60 * 12; // 12 hours
const USERNAME_RE = /^[A-Za-z0-9_.-]{3,20}$/;
const SESSION_ID_RE = /^[a-f0-9]{64}$/;
const APP_SECRET = process.env.APP_SECRET;
if (!APP_SECRET || Buffer.byteLength(APP_SECRET) < 32) {
  throw new Error('Set APP_SECRET to a randomly generated value of at least 32 bytes.');
}
const CERT_DIR = path.join(__dirname, 'cert');
const TEMPLATE_DIR = path.join(__dirname, 'templates');
const PUBLIC_DIR = path.join(__dirname, 'public');

const app = express();

app.engine('mustache', mustacheExpress());
app.set('view engine', 'mustache');
app.set('views', TEMPLATE_DIR);

app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.static(PUBLIC_DIR, { fallthrough: true }));

let client;
let credentials;
let sessions;
let squeaks;

async function initMongo() {
  client = new MongoClient(MONGO_URL, { serverSelectionTimeoutMS: 5000 });
  const cluster = await client.connect();
  const db = cluster.db(DB_NAME);
  credentials = db.collection('credentials');
  sessions = db.collection('sessions');
  squeaks = db.collection('squeaks');
  await sessions.createIndex({ id: 1 }, { unique: true });
  await credentials.createIndex({ username: 1 }, { unique: true });
  await squeaks.createIndex({ recipient: 1 });
  console.log('Patched app connected to MongoDB.');
}



function safeDecode(value) {
  try { return decodeURIComponent(value); } catch { return ''; }
}

function parseCookies(header = '') {
  return header.split(';').reduce((acc, part) => {
    if (!part) return acc;
    const [rawKey, rawValue] = part.split('=');
    if (!rawKey) return acc;
    acc[rawKey.trim()] = safeDecode((rawValue || '').trim());
    return acc;
  }, {});
}

function signValue(value) {
  const payload = JSON.stringify(value);
  const sig = crypto.createHmac('sha256', APP_SECRET).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

function verifySigned(value) {
  if (!value || typeof value !== 'string') return null;
  const lastDot = value.lastIndexOf('.');
  if (lastDot === -1) return null;
  const payload = value.slice(0, lastDot);
  const sig = value.slice(lastDot + 1);
  const expected = crypto.createHmac('sha256', APP_SECRET).update(payload).digest('hex');
  if (!/^[a-f0-9]{64}$/.test(sig)) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'))) return null;
  try {
    return JSON.parse(payload);
  } catch (err) {
    return null;
  }
}

function buildCookie(name, value, { maxAgeMs = SESSION_TTL_MS, httpOnly = true } = {}) {
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
    'Path=/',
    'SameSite=Strict',
    'Secure',
  ];
  if (httpOnly) attributes.push('HttpOnly');
  return attributes.join('; ');
}

function validateUsername(username) {
  if (!username || typeof username !== 'string') return 'Username is required.';
  if (!USERNAME_RE.test(username.trim())) return 'Username must be 3-20 chars (letters, numbers, ._-).';
  return null;
}

function validatePassword(password, username) {
  if (!password || typeof password !== 'string') return 'Password is required.';
  if (password.length < 8) return 'Password must be at least 8 characters.';
  if (username && password.toLowerCase().includes(username.toLowerCase())) {
    return 'Password cannot contain the username.';
  }
  return null;
}

function validateSessionId(id) {
  return SESSION_ID_RE.test(id || '');
}

function validateRecipient(recipient, users = []) {
  if (recipient === 'all') return null;
  if (typeof recipient !== 'string') return 'Invalid recipient.';
  const exists = users.some((u) => u.username === recipient);
  return exists ? null : 'Unknown recipient.';
}

function normalizeUsername(username) {
  return username.trim();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function passwordsMatch(password, stored) {
  if (!stored || !stored.salt || !stored.hash) return false;
  const attempt = crypto.scryptSync(password, stored.salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(stored.hash, 'hex'));
  } catch (err) {
    return false;
  }
}

function requireCsrf(req, res, next) {
  const token = req.body?.csrfToken || req.get('x-csrf-token');
  if (!req.csrfToken || !token || token !== req.csrfToken) {
    return res.status(403).json({ ok: false, message: 'Invalid CSRF token.' });
  }
  return next();
}

async function createSession(username) {
  const id = crypto.randomBytes(32).toString('hex'); // 64 hex chars
  const now = Date.now();
  const csrfToken = crypto.randomBytes(16).toString('hex');
  const doc = { id, username, createdAt: now, lastSeen: now, expiresAt: now + SESSION_TTL_MS, csrfToken };
  await sessions.insertOne(doc);
  const token = signValue({ id, username });
  return { token, doc };
}

async function loadSession(req) {
  req.session = null;
  req.user = null;
  const cookies = req.cookies || parseCookies(req.headers.cookie || '');
  const raw = cookies[COOKIE_NAME];
  const parsed = verifySigned(raw);
  if (!parsed || !validateSessionId(parsed.id) || typeof parsed.username !== 'string') {
    return;
  }

  const dbSession = await sessions.findOne({ id: parsed.id, username: parsed.username });
  if (!dbSession) return;

  const now = Date.now();
  if (now > dbSession.expiresAt) {
    await sessions.deleteOne({ id: dbSession.id });
    return;
  }

  if (now - dbSession.lastSeen > 1000 * 60 * 5) {
    await sessions.updateOne({ id: dbSession.id }, { $set: { lastSeen: now, expiresAt: now + SESSION_TTL_MS } });
  }

  req.session = dbSession;
  req.user = { username: parsed.username };
}

async function destroySession(sessionId) {
  if (!validateSessionId(sessionId)) return;
  await sessions.deleteOne({ id: sessionId });
}

function requireAuth(req, res, next) {
  if (!req.user || !req.session) {
    return res.status(401).json({ ok: false, message: 'Authentication required.' });
  }
  return next();
}

// parse cookies for all requests
app.use((req, res, next) => {
  req.cookies = parseCookies(req.headers.cookie || '');
  next();
});

// attach session
app.use(async (req, res, next) => {
  try {
    await loadSession(req);
  } catch (err) {
    console.error(err);
  }
  next();
});

// ensure CSRF token (guest or session)
app.use(async (req, res, next) => {
  try {
    let csrfToken = null;
    if (req.session && req.session.csrfToken) {
      csrfToken = req.session.csrfToken;
    } else {
      const raw = req.cookies[CSRF_COOKIE];
      const parsed = verifySigned(raw);
      if (parsed && typeof parsed.token === 'string') {
        csrfToken = parsed.token;
      }
    }

    if (!csrfToken) {
      csrfToken = crypto.randomBytes(16).toString('hex');
    }

    const signed = signValue({
      token: csrfToken,
      type: req.session ? 'session' : 'guest',
    });
    res.setHeader(
      'Set-Cookie',
      buildCookie(CSRF_COOKIE, signed, {
        httpOnly: false,
        maxAgeMs: req.session ? SESSION_TTL_MS : 1000 * 60 * 30,
      })
    );
    req.csrfToken = csrfToken;
    next();
  } catch (err) {
    console.error(err);
    next();
  }
});

app.get('/', async (req, res) => {
  if (!req.user) {
    return res.render('login', { csrf: req.csrfToken });
  }
  const users = await credentials.find({}, { projection: { username: 1, _id: 0 } }).toArray();
  const publicSqueaks = await squeaks.find({ recipient: 'all' }).toArray();
  const privateSqueals = await squeaks.find({ recipient: req.user.username }).toArray();
  res.render('app', {
    username: req.user.username,
    users,
    usersJson: JSON.stringify(users).replace(/</g, '\\u003c'),
    squeaks: publicSqueaks,
    squeals: privateSqueals,
    squeaksJson: JSON.stringify(publicSqueaks).replace(/</g, '\\u003c'),
    squealsJson: JSON.stringify(privateSqueals).replace(/</g, '\\u003c'),
    csrf: req.csrfToken,
  });
});

app.get('/session', (req, res) => {
  if (!req.user || !req.session) {
    return res.json({ authenticated: false, csrfToken: req.csrfToken });
  }
  res.json({ authenticated: true, user: { username: req.user.username }, csrfToken: req.csrfToken });
});

app.get('/users', async (req, res) => {
  const users = await credentials.find({}, { projection: { username: 1, _id: 0 } }).toArray();
  res.json({ ok: true, users, csrfToken: req.csrfToken });
});

app.post('/signup', requireCsrf, async (req, res) => {
  const { username, password } = req.body || {};
  const usernameError = validateUsername(username);
  const passwordError = validatePassword(password, username);
  if (usernameError || passwordError) {
    return res.status(400).json({ ok: false, message: usernameError || passwordError });
  }
  const cleanUsername = normalizeUsername(username);
  const existing = await credentials.findOne({ username: cleanUsername });
  if (existing) {
    return res.status(409).json({ ok: false, message: 'Username already exists.' });
  }

  const { salt, hash } = hashPassword(password);
  await credentials.insertOne({ username: cleanUsername, password: { salt, hash } });
  const { token, doc } = await createSession(cleanUsername);
  res.setHeader('Set-Cookie', [
    buildCookie(COOKIE_NAME, token, { httpOnly: true }),
    buildCookie(CSRF_COOKIE, signValue({ token: doc.csrfToken, type: 'session' }), { httpOnly: false }),
  ]);
  res.status(201).json({ ok: true, user: { username: cleanUsername }, csrfToken: doc.csrfToken });
});

app.post('/signin', requireCsrf, async (req, res) => {
  const { username, password } = req.body || {};
  const usernameError = validateUsername(username);
  if (usernameError) {
    return res.status(400).json({ ok: false, message: usernameError });
  }
  if (typeof password !== 'string' || !password) {
    return res.status(400).json({ ok: false, message: 'Password is required.' });
  }
  const cleanUsername = normalizeUsername(username);
  const user = await credentials.findOne({ username: cleanUsername });
  if (!user || !passwordsMatch(password, user.password)) {
    return res.status(401).json({ ok: false, message: 'Invalid credentials.' });
  }
  const { token, doc } = await createSession(cleanUsername);
  res.setHeader('Set-Cookie', [
    buildCookie(COOKIE_NAME, token, { httpOnly: true }),
    buildCookie(CSRF_COOKIE, signValue({ token: doc.csrfToken, type: 'session' }), { httpOnly: false }),
  ]);
  res.json({ ok: true, user: { username: cleanUsername }, csrfToken: doc.csrfToken });
});

app.post('/signout', requireAuth, requireCsrf, async (req, res) => {
  await destroySession(req.session.id);
  res.setHeader('Set-Cookie', [
    buildCookie(COOKIE_NAME, '', { maxAgeMs: 0, httpOnly: true }),
    buildCookie(CSRF_COOKIE, '', { maxAgeMs: 0, httpOnly: false }),
  ]);
  res.json({ ok: true });
});

app.get('/squeaks', requireAuth, async (req, res) => {
  const publicSqueaks = await squeaks.find({ recipient: 'all' }).toArray();
  const privateSqueals = await squeaks.find({ recipient: req.user.username }).toArray();
  res.json({ ok: true, squeaks: publicSqueaks, squeals: privateSqueals, csrfToken: req.csrfToken });
});

app.post('/squeak', requireAuth, requireCsrf, async (req, res) => {
  const { squeak: message, recipient = 'all' } = req.body || {};
  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ ok: false, message: 'Say something before squeaking.' });
  }

  const users = await credentials.find({}, { projection: { username: 1, _id: 0 } }).toArray();
  const recipientError = validateRecipient(recipient, users);
  if (recipientError) {
    return res.status(400).json({ ok: false, message: recipientError });
  }

  //Just trying the local language for fun
  const time = new Date().toLocaleDateString('sv-SE', { weekday: 'short', hour: 'numeric', minute: 'numeric' });
  await squeaks.insertOne({
    name: req.user.username,
    time,
    recipient: recipient === 'all' ? 'all' : recipient,
    squeak: message.trim().slice(0, 280),
  });
  res.json({ ok: true, csrfToken: req.csrfToken });
});

app.use((req, res) => {
  if (req.user) {
    return res.redirect('/');
  }
  return res.render('login', { csrf: req.csrfToken });
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ ok: false, message: 'Unexpected server error.' });
});

const CERT_PATH = path.join(CERT_DIR, 'server.crt');
const KEY_PATH = path.join(CERT_DIR, 'server.key');

function loadCredentials() {
  try {
    return { cert: fs.readFileSync(CERT_PATH), key: fs.readFileSync(KEY_PATH) };
  } catch {
    throw new Error('Missing TLS files. Generate cert/server.crt and cert/server.key; see README.md.');
  }
}

async function start() {
  const creds = loadCredentials();
  await initMongo();
  https.createServer(creds, app).listen(PORT, HOST, () => {
    console.log(`Patched Squeak! server listening on https://${HOST}:${PORT}`);
  });
}

start().catch(async () => {
  console.error('Startup failed. Check MongoDB, APP_SECRET, and TLS files; see README.md.');
  if (client) await client.close().catch(() => {});
  process.exitCode = 1;
});
