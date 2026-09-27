'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createDb } = require('../src/db');
const { createApp } = require('../src/app');
const { getConfig } = require('../src/config');

// High login limit on the shared instance so other tests never trip it;
// the brute-force test below uses its own instance with a low limit.
const config = getConfig({
  JWT_SECRET: 'test-secret-at-least-16-chars-long',
  DB_PATH: ':memory:',
  LOGIN_RATE_LIMIT_MAX: '1000',
});

let db;
let server;
let baseUrl;

function postJson(url, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  return fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
}

async function login(username, password) {
  return postJson(`${baseUrl}/auth/login`, { username, password });
}

async function getToken() {
  const res = await login('admin', 'Admin123!');
  assert.equal(res.status, 200);
  const body = await res.json();
  return body.token;
}

before(async () => {
  db = createDb({ path: ':memory:' });
  const app = createApp({ db, config });
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server?.close();
  db?.close();
});

// ---------------------------------------------------------------------------
// Health / misc
// ---------------------------------------------------------------------------

test('GET /health returns ok', async () => {
  const res = await fetch(`${baseUrl}/health`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: 'ok' });
});

test('unknown route returns 404 JSON (no stack trace leak)', async () => {
  const res = await fetch(`${baseUrl}/nope`);
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: 'Not found' });
});

// ---------------------------------------------------------------------------
// POST /auth/login
// ---------------------------------------------------------------------------

test('login with valid credentials returns a JWT', async () => {
  const res = await login('admin', 'Admin123!');
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(body.token && body.token.split('.').length === 3, 'expected a JWT');
  assert.equal(body.user.username, 'admin');
  assert.equal(body.user.role, 'admin');
  // Never leak the password hash
  assert.equal('password_hash' in body.user, false);
});

test('login with wrong password returns generic 401', async () => {
  const res = await login('admin', 'WrongPass123!');
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'Invalid credentials' });
});

test('login with unknown user returns the same generic 401 (no enumeration)', async () => {
  const res = await login('ghost_user', 'SomePass123!');
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'Invalid credentials' });
});

test('login with malformed input returns 400', async () => {
  const res = await login('x', 'short');
  assert.equal(res.status, 400);
});

// ---------------------------------------------------------------------------
// Protected endpoints (JWT middleware)
// ---------------------------------------------------------------------------

test('GET /api/data without token returns 401', async () => {
  const res = await fetch(`${baseUrl}/api/data`);
  assert.equal(res.status, 401);
});

test('GET /api/data with invalid/expired token returns 401', async () => {
  const res = await fetch(`${baseUrl}/api/data`, {
    headers: { Authorization: 'Bearer not.a.jwt' },
  });
  assert.equal(res.status, 401);
});

test('GET /api/data with valid token returns the seeded posts', async () => {
  const token = await getToken();
  const res = await fetch(`${baseUrl}/api/data`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(body.count >= 1);
  assert.equal(body.posts[0].author, 'alice');
});

// ---------------------------------------------------------------------------
// SQL injection defense (OWASP A03)
// ---------------------------------------------------------------------------

test('search parameter is immune to SQL injection (parameterized LIKE)', async () => {
  const token = await getToken();
  const payload = `' OR 1=1 --`;
  const res = await fetch(`${baseUrl}/api/data?search=${encodeURIComponent(payload)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  // Must be a clean 200 with an empty result set — NOT all rows leaked
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.count, 0);
});

// ---------------------------------------------------------------------------
// XSS defense (OWASP A03)
// ---------------------------------------------------------------------------

test('user content is HTML-escaped before being returned (XSS defense)', async () => {
  const token = await getToken();
  const payload = '<script>alert("xss")</script>';
  const res = await postJson(
    `${baseUrl}/api/posts`,
    { title: payload, content: `Hello <img src=x onerror=alert(1)> world` },
    token
  );
  assert.equal(res.status, 201);
  const body = await res.json();

  // Raw tags must NOT appear in the response
  assert.ok(!body.post.title.includes('<script>'));
  assert.ok(!body.post.content.includes('<img'));
  // Escaped entities must be present (built via concatenation on purpose)
  const escapedScriptTag = '&' + 'lt;script' + '&' + 'gt;';
  assert.ok(body.post.title.includes(escapedScriptTag));
});

test('POST /api/posts requires a valid token', async () => {
  const res = await postJson(`${baseUrl}/api/posts`, { title: 'x', content: 'y' });
  assert.equal(res.status, 401);
});

test('POST /api/posts validates field lengths', async () => {
  const token = await getToken();
  const res = await postJson(`${baseUrl}/api/posts`, { title: '', content: 'ok' }, token);
  assert.equal(res.status, 400);
});

// ---------------------------------------------------------------------------
// Brute-force protection on login (separate app instance)
// ---------------------------------------------------------------------------

test('login endpoint rate-limits brute-force attempts', async () => {
  // Separate app instance with a low limit (max 3 attempts per window)
  const bruteConfig = getConfig({
    JWT_SECRET: 'test-secret-at-least-16-chars-long',
    DB_PATH: ':memory:',
    LOGIN_RATE_LIMIT_MAX: '3',
  });
  const db2 = createDb({ path: ':memory:' });
  const app2 = createApp({ db: db2, config: bruteConfig });
  const srv = app2.listen(0);
  await new Promise((resolve) => srv.once('listening', resolve));
  const url = `http://127.0.0.1:${srv.address().port}`;

  try {
    for (let i = 0; i < 4; i++) {
      const res = await postJson(`${url}/auth/login`, {
        username: 'admin',
        password: 'WrongPass123!',
      });
      if (i < 3) assert.equal(res.status, 401);
      else assert.equal(res.status, 429); // rate limited
    }
  } finally {
    srv.close();
    db2.close();
  }
});