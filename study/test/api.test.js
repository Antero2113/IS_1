'use strict';

// =============================================================================
// ИНТЕГРАЦИОННЫЕ SECURITY-ТЕСТЫ API
// -----------------------------------------------------------------------------
// Что это: настоящие HTTP-запросы к работающему серверу (поднимается в памяти),
// которые проверяют, что защиты реально работают:
//   1. JWT-поток (вход -> токен -> доступ к защищённым данным);
//   2. отказ без токена / с битым токеном (401);
//   3. SQL-инъекция не работает (параметризованные запросы);
//   4. XSS-нагрузка экранируется в ответе;
//   5. брутфорс логина ограничен rate-limiter'ом (429).
// Эти же тесты запускает CI (см. .github/workflows/ci.yml).
//
// Используется ВСТРОЕННЫЙ тест-раннер Node.js (node --test) — никаких
// дополнительных зависимостей не нужно. fetch тоже встроен в Node.
// =============================================================================

// Импортируем функции тест-раннера: test — тест, before/after — хуки жизненного цикла.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict'); // строгие проверки равенства

// Импортируем модули приложения (те же, что использует server.js).
const { createDb } = require('../src/db');
const { createApp } = require('../src/app');
const { getConfig } = require('../src/config');

// Конфигурация для тестов: свой JWT-секрет, база в памяти (':memory:'), а
// лимит попыток входа поднят до 1000, чтобы другие тесты его случайно не
// «проели» (для брутфорс-теста ниже создаётся отдельный экземпляр с лимитом 3).
const config = getConfig({
  JWT_SECRET: 'test-secret-at-least-16-chars-long',
  DB_PATH: ':memory:',
  LOGIN_RATE_LIMIT_MAX: '1000',
});

// Общие переменные, доступные всем тестам:
let db;       // база данных
let server;   // HTTP-сервер
let baseUrl;  // адрес сервера (http://127.0.0.1:<случайный порт>)

// --- Вспомогательные функции -------------------------------------------------

/** postJson — отправка POST-запроса с JSON-телом (и опциональным JWT). */
function postJson(url, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`; // добавляем токен, если есть
  return fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
}

/** login — короткая обёртка над POST /auth/login. */
async function login(username, password) {
  return postJson(`${baseUrl}/auth/login`, { username, password });
}

/** getToken — входит как admin и возвращает JWT (используется в тестах данных). */
async function getToken() {
  const res = await login('admin', 'Admin123!');
  assert.equal(res.status, 200);
  const body = await res.json();
  return body.token;
}

// --- Хуки жизненного цикла ---------------------------------------------------

// before — выполняется ОДИН раз перед всеми тестами:
// создаём БД в памяти, собираем приложение, запускаем сервер на порту 0
// (порт 0 означает «пусть ОС выберет свободный порт»).
before(async () => {
  db = createDb({ path: ':memory:' });
  const app = createApp({ db, config });
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve)); // ждём запуска
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

// after — выполняется после всех тестов: закрываем сервер и базу.
after(() => {
  server?.close(); // `?.` — безопасный вызов, если server вдруг undefined
  db?.close();
});

// =============================================================================
// ГРУППА 1. Health / базовое поведение
// =============================================================================

test('GET /health returns ok', async () => {
  // healthcheck должен отвечать 200 и {"status":"ok"}.
  const res = await fetch(`${baseUrl}/health`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { status: 'ok' });
});

test('unknown route returns 404 JSON (no stack trace leak)', async () => {
  // Несуществующий маршрут должен вернуть JSON «Not found» (см. app.js),
  // а НЕ HTML-страницу Express со стектрейсом.
  const res = await fetch(`${baseUrl}/nope`);
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: 'Not found' });
});

// =============================================================================
// ГРУППА 2. POST /auth/login — аутентификация
// =============================================================================

test('login with valid credentials returns a JWT', async () => {
  const res = await login('admin', 'Admin123!');
  assert.equal(res.status, 200);
  const body = await res.json();

  // JWT состоит из трёх частей, разделённых точками: header.payload.signature.
  assert.ok(body.token && body.token.split('.').length === 3, 'expected a JWT');
  assert.equal(body.user.username, 'admin');
  assert.equal(body.user.role, 'admin');
  // ВАЖНАЯ проверка: хэш пароля не должен «утечь» в ответ API.
  assert.equal('password_hash' in body.user, false);
});

test('login with wrong password returns generic 401', async () => {
  const res = await login('admin', 'WrongPass123!');
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'Invalid credentials' });
});

test('login with unknown user returns the same generic 401 (no enumeration)', async () => {
  // Неизвестный пользователь получает ТОТ ЖЕ ответ, что и при неверном пароле —
  // это защита от перечисления пользователей (user enumeration).
  const res = await login('ghost_user', 'SomePass123!');
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'Invalid credentials' });
});

test('login with malformed input returns 400', async () => {
  // Короткий логин 'x' и короткий пароль не проходят валидацию формата.
  const res = await login('x', 'short');
  assert.equal(res.status, 400);
});

// =============================================================================
// ГРУППА 3. Защищённые эндпоинты (JWT middleware)
// =============================================================================

test('GET /api/data without token returns 401', async () => {
  // Без заголовка Authorization middleware должен отказать.
  const res = await fetch(`${baseUrl}/api/data`);
  assert.equal(res.status, 401);
});

test('GET /api/data with invalid/expired token returns 401', async () => {
  // Подделанный токен ('not.a.jwt') не пройдёт проверку подписи.
  const res = await fetch(`${baseUrl}/api/data`, {
    headers: { Authorization: 'Bearer not.a.jwt' },
  });
  assert.equal(res.status, 401);
});

test('GET /api/data with valid token returns the seeded posts', async () => {
  // С настоящим токеном получаем данные: минимум один пост, автор — alice.
  const token = await getToken();
  const res = await fetch(`${baseUrl}/api/data`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(body.count >= 1);
  assert.equal(body.posts[0].author, 'alice');
});

// =============================================================================
// ГРУППА 4. Защита от SQL-инъекций (OWASP A03)
// =============================================================================

test('search parameter is immune to SQL injection (parameterized LIKE)', async () => {
  const token = await getToken();
  // Классическая инъекция: если бы search подставлялся в SQL конкатенацией,
  // `' OR 1=1 --` замкнул бы кавычку и сделал условие истинным — вернулись бы
  // ВСЕ записи, хотя поиск должен был ничего не найти.
  const payload = `' OR 1=1 --`;
  const res = await fetch(`${baseUrl}/api/data?search=${encodeURIComponent(payload)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  // Ожидание: чистый 200 с ПУСТЫМ результатом — ни одна строка не «утекла».
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.count, 0);
});

// =============================================================================
// ГРУППА 5. Защита от XSS (OWASP A03)
// =============================================================================

test('user content is HTML-escaped before being returned (XSS defense)', async () => {
  const token = await getToken();
  // Полезная нагрузка XSS: скрипт и «битая» картинка с обработчиком ошибки.
  const payload = '<script>alert("xss")</script>';
  const res = await postJson(
    `${baseUrl}/api/posts`,
    { title: payload, content: `Hello <img src=x onerror=alert(1)> world` },
    token
  );
  assert.equal(res.status, 201);
  const body = await res.json();

  // 1) Сырые теги НЕ должны появиться в ответе...
  assert.ok(!body.post.title.includes('<script>'));
  assert.ok(!body.post.content.includes('<img'));
  // 2) ...а вместо них — экранированные сущности.
  // Строка собрана конкатенацией специально, чтобы её не «съел» редактор
  // как настоящую HTML-сущность: ожидаем <script> внутри ответа.
  const escapedScriptTag = '&' + 'lt;script' + '&' + 'gt;';
  assert.ok(body.post.title.includes(escapedScriptTag));
});

test('POST /api/posts requires a valid token', async () => {
  // Создание поста без токена — 401.
  const res = await postJson(`${baseUrl}/api/posts`, { title: 'x', content: 'y' });
  assert.equal(res.status, 401);
});

test('POST /api/posts validates field lengths', async () => {
  // Пустой заголовок не проходит валидацию — 400 Bad Request.
  const token = await getToken();
  const res = await postJson(`${baseUrl}/api/posts`, { title: '', content: 'ok' }, token);
  assert.equal(res.status, 400);
});

// =============================================================================
// ГРУППА 6. Защита от брутфорса (rate limiting)
// =============================================================================

test('login endpoint rate-limits brute-force attempts', async () => {
  // Создаём ОТДЕЛЬНЫЙ экземпляр приложения с маленьким лимитом (макс. 3
  // попытки за окно), чтобы не «сжечь» лимит основного приложения,
  // которым пользуются остальные тесты.
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
    // Делаем 4 попытки входа с неверным паролем.
    for (let i = 0; i < 4; i++) {
      const res = await postJson(`${url}/auth/login`, {
        username: 'admin',
        password: 'WrongPass123!',
      });
      // Первые 3: 401 (неверный пароль)...
      if (i < 3) assert.equal(res.status, 401);
      // ...а 4-я попытка уже превысила лимит -> 429 Too Many Requests.
      else assert.equal(res.status, 429); // rate limited
    }
  } finally {
    // finally — гарантированно закрываем ресурсы, даже если тест упал.
    srv.close();
    db2.close();
  }
});

// =============================================================================
// ИТОГ: каждый тест — это «живое доказательство» конкретной защиты.
// Если в будущем кто-то уберёт middleware или заменит параметризованный
// запрос на конкатенацию строк — тесты сразу упадут, и CI не пропустит
// такие изменения.
// =============================================================================