'use strict';

// =============================================================================
// ЗАЩИЩЁННЫЕ МАРШРУТЫ ДАННЫХ: GET /api/data и POST /api/posts
// -----------------------------------------------------------------------------
// ВАЖНО: все маршруты этого роутера доступны ТОЛЬКО аутентифицированным
// пользователям, потому что в app.js они смонтированы ПОСЛЕ middleware
// auth.authenticateToken: app.use('/api', auth.authenticateToken, dataRoutes).
// Если токена нет/он недействителен — Express вернёт 401 ещё до этого файла.
//
// Здесь же применяются две защиты OWASP:
//   - XSS: пользовательские поля ЭКРАНИРУЮТСЯ перед отправкой в ответе;
//   - SQLi: всё, что попадает в SQL, — только через параметризованные запросы.
// =============================================================================

const express = require('express');
const { listPosts, insertPost } = require('../db');     // запросы к БД
const { escapeHtml, sanitizeText, isValidTitle, isValidContent } = require('../security');

const router = express.Router();

/**
 * toSafePost(post) — «безопасное» представление поста для ответа API.
 * Каждое поле, которое вводил пользователь (title, content) или которое
 * может содержать опасные символы (author), пропускается через escapeHtml.
 *
 * ЗАЧЕМ, если мы отдаём JSON, а не HTML?
 * JSON-ответ сам по себе не выполняется браузером. Но API могут использовать
 * разные клиенты, и если какой-то из них отрендерит эти данные как HTML
 * (SPA, админка, шаблоны), внедрённый скрипт выполнится. Экранирование на
 * уровне API — это defense-in-depth (защита вглубь): данные уже приходят
 * в клиент «чистыми», независимо от того, как клиент их использует.
 */
function toSafePost(post) {
  return {
    id: post.id,
    title: escapeHtml(post.title),      // например <script> -> <script>
    content: escapeHtml(post.content),
    author: escapeHtml(post.author),
    created_at: post.created_at,        // генерируется БД — экранировать не нужно
  };
}

/**
 * GET /api/data — список постов (защищён).
 * Необязательный параметр ?search= фильтрует по заголовку/тексту.
 */
router.get('/data', (req, res) => {
  // Чистим поисковую строку (контрольные символы/пробелы)...
  const search = sanitizeText(req.query.search);
  // ...и передаём в параметризованный LIKE-запрос (см. db.js).
  // Даже если search = "' OR 1=1 --", SQL не сломается — это просто текст.
  const posts = listPosts(req.app.locals.db, search).map(toSafePost);
  res.json({ count: posts.length, posts });
});

/**
 * POST /api/posts — создание нового поста (защищён).
 * Пример атаки, которую этот эндпоинт отражает:
 *   { "title": "<script>alert('xss')</script>", "content": "..." }
 * Храним мы такой заголовок как есть (в БД нет причин «портить» данные),
 * но В ОТВЕТЕ он будет отдан в экранированном виде (см. toSafePost).
 */
router.post('/posts', (req, res) => {
  // 1. Санитизация ввода: управляющие символы и пробелы по краям.
  const title = sanitizeText(req.body?.title);
  const content = sanitizeText(req.body?.content);

  // 2. Валидация длины ДО записи в БД — защита от мусора и DoS.
  if (!isValidTitle(title)) {
    return res.status(400).json({ error: 'Title must be 1-120 characters long' });
  }
  if (!isValidContent(content)) {
    return res.status(400).json({ error: 'Content must be 1-5000 characters long' });
  }

  // 3. Сохранение через параметризованный INSERT (см. db.js — insertPost).
  // req.user появился благодаря middleware аутентификации (auth.js) —
  // это данные из проверенного JWT, значит id автора брать можно отсюда.
  const post = insertPost(req.app.locals.db, {
    userId: req.user.id,
    title,
    content,
  });

  // 4. Отдаём созданный пост (201 Created) в экранированном виде.
  res.status(201).json({ post: toSafePost(post) });
});

module.exports = router;

// =============================================================================
// ИТОГ:
// - весь роутер закрыт JWT-аутентификацией (иначе 401);
// - XSS нейтрализуется на выходе (escapeHtml), SQLi — параметризацией на входе;
// - длина полей ограничена (400) — защита от гигантских payload.
// =============================================================================