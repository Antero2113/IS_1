'use strict';

// =============================================================================
// МАРШРУТ АУТЕНТИФИКАЦИИ: POST /auth/login
// -----------------------------------------------------------------------------
// Задача эндпоинта:
//   принять { username, password } -> проверить -> выдать JWT.
// Это ЕДИНСТВЕННЫЙ публичный эндпоинт, связанный с пользователями,
// поэтому здесь сосредоточено несколько защит от атак на аутентификацию.
// =============================================================================

const express = require('express');
const bcrypt = require('bcryptjs');                       // сравнение хэшей паролей
const rateLimit = require('express-rate-limit');          // ограничение частоты запросов
const { findByUsername } = require('../db');              // поиск юзера в БД
const { sanitizeText, isValidUsername, isValidPassword } = require('../security');

/**
 * createLoginLimiter(config) — защита от БРУТФОРСА (перебора паролей).
 * Суть: с одного IP разрешено максимум N попыток входа за окно времени.
 * Превысил лимит -> HTTP 429 Too Many Requests.
 */
function createLoginLimiter(config) {
  return rateLimit({
    windowMs: config.loginRateLimitWindowMs, // окно: по умолчанию 15 минут
    limit: config.loginRateLimitMax,         // максимум попыток: по умолчанию 5
    standardHeaders: true,                   // сообщать о лимите через стандартные заголовки
    legacyHeaders: false,                    // не использовать устаревшие заголовки
    message: { error: 'Too many login attempts. Try again later.' }, // тело ответа 429
  });
}

/**
 * authRoutes({ config }) — фабрика роутера.
 * Почему фабрика: роутер и его rate-limit создаются ДЛЯ КАЖДОГО экземпляра
 * приложения заново. Если бы router был один на всех, то счётчики попыток
 * и обработчики «протекали» бы между приложениями (например, в тестах).
 */
function authRoutes({ config }) {
  const router = express.Router();                 // создаём роутер
  const loginLimiter = createLoginLimiter(config); // limiter для этого приложения

  // Регистрируем POST /auth/login. ПОРЯДОК middleware:
  // loginLimiter выполняется ПЕРВЫМ (считает все попытки, даже неудачные).
  router.post('/login', loginLimiter, (req, res) => {
    // --- Шаг 1. Чистим и валидируем ввод -------------------------------------
    // sanitizeText — убирает управляющие символы и пробелы.
    const username = sanitizeText(req.body?.username);
    // req.body заполняется express.json() (см. app.js). `?.` — безопасный доступ:
    // если body или username отсутствуют, получим undefined, а не ошибку.
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    // Валидация ФОРМАТА до обращения к БД: невалидные данные => 400 Bad Request.
    if (!isValidUsername(username) || !isValidPassword(password)) {
      return res.status(400).json({ error: 'Invalid username or password format' });
    }

    // --- Шаг 2. Ищем пользователя --------------------------------------------
    // Параметризованный запрос (защита от SQLi) — см. db.js.
    const user = findByUsername(req.app.locals.db, username);

    // --- Шаг 3. Проверяем пароль ---------------------------------------------
    // if (!user || !bcrypt.compareSync(...)) — ОБЪЕДИНЁННОЕ условие.
    // ПОЧЕМУ ТАК: при неизвестном пользователе и при неверном пароле мы
    // возвращаем ОДИНАКОВЫЙ ответ «Invalid credentials». Если бы ответы
    // отличались («такого юзера нет» vs «неверный пароль»), злоумышленник
    // мог бы перебором логинов собрать список существующих пользователей —
    // это называется User Enumeration (OWASP A07).
    // compareSync сравнивает введённый пароль с bcrypt-хэшем из БД.
    // Сравнение происходит внутри bcrypt (устойчиво к timing-атакам),
    // сам пароль в открытом виде нигде не хранится и не логируется.
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // --- Шаг 4. Выпускаем JWT и отвечаем -------------------------------------
    // signToken берёт данные юзера и подписывает токен секретом (см. auth.js).
    const token = req.app.locals.auth.signToken(user);

    // Отдаём токен клиенту. Клиент должен слать его в заголовке
    // Authorization: Bearer <token> на защищённые эндпоинты.
    return res.json({
      token,
      token_type: 'Bearer',                    // стандартная схема авторизации
      expires_in: config.jwtExpiresIn,         // срок жизни токена
      user: { id: user.id, username: user.username, role: user.role },
      // ^ в ответе НЕТ password_hash — хэш никогда не покидает сервер!
    });
  });

  return router; // роутер подключается в app.js под /auth
}

module.exports = { authRoutes };

// =============================================================================
// ИТОГ ЗАЩИТ НА ВХОДЕ:
// - rate-limit против брутфорса (429 после N попыток);
// - валидация формата до запроса к БД (400);
// - единый ответ 401 — нет перечисления пользователей;
// - пароль сверяется только через bcrypt, в открытом виде не появляется;
// - в ответе клиенту не отдаётся password_hash.
// =============================================================================