'use strict';

// =============================================================================
// АУТЕНТИФИКАЦИЯ (JWT)
// -----------------------------------------------------------------------------
// Что происходит в этом модуле:
//   1) signToken(user) — ПОДПИСЫВАЕТ JWT после успешного входа.
//   2) authenticateToken(req, res, next) — middleware, который ПРОВЕРЯЕТ
//      JWT на всех защищённых эндпоинтах (/api/*).
//
// Что такое JWT (JSON Web Token):
// это строка вида header.payload.signature (три части через точку). В payload
// лежат данные о пользователе, а подпись (сигнатура) сделана секретным ключом
// JWT_SECRET. Кто знает секрет — может проверить, что токен не подделан и
// не изменён, а также что он не истёк.
//
// Фабрика createAuth(config) нужна, чтобы в ТЕСТАХ можно было создать
// аутентификацию со своим секретом (не тем, что в production).
// =============================================================================

const jwt = require('jsonwebtoken'); // библиотека для работы с JWT

/** createAuth(config) — возвращает { signToken, authenticateToken }. */
function createAuth(config) {
  // issuer/audience — «контракт» токена: кто выпустил (наш API) и для кого
  // предназначен (наш клиент). При проверке они должны совпасть — это защита
  // от подстановки чужих токенов, выпущенных другими сервисами.
  const ISSUER = 'is1-api';
  const AUDIENCE = 'is1-client';

  /**
   * signToken(user) — выпуск JWT после успешной аутентификации.
   */
  function signToken(user) {
    return jwt.sign(
      // Полезная нагрузка (payload). sub — стандартное поле «субъект» (id юзера).
      { sub: String(user.id), username: user.username, role: user.role },
      config.jwtSecret,                    // секрет подписи (из env!)
      { expiresIn: config.jwtExpiresIn, issuer: ISSUER, audience: AUDIENCE }
      //   ^ expiresIn — время жизни: после истечения токен недействителен.
    );
  }

  /**
   * authenticateToken(req, res, next) — Express-middleware.
   * Express вызывает middleware последовательно перед обработчиком маршрута;
   * middleware либо отвечает сам (res.status(...)), либо передаёт управление
   * дальше через next().
   *
   * Ожидается заголовок:  Authorization: Bearer <token>
   */
  function authenticateToken(req, res, next) {
    // Берём заголовок Authorization (если его нет — пустая строка).
    const header = req.headers.authorization || '';
    // Разбиваем на две части: схему ('Bearer') и сам токен.
    const [scheme, token] = header.split(' ');

    // Если схема не Bearer или токена нет — отказ 401.
    // 401 (Unauthorized) = «вы не представили действующее удостоверение».
    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ error: 'Missing or malformed Authorization header' });
    }

    try {
      // Проверяем подпись, срок действия, issuer и audience.
      // Если токен подделан, истёк или от другого сервиса — jwt.verify
      // бросит исключение, и мы попадём в catch.
      const payload = jwt.verify(token, config.jwtSecret, {
        issuer: ISSUER,
        audience: AUDIENCE,
      });

      // Кладём данные пользователя в req.user — следующие обработчики
      // смогут их прочитать (например, узнать id автора поста).
      req.user = { id: Number(payload.sub), username: payload.username, role: payload.role };
      next(); // управление дальше — к обработчику защищённого маршрута
    } catch {
      // Любая ошибка верификации => единый ответ 401 (без деталей,
      // чтобы не подсказывать атакующему).
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  }

  // Возвращаем обе функции наружу.
  return { signToken, authenticateToken };
}

module.exports = { createAuth };

// =============================================================================
// ЗАЧЕМ ВСЁ ЭТО (OWASP A07 — Broken Authentication):
// - Статус-код 401 и никакой информации о причине -> не «подсказываем» атакующему.
// - expiresIn ограничивает время действия украденного токена.
// - issuer/audience не дают использовать чужие токены от других приложений.
// - Фабрика позволяет тестам подставлять свой секрет.
// =============================================================================