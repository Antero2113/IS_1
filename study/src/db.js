'use strict';

// =============================================================================
// СЛОЙ РАБОТЫ С БАЗОЙ ДАННЫХ (SQLite)
// -----------------------------------------------------------------------------
// Задачи этого модуля:
//   1) создать файл базы данных со схемой таблиц (users, posts);
//   2) наполнить её демо-данными (seed), если она пустая;
//   3) предоставить функции запросов (поиск пользователя, список постов, ...).
//
// ГЛАВНОЕ ПРО БЕЗОПАСНОСТЬ:
// Каждый SQL-запрос здесь использует ПАРАМЕТРИЗОВАННЫЕ выражения
// (placeholder '?' в prepare, значения передаются отдельно в get/all/run).
// Это — основная защита от SQL-инъекций (OWASP A03): пользовательский ввод
// НИКОГДА не вклеивается в строку SQL, поэтому его нельзя «вырваться»
// из кавычек и выполнить свой код.
//
// Дополнительно: `node:sqlite` — ВСТРОЕННЫЙ модуль Node.js, поэтому для
// работы с SQLite не нужно компилировать нативные зависимости.
// =============================================================================

const { DatabaseSync } = require('node:sqlite'); // синхронный API SQLite от Node.js
const bcrypt = require('bcryptjs');              // хэширование паролей

// Количество раундов bcrypt. Чем больше — тем медленнее перебор пароля
// злоумышленником, но и тем дольше сам вход. 12 — разумный компромисс.
const BCRYPT_ROUNDS = 12;

/**
 * createDb({ path }) — создаёт/открывает базу данных и возвращает объект БД.
 * path ':memory:' означает «база только в оперативной памяти» (для тестов).
 */
function createDb({ path = './data/app.db' } = {}) {
  // Открываем соединение с файлом (или создаём новый файл).
  const db = new DatabaseSync(path);

  // PRAGMA journal_mode = WAL — режим журнала WAL: ускоряет чтение/запись
  // и защищает файл от повреждения при сбое. Для in-memory базы не нужен.
  if (path !== ':memory:') {
    db.exec('PRAGMA journal_mode = WAL;');
  }

  // PRAGMA foreign_keys = ON — включаем проверку ВНЕШНИХ КЛЮЧЕЙ
  // (в SQLite она выключена по умолчанию!). Благодаря этому ON DELETE CASCADE
  // будет реально удалять посты при удалении пользователя.
  db.exec('PRAGMA foreign_keys = ON;');

  // CREATE TABLE IF NOT EXISTS — создаёт таблицы, если их ещё нет.
  // Это «миграция» схемы в самом простом виде.
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT, -- автогенерация id
      username      TEXT    NOT NULL UNIQUE,           -- логин уникален
      password_hash TEXT    NOT NULL,                  -- ТОЛЬКО хэш, никогда пароль!
      role          TEXT    NOT NULL DEFAULT 'user',   -- роль (user/admin)
      created_at    TEXT    NOT NULL DEFAULT (datetime('now')) -- время создания
    );

    CREATE TABLE IF NOT EXISTS posts (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      --   ^ внешний ключ на users; CASCADE = удалить посты, если юзер удалён
      title      TEXT    NOT NULL,
      content    TEXT    NOT NULL,
      created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Заполняем демо-данными, если база пустая.
  seed(db);
  return db; // возвращаем «ручку» для работы с БД
}

/**
 * seed(db) — наполнение базы начальными данными (demo-пользователями и постом).
 * Выполняется только один раз: если в таблице users уже есть строки, выходим.
 */
function seed(db) {
  // Проверяем количество пользователей (параметризованный запрос с COUNT).
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM users').get();
  if (n > 0) return; // база уже заполнена — не трогаем

  // Подготавливаем INSERT с плейсхолдерами (?, ?, ?).
  const insertUser = db.prepare(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
  );
  const demoUsers = [
    { username: 'admin', password: 'Admin123!', role: 'admin' },
    { username: 'alice', password: 'Alice123!', role: 'user' },
  ];

  for (const u of demoUsers) {
    // СУТЬ: в БД сохраняем не пароль, а его bcrypt-хэш.
    // hashSync — синхронное хэширование (bcrypt добавляет случайную «соль»,
    // поэтому даже одинаковые пароли дают разные хэши).
    const hash = bcrypt.hashSync(u.password, BCRYPT_ROUNDS);
    insertUser.run(u.username, hash, u.role);
  }

  // Добавляем один демо-пост от alice.
  const alice = db.prepare('SELECT id FROM users WHERE username = ?').get('alice');
  const insertPost = db.prepare(
    'INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)'
  );
  insertPost.run(alice.id, 'Hello from Alice', 'This is a sample post stored in SQLite.');

  console.log('[db] Seeded demo users (admin / alice) and a sample post.');
}

/** findByUsername — поиск пользователя по логину (для входа). */
function findByUsername(db, username) {
  // SELECT * — вернёт ВСЕ колонки, включая password_hash.
  // Хэш никуда не «утекает» наружу: роуты не включают его в ответ.
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

/** findUserById — выборка публичных полей пользователя по id. */
function findUserById(db, id) {
  // Перечисляем нужные колонки ЯВНО — password_hash сюда не попадает.
  return db
    .prepare('SELECT id, username, role, created_at FROM users WHERE id = ?')
    .get(id);
}

/**
 * listPosts(db, search) — список постов с именем автора.
 * Если задан search — фильтр по заголовку/тексту через LIKE.
 *
 * ПОЧЕМУ ЭТО БЕЗОПАСНО ОТ SQLi:
 * пользовательская строка search попадает только в параметр (?) запроса
 * LIKE. Попытка передать, например, `' OR 1=1 --` не изменит структуру SQL —
 * это будет просто текст, который ничего не найдёт (проверяется тестом!).
 */
function listPosts(db, search) {
  if (search) {
    const like = `%${search}%`; // LIKE-шаблон: содержит искомый фрагмент
    return db
      .prepare(
        `SELECT p.id, p.title, p.content, p.created_at, u.username AS author
           FROM posts p JOIN users u ON u.id = p.user_id
          WHERE p.title LIKE ? OR p.content LIKE ?
          ORDER BY p.id DESC`
      )
      .all(like, like); // значения передаются ОТДЕЛЬНО от SQL-строки
  }
  // Без поиска — просто все посты, новые сверху.
  return db
    .prepare(
      `SELECT p.id, p.title, p.content, p.created_at, u.username AS author
         FROM posts p JOIN users u ON u.id = p.user_id
        ORDER BY p.id DESC`
    )
    .all();
}

/** insertPost — вставка нового поста (тоже через параметризованный INSERT). */
function insertPost(db, { userId, title, content }) {
  // run() выполняет INSERT и возвращает результат, где lastInsertRowid — id новой строки.
  const res = db
    .prepare('INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)')
    .run(userId, title, content);

  // Сразу возвращаем созданный пост вместе с автором (для ответа API).
  return db
    .prepare(
      `SELECT p.id, p.title, p.content, p.created_at, u.username AS author
         FROM posts p JOIN users u ON u.id = p.user_id
        WHERE p.id = ?`
    )
    .get(res.lastInsertRowid);
}

// Экспортируем функции для использования в роутах.
module.exports = { createDb, findByUsername, findUserById, listPosts, insertPost };

// =============================================================================
// ИТОГ ПО БЕЗОПАСНОСТИ СЛОЯ БД:
// - Только параметризованные запросы -> нет SQL-инъекций.
// - Пароли хранятся как bcrypt-хэши (с солью, cost 12) -> нет утечки паролей.
// - password_hash не попадает в выборки, которые идут в ответы API.
// =============================================================================