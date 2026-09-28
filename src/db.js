'use strict';

const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');

const BCRYPT_ROUNDS = 12;

function createDb({ path = './data/app.db' } = {}) {
  const db = new DatabaseSync(path);

  if (path !== ':memory:') {
    db.exec('PRAGMA journal_mode = WAL;');
  }
  db.exec('PRAGMA foreign_keys = ON;');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL UNIQUE,
      password_hash TEXT    NOT NULL,
      role          TEXT    NOT NULL DEFAULT 'user',
      created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS posts (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title      TEXT    NOT NULL,
      content    TEXT    NOT NULL,
      created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
  `);

  seed(db);
  return db;
}

function seed(db) {
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM users').get();
  if (n > 0) return;

  const insertUser = db.prepare(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
  );
  const demoUsers = [
    { username: 'admin', password: 'Admin123!', role: 'admin' },
    { username: 'alice', password: 'Alice123!', role: 'user' },
  ];

  for (const u of demoUsers) {
    const hash = bcrypt.hashSync(u.password, BCRYPT_ROUNDS);
    insertUser.run(u.username, hash, u.role);
  }

  const alice = db.prepare('SELECT id FROM users WHERE username = ?').get('alice');
  const insertPost = db.prepare(
    'INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)'
  );
  insertPost.run(alice.id, 'Hello from Alice', 'This is a sample post stored in SQLite.');

  console.log('[db] Seeded demo users (admin / alice) and a sample post.');
}

function findByUsername(db, username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function findUserById(db, id) {
  return db
    .prepare('SELECT id, username, role, created_at FROM users WHERE id = ?')
    .get(id);
}

function listPosts(db, search) {
  if (search) {
    const like = `%${search}%`;
    return db
      .prepare(
        `SELECT p.id, p.title, p.content, p.created_at, u.username AS author
           FROM posts p JOIN users u ON u.id = p.user_id
          WHERE p.title LIKE ? OR p.content LIKE ?
          ORDER BY p.id DESC`
      )
      .all(like, like);
  }
  return db
    .prepare(
      `SELECT p.id, p.title, p.content, p.created_at, u.username AS author
         FROM posts p JOIN users u ON u.id = p.user_id
        ORDER BY p.id DESC`
    )
    .all();
}

function insertPost(db, { userId, title, content }) {
  const res = db
    .prepare('INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)')
    .run(userId, title, content);
  return db
    .prepare(
      `SELECT p.id, p.title, p.content, p.created_at, u.username AS author
         FROM posts p JOIN users u ON u.id = p.user_id
        WHERE p.id = ?`
    )
    .get(res.lastInsertRowid);
}

module.exports = { createDb, findByUsername, findUserById, listPosts, insertPost };