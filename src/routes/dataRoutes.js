'use strict';

const express = require('express');
const { listPosts, insertPost } = require('../db');
const { escapeHtml, sanitizeText, isValidTitle, isValidContent } = require('../security');

const router = express.Router();

/**
 * Sanitizes a post for output: every user-controlled field is HTML-escaped
 * before it is returned by the API (defense against stored XSS, OWASP A03).
 * JSON responses already cannot be executed as HTML, but escaping is applied
 * as defense-in-depth in case a client renders this data as markup.
 */
function toSafePost(post) {
  return {
    id: post.id,
    title: escapeHtml(post.title),
    content: escapeHtml(post.content),
    author: escapeHtml(post.author),
    created_at: post.created_at,
  };
}

/**
 * GET /api/data — protected. Returns the list of posts.
 * Optional `?search=` filters by title/content via a *parameterized* LIKE
 * query (SQL injection safe).
 */
router.get('/data', (req, res) => {
  const search = sanitizeText(req.query.search);
  const posts = listPosts(req.app.locals.db, search).map(toSafePost);
  res.json({ count: posts.length, posts });
});

/**
 * POST /api/posts — protected. Creates a new post.
 * User-supplied title/content are normalized, length-validated, stored via a
 * parameterized INSERT, and returned HTML-escaped.
 */
router.post('/posts', (req, res) => {
  const title = sanitizeText(req.body?.title);
  const content = sanitizeText(req.body?.content);

  if (!isValidTitle(title)) {
    return res.status(400).json({ error: 'Title must be 1-120 characters long' });
  }
  if (!isValidContent(content)) {
    return res.status(400).json({ error: 'Content must be 1-5000 characters long' });
  }

  const post = insertPost(req.app.locals.db, {
    userId: req.user.id,
    title,
    content,
  });
  res.status(201).json({ post: toSafePost(post) });
});

module.exports = router;