'use strict';

const express = require('express');
const { listPosts, insertPost } = require('../db');
const { escapeHtml, sanitizeText, isValidTitle, isValidContent } = require('../security');

const router = express.Router();

function toSafePost(post) {
  return {
    id: post.id,
    title: escapeHtml(post.title),
    content: escapeHtml(post.content),
    author: escapeHtml(post.author),
    created_at: post.created_at,
  };
}

router.get('/data', (req, res) => {
  const search = sanitizeText(req.query.search);
  const posts = listPosts(req.app.locals.db, search).map(toSafePost);
  res.json({ count: posts.length, posts });
});

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