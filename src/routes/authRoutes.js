'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { findByUsername } = require('../db');
const { sanitizeText, isValidUsername, isValidPassword } = require('../security');

function createLoginLimiter(config) {
  return rateLimit({
    windowMs: config.loginRateLimitWindowMs,
    limit: config.loginRateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Try again later.' },
  });
}

function authRoutes({ config }) {
  const router = express.Router();
  const loginLimiter = createLoginLimiter(config);

  router.post('/login', loginLimiter, (req, res) => {
    const username = sanitizeText(req.body?.username);
    const password = typeof req.body?.password === 'string' ? req.body.password : '';

    if (!isValidUsername(username) || !isValidPassword(password)) {
      return res.status(400).json({ error: 'Invalid username or password format' });
    }

    const user = findByUsername(req.app.locals.db, username);

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = req.app.locals.auth.signToken(user);
    return res.json({
      token,
      token_type: 'Bearer',
      expires_in: config.jwtExpiresIn,
      user: { id: user.id, username: user.username, role: user.role },
    });
  });

  return router;
}

module.exports = { authRoutes };