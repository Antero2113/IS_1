'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { findByUsername } = require('../db');
const { sanitizeText, isValidUsername, isValidPassword } = require('../security');

/**
 * Brute-force protection: max N login attempts per IP per window
 * (default 5 per 15 minutes, configurable via env).
 */
function createLoginLimiter(config) {
  return rateLimit({
    windowMs: config.loginRateLimitWindowMs,
    limit: config.loginRateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Try again later.' },
  });
}

/**
 * POST /auth/login — authenticates a user and issues a JWT.
 *
 * Security notes:
 *  - passwords are compared with bcrypt (constant-time-ish), never plaintext;
 *  - the same generic 401 is returned for "unknown user" and "wrong password"
 *    to prevent username enumeration;
 *  - endpoint is rate-limited against brute force.
 */
function authRoutes({ config }) {
  // Router is created per app instance so rate-limit stores and route
  // registrations are never shared between applications.
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