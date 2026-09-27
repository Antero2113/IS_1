'use strict';

const express = require('express');
const helmet = require('helmet');
const { createAuth } = require('./auth');
const { authRoutes } = require('./routes/authRoutes');
const dataRoutes = require('./routes/dataRoutes');

/**
 * Express application factory.
 *
 * Security middleware applied globally:
 *  - helmet(): security headers (CSP, X-Content-Type-Options, HSTS, ...);
 *  - x-powered-by disabled (no server fingerprinting);
 *  - strict 10kb JSON body limit;
 *  - global 404 + centralized error handler (no stack traces leaked to client).
 *
 * Protected area: everything mounted under /api requires a valid JWT
 * (authenticateToken middleware).
 */
function createApp({ db, config }) {
  const app = express();
  const auth = createAuth(config);

  app.locals.db = db;
  app.locals.config = config;
  app.locals.auth = auth;

  app.disable('x-powered-by');
  app.use(helmet());
  app.use(express.json({ limit: '10kb' }));

  // Public endpoints
  app.get('/health', (req, res) => res.json({ status: 'ok' }));

  // Auth (public): POST /auth/login
  app.use('/auth', authRoutes({ config }));

  // Everything under /api requires authentication
  app.use('/api', auth.authenticateToken, dataRoutes);

  // 404 handler
  app.use((req, res) => res.status(404).json({ error: 'Not found' }));

  // Centralized error handler — never leaks internals to the client
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error('[error]', err.message);
    res.status(err.status || 500).json({ error: 'Internal server error' });
  });

  return app;
}

module.exports = { createApp };