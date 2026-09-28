'use strict';

const express = require('express');
const helmet = require('helmet');
const { createAuth } = require('./auth');
const { authRoutes } = require('./routes/authRoutes');
const dataRoutes = require('./routes/dataRoutes');

function createApp({ db, config }) {
  const app = express();
  const auth = createAuth(config);

  app.locals.db = db;
  app.locals.config = config;
  app.locals.auth = auth;

  app.disable('x-powered-by');
  app.use(helmet());
  app.use(express.json({ limit: '10kb' }));

  app.get('/health', (req, res) => res.json({ status: 'ok' }));

  app.use('/auth', authRoutes({ config }));

  app.use('/api', auth.authenticateToken, dataRoutes);

  app.use((req, res) => res.status(404).json({ error: 'Not found' }));

  app.use((err, req, res, next) => {
    console.error('[error]', err.message);
    res.status(err.status || 500).json({ error: 'Internal server error' });
  });

  return app;
}

module.exports = { createApp };