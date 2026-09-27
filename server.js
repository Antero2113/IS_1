'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { getConfig } = require('./src/config');
const { createDb } = require('./src/db');
const { createApp } = require('./src/app');

const config = getConfig();

if (config.dbPath !== ':memory:') {
  fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });
}

const db = createDb({ path: config.dbPath });
const app = createApp({ db, config });

app.listen(config.port, () => {
  console.log(`[server] Secure API listening on http://localhost:${config.port}`);
  console.log('[server] Demo logins -> admin / Admin123!  |  alice / Alice123!');
});