'use strict';

/**
 * Centralized, environment-based configuration.
 * Secrets must NOT be committed — set JWT_SECRET via environment variable.
 */

const DEFAULT_JWT_SECRET = 'insecure-dev-secret-change-me';

function getConfig(env = process.env) {
  const jwtSecret = env.JWT_SECRET || DEFAULT_JWT_SECRET;
  if (jwtSecret === DEFAULT_JWT_SECRET || jwtSecret.length < 16) {
    console.warn(
      '[config] WARNING: JWT_SECRET is missing/weak. Set a strong secret (>=16 chars) in production.'
    );
  }

  return {
    port: Number(env.PORT) || 3000,
    dbPath: env.DB_PATH || './data/app.db',
    jwtSecret,
    jwtExpiresIn: env.JWT_EXPIRES_IN || '1h',
    // Brute-force protection for the login endpoint
    loginRateLimitWindowMs: Number(env.LOGIN_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    loginRateLimitMax: Number(env.LOGIN_RATE_LIMIT_MAX) || 5,
  };
}

module.exports = { getConfig };