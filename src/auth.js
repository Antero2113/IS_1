'use strict';

const jwt = require('jsonwebtoken');

function createAuth(config) {
  const ISSUER = 'is1-api';
  const AUDIENCE = 'is1-client';

  function signToken(user) {
    return jwt.sign(
      { sub: String(user.id), username: user.username, role: user.role },
      config.jwtSecret,
      { expiresIn: config.jwtExpiresIn, issuer: ISSUER, audience: AUDIENCE }
    );
  }

  function authenticateToken(req, res, next) {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');

    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ error: 'Missing or malformed Authorization header' });
    }

    try {
      const payload = jwt.verify(token, config.jwtSecret, {
        issuer: ISSUER,
        audience: AUDIENCE,
      });
      req.user = { id: Number(payload.sub), username: payload.username, role: payload.role };
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  }

  return { signToken, authenticateToken };
}

module.exports = { createAuth };