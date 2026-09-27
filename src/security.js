'use strict';

/**
 * Input sanitization and output escaping helpers.
 *
 * References:
 *  - OWASP XSS Prevention Cheat Sheet:
 *    https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
 *  - OWASP Input Validation Cheat Sheet
 */

/**
 * OWASP-recommended HTML entity escaping.
 * Applied to ALL user-supplied data before it is returned in API responses
 * (defense against stored/reflected XSS).
 *
 * Entities are built via concatenation so they survive any tooling that
 * might decode HTML entities. The switch only ever receives characters from
 * the fixed class `[&<>"'/]`, never arbitrary user input.
 */
function escapeHtml(input) {
  return String(input ?? '').replace(/[&<>"'/]/g, (ch) => {
    switch (ch) {
      case '&':
        return '&' + 'amp;';
      case '<':
        return '&' + 'lt;';
      case '>':
        return '&' + 'gt;';
      case '"':
        return '&' + 'quot;';
      case "'":
        return '&' + '#x27;';
      default:
        return '&' + '#x2F;';
    }
  });
}

/**
 * Normalizes free-text input: strips control characters and trims whitespace.
 * This is a whitelist-style normalization before validation/storage.
 */
function sanitizeText(input) {
  return String(input ?? '')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .trim();
}

/** Username policy: 3–32 chars, latin letters/digits/underscore only. */
function isValidUsername(username) {
  return typeof username === 'string' && /^[a-zA-Z0-9_]{3,32}$/.test(username);
}

/** Password policy: 8–128 chars. Stored ONLY as a bcrypt hash, never plaintext. */
function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

function isValidTitle(title) {
  return typeof title === 'string' && title.length >= 1 && title.length <= 120;
}

function isValidContent(content) {
  return typeof content === 'string' && content.length >= 1 && content.length <= 5000;
}

module.exports = {
  escapeHtml,
  sanitizeText,
  isValidUsername,
  isValidPassword,
  isValidTitle,
  isValidContent,
};