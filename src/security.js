'use strict';

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

function sanitizeText(input) {
  return String(input ?? '')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .trim();
}

function isValidUsername(username) {
  return typeof username === 'string' && /^[a-zA-Z0-9_]{3,32}$/.test(username);
}

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