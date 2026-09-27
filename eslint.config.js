'use strict';

/**
 * ESLint flat config used as a lightweight SAST (static application security
 * testing) tool — `eslint-plugin-security` flags common insecure patterns:
 * eval/Function usage, unsafe regex, object injection, timing attacks, etc.
 */

const security = require('eslint-plugin-security');

module.exports = [
  {
    ignores: ['node_modules/**', 'data/**', 'coverage/**'],
  },
  security.configs.recommended,
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        console: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        URL: 'readonly',
        setTimeout: 'readonly',
        fetch: 'readonly',
        AbortController: 'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      'no-undef': 'error',
      // False positives for this codebase (see notes):
      //  - passwords/tokens are compared via bcrypt.compareSync and
      //    jwt.verify — constant-time inside those libraries
      'security/detect-possible-timing-attacks': 'off',
      //  - DB path comes from an env var at startup, not from user input
      'security/detect-non-literal-fs-filename': 'off',
    },
  },
];