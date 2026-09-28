'use strict';

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
      'security/detect-possible-timing-attacks': 'off',
      'security/detect-non-literal-fs-filename': 'off',
    },
  },
];
