const crypto = require('node:crypto');

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;

function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidUsername(value) {
  return USERNAME_RE.test(normalizeUsername(value));
}

function isValidPassword(value) {
  return typeof value === 'string' && value.length >= 10 && value.length <= 128;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function generateToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function generateAccessCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(16);
  let raw = '';
  for (let i = 0; i < 16; i += 1) raw += alphabet[bytes[i] % alphabet.length];
  return `MSN-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

function normalizeAccessCode(value) {
  return String(value || '').trim().toUpperCase().replace(/\s+/g, '');
}

module.exports = {
  generateAccessCode,
  generateToken,
  isValidPassword,
  isValidUsername,
  normalizeAccessCode,
  normalizeUsername,
  sha256
};
