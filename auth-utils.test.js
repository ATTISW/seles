const test = require('node:test');
const assert = require('node:assert/strict');
const {
  generateAccessCode,
  isValidPassword,
  isValidUsername,
  normalizeUsername,
  sha256
} = require('./auth-utils');

test('логин нормализуется и проверяется', () => {
  assert.equal(normalizeUsername('  User.Name  '), 'user.name');
  assert.equal(isValidUsername('user-01'), true);
  assert.equal(isValidUsername('я'), false);
  assert.equal(isValidUsername('ab'), false);
});

test('пароль должен быть не короче 10 символов', () => {
  assert.equal(isValidPassword('123456789'), false);
  assert.equal(isValidPassword('1234567890'), true);
});

test('одноразовые коды уникальны и имеют ожидаемый формат', () => {
  const first = generateAccessCode();
  const second = generateAccessCode();
  assert.match(first, /^MSN-[A-Z2-9]{4}(?:-[A-Z2-9]{4}){3}$/);
  assert.notEqual(first, second);
  assert.equal(sha256(first).length, 64);
});
