require('dotenv').config();

const fs = require('node:fs');
const path = require('node:path');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { Pool } = require('pg');
const {
  generateAccessCode,
  generateToken,
  isValidPassword,
  isValidUsername,
  normalizeAccessCode,
  normalizeUsername,
  sha256
} = require('./auth-utils');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_DAYS = Math.max(1, Math.min(30, Number(process.env.SESSION_DAYS || 7)));
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;
const COOKIE_NAME = 'msn_session';
const isProduction = process.env.NODE_ENV === 'production';
const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) throw new Error('Не задана переменная DATABASE_URL');

const isLocalDatabase = /localhost|127\.0\.0\.1/.test(databaseUrl);
const pool = new Pool({
  connectionString: databaseUrl,
  ssl: isLocalDatabase ? false : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '16kb' }));
app.use(cookieParser());

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use('/api', (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  const expectedOrigin = `${req.protocol}://${req.get('host')}`;
  if (origin && origin !== expectedOrigin) {
    return res.status(403).json({ error: 'Запрос отклонён проверкой источника.' });
  }
  return next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Слишком много попыток. Повторите через 15 минут.' }
});

function setSessionCookie(res, token) {
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: SESSION_MS,
    path: '/'
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: '/'
  });
}

async function audit(client, actorUserId, action, targetUserId = null, metadata = {}) {
  await client.query(
    'INSERT INTO audit_log (actor_user_id, action, target_user_id, metadata) VALUES ($1, $2, $3, $4)',
    [actorUserId, action, targetUserId, JSON.stringify(metadata)]
  );
}

async function createSession(user, req, res, client = pool) {
  const token = generateToken();
  const tokenHash = sha256(token);
  const expiresAt = new Date(Date.now() + SESSION_MS);
  await client.query(
    `INSERT INTO sessions (token_hash, user_id, expires_at, ip_address, user_agent)
     VALUES ($1, $2, $3, $4, $5)`,
    [tokenHash, user.id, expiresAt, req.ip, String(req.get('user-agent') || '').slice(0, 500)]
  );
  setSessionCookie(res, token);
}

async function getSessionUser(req) {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return null;
  const tokenHash = sha256(token);
  const result = await pool.query(
    `SELECT u.id, u.username, u.role, u.blocked, s.expires_at
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > NOW()`,
    [tokenHash]
  );
  const user = result.rows[0];
  if (!user || user.blocked) {
    await pool.query('DELETE FROM sessions WHERE token_hash = $1', [tokenHash]);
    return null;
  }
  pool.query('UPDATE sessions SET last_seen_at = NOW() WHERE token_hash = $1', [tokenHash]).catch(() => {});
  return user;
}

async function requireApiAuth(req, res, next) {
  try {
    req.user = await getSessionUser(req);
    if (!req.user) {
      clearSessionCookie(res);
      return res.status(401).json({ error: 'Нужно войти в аккаунт.' });
    }
    return next();
  } catch (error) {
    return next(error);
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Недостаточно прав.' });
  return next();
}

function protectedPage(role) {
  return async (req, res, next) => {
    try {
      const user = await getSessionUser(req);
      if (!user) {
        clearSessionCookie(res);
        return res.redirect('/login');
      }
      if (role && user.role !== role) return res.redirect('/app');
      return next();
    } catch (error) {
      return next(error);
    }
  };
}

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.status(200).json({ status: 'ok' });
  } catch (_error) {
    res.status(503).json({ status: 'unavailable' });
  }
});

app.get('/', async (req, res, next) => {
  try {
    const user = await getSessionUser(req);
    if (!user) return res.redirect('/login');
    return res.redirect(user.role === 'admin' ? '/admin' : '/app');
  } catch (error) {
    return next(error);
  }
});

app.get('/login', async (req, res, next) => {
  try {
    const user = await getSessionUser(req);
    if (user) return res.redirect(user.role === 'admin' ? '/admin' : '/app');
    return res.sendFile(path.join(__dirname, 'public', 'login.html'));
  } catch (error) {
    return next(error);
  }
});

app.get('/app', protectedPage(), (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'app.html'));
});

app.get('/admin', protectedPage('admin'), (_req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/api/auth/me', requireApiAuth, (req, res) => {
  res.json({ user: { id: req.user.id, username: req.user.username, role: req.user.role } });
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || '');
    const result = await pool.query(
      `SELECT id, username, password_hash, role, blocked, failed_login_attempts, locked_until
         FROM users WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];

    if (!user) {
      await bcrypt.compare(password, '$2b$12$0VY3vQ4P3bM/Vf0Yty9PzeQn3ywhXwO1P7LQwCVa93/vHLnr.ySGC');
      return res.status(401).json({ error: 'Неверный логин или пароль.' });
    }
    if (user.blocked) return res.status(403).json({ error: 'Аккаунт заблокирован администратором.' });
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return res.status(429).json({ error: 'Аккаунт временно заблокирован после неверных попыток.' });
    }

    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      const attempts = Number(user.failed_login_attempts || 0) + 1;
      await pool.query(
        `UPDATE users
            SET failed_login_attempts = $2,
                locked_until = CASE WHEN $2 >= 5 THEN NOW() + INTERVAL '15 minutes' ELSE NULL END
          WHERE id = $1`,
        [user.id, attempts]
      );
      return res.status(401).json({ error: 'Неверный логин или пароль.' });
    }

    await pool.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1',
      [user.id]
    );
    await createSession(user, req, res);
    await audit(pool, user.id, 'login');
    return res.json({ ok: true, redirect: user.role === 'admin' ? '/admin' : '/app' });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/auth/activate', authLimiter, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || '');
    const accessCode = normalizeAccessCode(req.body.accessCode);

    if (!isValidUsername(username)) {
      return res.status(400).json({ error: 'Логин: 3–32 символа, латинские буквы, цифры, точка, дефис или подчёркивание.' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Пароль должен содержать от 10 до 128 символов.' });
    }
    if (!accessCode) return res.status(400).json({ error: 'Введите одноразовый код администратора.' });

    await client.query('BEGIN');
    const keyResult = await client.query(
      `SELECT id FROM access_keys
        WHERE code_hash = $1
          AND used_at IS NULL
          AND revoked_at IS NULL
          AND expires_at > NOW()
        FOR UPDATE`,
      [sha256(accessCode)]
    );
    const accessKey = keyResult.rows[0];
    if (!accessKey) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Код недействителен, уже использован или истёк.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    let user;
    try {
      const userResult = await client.query(
        `INSERT INTO users (username, password_hash, role)
         VALUES ($1, $2, 'user')
         RETURNING id, username, role`,
        [username, passwordHash]
      );
      user = userResult.rows[0];
    } catch (error) {
      if (error.code === '23505') {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'Этот логин уже занят.' });
      }
      throw error;
    }

    await client.query(
      'UPDATE access_keys SET used_at = NOW(), used_by = $2 WHERE id = $1 AND used_at IS NULL',
      [accessKey.id, user.id]
    );
    await createSession(user, req, res, client);
    await audit(client, user.id, 'account_activated', user.id, { accessKeyId: accessKey.id });
    await client.query('COMMIT');
    return res.status(201).json({ ok: true, redirect: '/app' });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    return next(error);
  } finally {
    client.release();
  }
});

app.post('/api/auth/logout', async (req, res, next) => {
  try {
    const token = req.cookies[COOKIE_NAME];
    if (token) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [sha256(token)]);
    clearSessionCookie(res);
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
});

app.get('/api/admin/overview', requireApiAuth, requireAdmin, async (_req, res, next) => {
  try {
    const [users, keys, stats, events] = await Promise.all([
      pool.query(
        `SELECT id, username, role, blocked, created_at, last_login_at
           FROM users ORDER BY role = 'admin' DESC, created_at DESC`
      ),
      pool.query(
        `SELECT k.id, k.code_preview, k.label, k.created_at, k.expires_at, k.used_at, k.revoked_at,
                u.username AS used_by_username
           FROM access_keys k
           LEFT JOIN users u ON u.id = k.used_by
          ORDER BY k.created_at DESC LIMIT 100`
      ),
      pool.query(
        `SELECT
          (SELECT COUNT(*)::int FROM users WHERE role = 'user') AS users_total,
          (SELECT COUNT(*)::int FROM users WHERE role = 'user' AND blocked) AS users_blocked,
          (SELECT COUNT(*)::int FROM sessions WHERE expires_at > NOW()) AS sessions_active,
          (SELECT COUNT(*)::int FROM access_keys WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()) AS keys_active`
      ),
      pool.query(
        `SELECT a.id, a.action, a.created_at, actor.username AS actor_username, target.username AS target_username
           FROM audit_log a
           LEFT JOIN users actor ON actor.id = a.actor_user_id
           LEFT JOIN users target ON target.id = a.target_user_id
          ORDER BY a.created_at DESC LIMIT 30`
      )
    ]);
    return res.json({ users: users.rows, keys: keys.rows, stats: stats.rows[0], events: events.rows });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/admin/keys', requireApiAuth, requireAdmin, async (req, res, next) => {
  try {
    const days = Math.max(1, Math.min(30, Number(req.body.days || 7)));
    const label = String(req.body.label || '').trim().slice(0, 80) || null;
    const code = generateAccessCode();
    const preview = `${code.slice(0, 8)}…${code.slice(-4)}`;
    const result = await pool.query(
      `INSERT INTO access_keys (code_hash, code_preview, label, created_by, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + ($5::int * INTERVAL '1 day'))
       RETURNING id, code_preview, label, created_at, expires_at`,
      [sha256(code), preview, label, req.user.id, days]
    );
    await audit(pool, req.user.id, 'access_key_created', null, { accessKeyId: result.rows[0].id, days, label });
    return res.status(201).json({ key: { ...result.rows[0], code } });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/admin/keys/:id/revoke', requireApiAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Некорректный ключ.' });
    const result = await pool.query(
      `UPDATE access_keys SET revoked_at = NOW()
        WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL
        RETURNING id`,
      [id]
    );
    if (!result.rowCount) return res.status(409).json({ error: 'Ключ уже использован или отозван.' });
    await audit(pool, req.user.id, 'access_key_revoked', null, { accessKeyId: id });
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/admin/users/:id/block', requireApiAuth, requireAdmin, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Некорректный пользователь.' });
    if (id === Number(req.user.id)) return res.status(400).json({ error: 'Нельзя заблокировать собственный аккаунт.' });
    await client.query('BEGIN');
    const result = await client.query(
      `UPDATE users SET blocked = TRUE, blocked_at = NOW()
        WHERE id = $1 AND role = 'user'
        RETURNING id`,
      [id]
    );
    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Пользователь не найден.' });
    }
    await client.query('DELETE FROM sessions WHERE user_id = $1', [id]);
    await audit(client, req.user.id, 'user_blocked', id);
    await client.query('COMMIT');
    return res.json({ ok: true });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    return next(error);
  } finally {
    client.release();
  }
});

app.post('/api/admin/users/:id/unblock', requireApiAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'Некорректный пользователь.' });
    const result = await pool.query(
      `UPDATE users
          SET blocked = FALSE, blocked_at = NULL, failed_login_attempts = 0, locked_until = NULL
        WHERE id = $1 AND role = 'user'
        RETURNING id`,
      [id]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'Пользователь не найден.' });
    await audit(pool, req.user.id, 'user_unblocked', id);
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
});

app.post('/api/admin/users/:id/revoke-sessions', requireApiAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1 || id === Number(req.user.id)) {
      return res.status(400).json({ error: 'Некорректный пользователь.' });
    }
    await pool.query('DELETE FROM sessions WHERE user_id = $1', [id]);
    await audit(pool, req.user.id, 'sessions_revoked', id);
    return res.json({ ok: true });
  } catch (error) {
    return next(error);
  }
});

app.use((_req, res) => res.status(404).json({ error: 'Страница не найдена.' }));

app.use((error, _req, res, _next) => {
  console.error(error);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Ошибка сервера. Попробуйте ещё раз.' });
});

async function initialize() {
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
  await pool.query('DELETE FROM sessions WHERE expires_at <= NOW()');

  const adminResult = await pool.query("SELECT id, username FROM users WHERE role = 'admin' LIMIT 1");
  if (!adminResult.rowCount) {
    const adminLogin = normalizeUsername(process.env.ADMIN_LOGIN);
    const adminPassword = String(process.env.ADMIN_PASSWORD || '');
    if (!isValidUsername(adminLogin) || !isValidPassword(adminPassword)) {
      throw new Error('Для первого запуска задайте ADMIN_LOGIN и ADMIN_PASSWORD (минимум 10 символов)');
    }
    const passwordHash = await bcrypt.hash(adminPassword, 12);
    await pool.query(
      "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')",
      [adminLogin, passwordHash]
    );
    console.log(`Создан аккаунт администратора: ${adminLogin}`);
  }

  app.listen(PORT, () => console.log(`MS NAVIGATOR запущен на порту ${PORT}`));
}

initialize().catch((error) => {
  console.error('Не удалось запустить приложение:', error.message);
  process.exit(1);
});

async function shutdown() {
  await pool.end();
  process.exit(0);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
