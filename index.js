const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Настройка CORS. Если на Render есть переменная CORS_ORIGIN, используем её. Иначе разрешаем всем.
const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(',').map(x => x.trim())
  : true;

app.use(cors({
  origin: allowedOrigins,
  credentials: false,
  methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '12mb' }));

// ==========================================
// PREMIUM KEYS
// ==========================================
let secretKeys = {};

try {
  if (process.env.premium_keys) {
    const raw = JSON.parse(process.env.premium_keys);
    const arr = raw.codes || raw;

    if (Array.isArray(arr)) {
      for (const k of arr) {
        secretKeys[String(k.id).toUpperCase()] = {
          duration: k.duration,
          max_activations: Number(k.max_activations || 1),
          used: Boolean(k.used),
          gived: Boolean(k.gived)
        };
      }
    } else {
      secretKeys = Object.fromEntries(
        Object.entries(arr).map(([key, value]) => [
          key.toUpperCase(),
          value
        ])
      );
    }
  }
  console.log(`Загружено ключей: ${Object.keys(secretKeys).length}`);
} catch (e) {
  console.error('Ошибка premium_keys:', e.message);
}

// ==========================================
// SQLITE
// ==========================================
const dbPath = process.env.DB_PATH || './database.sqlite';

fs.mkdirSync(path.dirname(path.resolve(dbPath)), {
  recursive: true
});

const db = new sqlite3.Database(dbPath, err => {
  if (err) console.error('Ошибка SQLite:', err.message);
  else console.log('SQLite подключена:', dbPath);
});

const dbGet = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });

const dbAll = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });

const dbRun = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });

const normalizeUsername = value => String(value || '').trim().toLowerCase();
const validUsername = value => /^[a-zA-Z0-9_]{3,24}$/.test(value);
const hashSecret = value => crypto.createHash('sha256').update(value).digest('hex');

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    avatar: user.avatar || '',
    cover: user.cover || '',
    createdAt: user.created_at
  };
}

let premiumQueue = Promise.resolve();
function runPremiumExclusive(task) {
  const result = premiumQueue.then(task, task);
  premiumQueue = result.catch(() => {});
  return result;
}

function durationDays(duration) {
  const durations = {
    '7_days': 7,
    '1_month': 30,
    '3_months': 90,
    '6_months': 180,
    'forever': 3650
  };
  return durations[duration] || 30;
}

// ==========================================
// DATABASE INITIALIZATION
// ==========================================
async function initializeDatabase() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS activations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_id TEXT,
      device_id TEXT,
      expires INTEGER
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS key_status (
      key_id TEXT PRIMARY KEY,
      gived INTEGER DEFAULT 0,
      used INTEGER DEFAULT 0
    )
  `);

  const keyStatusColumns = await dbAll('PRAGMA table_info(key_status)');
  if (!keyStatusColumns.some(c => c.name === 'used')) {
    await dbRun('ALTER TABLE key_status ADD COLUMN used INTEGER DEFAULT 0');
  }

  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      username_norm TEXT NOT NULL UNIQUE,
      email TEXT,
      email_norm TEXT,
      password_hash TEXT NOT NULL,
      avatar TEXT DEFAULT '',
      cover TEXT DEFAULT '',
      created_at INTEGER NOT NULL
    )
  `);

  const columns = await dbAll('PRAGMA table_info(users)');
  const emailCol = columns.find(c => c.name === 'email');
  const emailNormCol = columns.find(c => c.name === 'email_norm');

  if ((emailCol && emailCol.notnull) || (emailNormCol && emailNormCol.notnull)) {
    await dbRun('BEGIN IMMEDIATE');
    try {
      await dbRun(`
        CREATE TABLE users_migrated (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL,
          username_norm TEXT NOT NULL UNIQUE,
          email TEXT,
          email_norm TEXT,
          password_hash TEXT NOT NULL,
          avatar TEXT DEFAULT '',
          cover TEXT DEFAULT '',
          created_at INTEGER NOT NULL
        )
      `);

      await dbRun(`
        INSERT INTO users_migrated (
          id, username, username_norm, email, email_norm, password_hash, avatar, cover, created_at
        )
        SELECT id, username, username_norm, email, email_norm, password_hash, COALESCE(avatar, ''), COALESCE(cover, ''), created_at
        FROM users
      `);

      await dbRun('DROP TABLE users');
      await dbRun('ALTER TABLE users_migrated RENAME TO users');
      await dbRun('COMMIT');
      console.log('Схема users обновлена');
    } catch (e) {
      await dbRun('ROLLBACK').catch(() => {});
      throw e;
    }
  }

  await dbRun(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS auth_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      purpose TEXT NOT NULL,
      email_norm TEXT NOT NULL,
      username TEXT,
      password_hash TEXT,
      code_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      attempts INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL
    )
  `);

  await dbRun(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_activations_device ON activations(device_id)`);
}

// ==========================================
// RESTORE KEY STATUSES
// ==========================================
async function restoreKeyStatuses() {
  const savedKeyStatuses = await dbAll('SELECT key_id, gived, used FROM key_status');
  for (const row of savedKeyStatuses) {
    const id = String(row.key_id).toUpperCase();
    if (secretKeys[id]) {
      secretKeys[id].gived = Boolean(row.gived);
      secretKeys[id].used = Boolean(row.used);
    }
  }

  for (const [id, config] of Object.entries(secretKeys)) {
    const result = await dbGet('SELECT COUNT(*) AS count FROM activations WHERE key_id = ?', [id]);
    const max = Math.max(1, Number(config.max_activations) || 1);
    if ((result?.count || 0) >= max) {
      config.used = true;
      await dbRun(
        `INSERT INTO key_status (key_id, gived, used) VALUES (?, 1, 1)
         ON CONFLICT(key_id) DO UPDATE SET gived = 1, used = 1`,
        [id]
      );
    }
  }
}

// ==========================================
// SESSIONS & AUTH
// ==========================================
async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  await dbRun(
    `INSERT INTO sessions (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)`,
    [userId, hashSecret(token), now + 30 * 86400000, now]
  );
  return token;
}

async function authMiddleware(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!token) return res.status(401).json({ message: 'Необходим вход' });

    const session = await dbGet(
      `SELECT users.*, sessions.id AS session_id, sessions.expires_at
       FROM sessions JOIN users ON users.id = sessions.user_id
       WHERE sessions.token_hash = ?`,
      [hashSecret(token)]
    );

    if (!session || session.expires_at < Date.now()) {
      return res.status(401).json({ message: 'Сессия истекла' });
    }

    req.user = session;
    req.sessionId = session.session_id;
    next();
  } catch (e) {
    console.error('AUTH:', e);
    res.status(500).json({ message: 'Ошибка авторизации' });
  }
}

// ==========================================
// ROUTES
// ==========================================
app.post('/api/auth/register', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    if (!validUsername(username)) return res.status(400).json({ message: 'Ник: 3–24 символа, латинские буквы, цифры и _' });
    if (password.length < 8 || password.length > 128) return res.status(400).json({ message: 'Пароль должен содержать от 8 до 128 символов' });

    const usernameNorm = normalizeUsername(username);
    const existing = await dbGet('SELECT id FROM users WHERE username_norm = ?', [usernameNorm]);
    if (existing) return res.status(409).json({ message: 'Этот никнейм уже занят' });

    const passwordHash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
    const now = Date.now();

    const result = await dbRun(
      `INSERT INTO users (username, username_norm, email, email_norm, password_hash, created_at) VALUES (?, ?, NULL, NULL, ?, ?)`,
      [username, usernameNorm, passwordHash, now]
    );

    const user = await dbGet('SELECT * FROM users WHERE id = ?', [result.lastID]);
    const token = await createSession(user.id);

    res.status(201).json({ success: true, token, user: publicUser(user) });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ message: 'Этот никнейм уже занят' });
    console.error('REGISTER:', e);
    res.status(500).json({ message: 'Ошибка регистрации' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const password = String(req.body?.password || '');
    if (!username || !password) return res.status(400).json({ message: 'Введите никнейм и пароль' });

    const user = await dbGet('SELECT * FROM users WHERE username_norm = ?', [username]);
    if (!user || !(await argon2.verify(user.password_hash, password))) {
      return res.status(401).json({ message: 'Неверный никнейм или пароль' });
    }

    const token = await createSession(user.id);
    res.json({ success: true, token, user: publicUser(user) });
  } catch (e) {
    console.error('LOGIN:', e);
    res.status(500).json({ message: 'Ошибка входа' });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.patch('/api/profile', authMiddleware, async (req, res) => {
  try {
    const username = String(req.body?.username ?? req.user.username).trim();
    const avatar = req.body?.avatar ?? req.user.avatar ?? '';
    const cover = req.body?.cover ?? req.user.cover ?? '';

    if (!validUsername(username)) return res.status(400).json({ message: 'Некорректный никнейм' });
    if (typeof avatar !== 'string' || typeof cover !== 'string' || avatar.length > 7 * 1024 * 1024 || cover.length > 7 * 1024 * 1024) {
      return res.status(400).json({ message: 'Некорректное изображение' });
    }

    const collision = await dbGet(`SELECT id FROM users WHERE username_norm = ? AND id != ?`, [normalizeUsername(username), req.user.id]);
    if (collision) return res.status(409).json({ message: 'Это имя уже занято' });

    await dbRun(
      `UPDATE users SET username = ?, username_norm = ?, avatar = ?, cover = ? WHERE id = ?`,
      [username, normalizeUsername(username), avatar, cover, req.user.id]
    );

    const user = await dbGet('SELECT * FROM users WHERE id = ?', [req.user.id]);
    res.json({ success: true, user: publicUser(user) });
  } catch (e) {
    console.error('PROFILE:', e);
    res.status(500).json({ message: 'Не удалось сохранить профиль' });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    await dbRun('DELETE FROM sessions WHERE id = ?', [req.sessionId]);
    res.json({ success: true });
  } catch (e) {
    console.error('LOGOUT:', e);
    res.status(500).json({ message: 'Ошибка выхода' });
  }
});

app.post('/api/get-key', async (req, res) => {
  try {
    const duration = req.body?.duration;
    let foundKey = null;

    for (const [key, data] of Object.entries(secretKeys)) {
      if (data.duration === duration && !data.gived && !data.used) {
        foundKey = key;
        break;
      }
    }

    if (!foundKey) return res.status(404).json({ success: false, message: 'Нет свободных ключей для этого тарифа' });

    await dbRun(`INSERT OR REPLACE INTO key_status (key_id, gived) VALUES (?, 1)`, [foundKey]);
    secretKeys[foundKey].gived = true;
    res.json({ success: true, key: foundKey });
  } catch (e) {
    console.error('GET KEY:', e);
    res.status(500).json({ success: false, message: 'Ошибка базы данных' });
  }
});

// ==========================================
// ВОТ ЗДЕСЬ ВАЖНЫЙ МОМЕНТ: МЕТОД POST
// ==========================================
app.post('/api/activate', async (req, res) => {
  try {
    const key = String(req.body?.key || '').trim().toUpperCase();
    const deviceId = String(req.body?.deviceId || '').trim();

    if (!key || !deviceId) {
      return res.status(400).json({ success: false, message: 'Не передан ключ или ID устройства' });
    }

    if (key.length > 200 || deviceId.length > 200) {
      return res.status(400).json({ success: false, message: 'Некорректные данные' });
    }

    const config = secretKeys[key];
    if (!config) {
      return res.status(404).json({ success: false, message: 'invalid_key' });
    }

    const activation = await runPremiumExclusive(async () => {
      const saved = await dbGet('SELECT gived, used FROM key_status WHERE key_id = ?', [key]);
      if (saved?.used) config.used = true;

      const existing = await dbGet(
        `SELECT * FROM activations WHERE key_id = ? AND device_id = ? ORDER BY expires DESC LIMIT 1`,
        [key, deviceId]
      );

      if (existing && existing.expires > Date.now()) return { error: 'already_activated_here' };

      const count = await dbGet('SELECT COUNT(*) AS count FROM activations WHERE key_id = ?', [key]);
      const max = Math.max(1, Number(config.max_activations) || 1);

      if ((count?.count || 0) >= max) {
        config.used = true;
        await dbRun(
          `INSERT INTO key_status (key_id, gived, used) VALUES (?, 1, 1)
           ON CONFLICT(key_id) DO UPDATE SET gived = 1, used = 1`,
          [key]
        );
        return { error: 'exhausted' };
      }

      const expires = Date.now() + durationDays(config.duration) * 86400000;
      await dbRun(
        `INSERT INTO activations (key_id, device_id, expires) VALUES (?, ?, ?)`,
        [key, deviceId, expires]
      );

      const newCount = (count?.count || 0) + 1;
      const used = newCount >= max;

      await dbRun(
        `INSERT INTO key_status (key_id, gived, used) VALUES (?, 1, ?)
         ON CONFLICT(key_id) DO UPDATE SET gived = 1, used = MAX(key_status.used, excluded.used)`,
        [key, used ? 1 : 0]
      );

      config.gived = true;
      config.used = used;
      return { expires, duration: config.duration };
    });

    if (activation.error) {
      const messages = {
        already_activated_here: 'Этот ключ уже активирован на данном устройстве',
        exhausted: 'Лимит активаций этого ключа исчерпан'
      };
      return res.status(400).json({ success: false, message: activation.error, error: messages[activation.error] });
    }

    return res.json({ success: true, message: 'premium_activated', duration: activation.duration, expires: activation.expires });
  } catch (e) {
    console.error('ACTIVATE ERROR:', e);
    return res.status(500).json({ success: false, message: 'Ошибка активации ключа', error: process.env.NODE_ENV === 'development' ? e.message : undefined });
  }
});

app.get('/api/status', async (req, res) => {
  try {
    const deviceId = String(req.query.deviceId || '').trim();
    if (!deviceId) return res.status(400).json({ active: false, message: 'Не передан ID устройства' });

    const row = await dbGet(
      `SELECT * FROM activations WHERE device_id = ? ORDER BY expires DESC LIMIT 1`,
      [deviceId]
    );

    if (!row || Date.now() >= row.expires) return res.json({ active: false });

    const config = secretKeys[row.key_id] || {};
    return res.json({ active: true, expires: row.expires, duration: config.duration || '1_month' });
  } catch (e) {
    console.error('STATUS ERROR:', e);
    return res.status(500).json({ active: false, message: 'Ошибка проверки Premium' });
  }
});

app.get('/', (req, res) => {
  res.send('ProxyGem API работает ✅');
});

app.get('/api/health', async (req, res) => {
  try {
    await dbGet('SELECT 1');
    res.json({ success: true, server: true, database: true, auth: 'username-password', time: new Date().toISOString() });
  } catch (e) {
    console.error('HEALTH:', e);
    res.status(500).json({ success: false, server: true, database: false });
  }
});

app.use((err, req, res, next) => {
  console.error('UNHANDLED ERROR:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ success: false, message: 'Внутренняя ошибка сервера' });
});

// ==========================================
// START SERVER
// ==========================================
initializeDatabase()
  .then(restoreKeyStatuses)
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`ProxyGem API запущен на порту ${PORT}`);
      console.log('База данных готова');
    });
  })
  .catch(err => {
    console.error('Не удалось инициализировать базу:', err);
    process.exit(1);
  });

// Замените на ваш реальный адрес Render
const API_URL = 'https://ВАШ-СЕРВЕР.onrender.com/api/activate'; 

// Данные для теста
const keyFromInput = "32131313213"; 
// В реальном приложении deviceId должен генерироваться один раз и сохраняться в localStorage
const deviceId = "test-device-" + Math.floor(Math.random() * 10000); 

async function activatePremium() {
  try {
    console.log("Отправка запроса...");
    
    const response = await fetch(API_URL, {
      method: 'POST', // <--- ОБЯЗАТЕЛЬНО POST
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        key: keyFromInput,
        deviceId: deviceId
      })
    });

    const data = await response.json();
    
    if (!response.ok) {
      // Если сервер вернул ошибку (400, 404, 500)
      console.error("Ошибка от сервера:", data);
      alert(data.error || data.message || "Ошибка активации");
      return;
    }

    // Если всё успешно
    console.log("Успех!", data);
    alert("Премиум активирован! Истекает: " + new Date(data.expires).toLocaleDateString());
    
  } catch (error) {
    // Если произошла сетевая ошибка (CORS, нет интернета, сервер выключен)
    console.error("Сетевая ошибка:", error);
    alert("Ошибка соединения с сервером. Проверьте консоль.");
  }
}

// Запуск
activatePremium();
