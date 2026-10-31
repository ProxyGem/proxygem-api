
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const argon2 = require('argon2');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. CORS И JSON
// ==========================================

const allowedOrigins = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map(x => x.trim())
    : true;

app.use(cors({
    origin: allowedOrigins,
    credentials: false,
    methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors({
    origin: allowedOrigins,
    credentials: false
}));

app.use(express.json({ limit: '12mb' }));

// ==========================================
// 2. SMTP
// ==========================================

const SMTP_PORT = Number(process.env.SMTP_PORT || 2525);

const mailer = (
    process.env.SMTP_HOST &&
    process.env.SMTP_USER &&
    process.env.SMTP_PASS
) ? nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS.replace(/\s/g, '')
    },
    connectionTimeout: 20000,
    greetingTimeout: 20000,
    socketTimeout: 30000
}) : null;

// ==========================================
// 3. PREMIUM KEYS
// ==========================================

let secretKeys = {};

try {
    if (process.env.premium_keys) {
        const rawData = JSON.parse(process.env.premium_keys);
        const keysArray = rawData.codes || rawData;

        if (Array.isArray(keysArray)) {
            keysArray.forEach(k => {
                secretKeys[k.id] = {
                    duration: k.duration,
                    max_activations: k.max_activations || 1,
                    used: k.used || false,
                    gived: k.gived || false
                };
            });
        } else {
            secretKeys = keysArray;
        }

        console.log(
            `Загружено ключей: ${Object.keys(secretKeys).length}`
        );
    } else {
        console.log('ВНИМАНИЕ: premium_keys не найдена');

        secretKeys = {
            'TEST-KEY-123': {
                duration: '1_month',
                max_activations: 1,
                used: false,
                gived: false
            }
        };
    }
} catch (err) {
    console.error('Ошибка premium_keys:', err.message);
}

// ==========================================
// 4. SQLITE
// ==========================================

const dbPath = process.env.DB_PATH || './database.sqlite';

fs.mkdirSync(
    path.dirname(path.resolve(dbPath)),
    { recursive: true }
);

const db = new sqlite3.Database(dbPath, err => {
    if (err) {
        console.error('Ошибка SQLite:', err.message);
    } else {
        console.log('SQLite подключена:', dbPath);
    }
});

const dbGet = (sql, params = []) =>
    new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });

const dbRun = (sql, params = []) =>
    new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve(this);
        });
    });

function initializeDatabase() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run(`CREATE TABLE IF NOT EXISTS activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT,
                device_id TEXT,
                expires INTEGER
            )`);

            db.run(`CREATE TABLE IF NOT EXISTS key_status (
                key_id TEXT PRIMARY KEY,
                gived INTEGER DEFAULT 0
            )`);

            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                username_norm TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL,
                email_norm TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                avatar TEXT DEFAULT '',
                cover TEXT DEFAULT '',
                created_at INTEGER NOT NULL
            )`);

            db.run(`CREATE TABLE IF NOT EXISTS auth_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                purpose TEXT NOT NULL,
                email_norm TEXT NOT NULL,
                username TEXT,
                password_hash TEXT,
                code_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
            )`);

            db.run(`CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )`);

            db.get('SELECT 1', [], err => {
                if (err) reject(err);
                else resolve();
            });
        });
    });
}

// ==========================================
// 5. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ==========================================

const CODE_PEPPER = process.env.CODE_PEPPER;

const normalizeEmail = email =>
    String(email || '').trim().toLowerCase();

const normalizeUsername = username =>
    String(username || '').trim().toLowerCase();

const validEmail = email =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const validUsername = username =>
    /^[a-zA-Z0-9_]{3,24}$/.test(username);

const hashSecret = value =>
    crypto.createHash('sha256').update(value).digest('hex');

const hashCode = (email, purpose, code) => {
    if (!CODE_PEPPER) {
        throw new Error('CODE_PEPPER не настроен');
    }

    return crypto.createHmac('sha256', CODE_PEPPER)
        .update(`${purpose}:${email}:${code}`)
        .digest('hex');
};

const safeEqual = (a, b) => {
    const x = Buffer.from(a);
    const y = Buffer.from(b);

    return x.length === y.length &&
        crypto.timingSafeEqual(x, y);
};

const publicUser = user => ({
    id: user.id,
    username: user.username,
    email: user.email,
    avatar: user.avatar || '',
    cover: user.cover || '',
    createdAt: user.created_at
});

// ==========================================
// 6. ОТПРАВКА EMAIL
// ==========================================

async function sendVerificationCode(email, code, purpose) {
    if (!mailer) {
        throw new Error('SMTP не настроен');
    }

    const subject = purpose === 'register'
        ? 'Подтверждение регистрации ProxyGem'
        : 'Восстановление пароля ProxyGem';

    const description = purpose === 'register'
        ? 'Для завершения регистрации введи этот код:'
        : 'Для восстановления пароля введи этот код:';

    await mailer.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: email,
        subject,
        text: `${description}\n\n${code}\n\nКод действителен 10 минут.`,
        html: `
            <div style="font-family:Arial,sans-serif;max-width:500px;margin:auto">
                <h2>ProxyGem</h2>
                <p>${description}</p>
                <div style="font-size:32px;font-weight:bold;letter-spacing:8px">
                    ${code}
                </div>
                <p>Код действителен 10 минут.</p>
            </div>
        `
    });
}

// ==========================================
// 7. СЕССИИ И АВТОРИЗАЦИЯ
// ==========================================

async function createSession(userId) {
    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = hashSecret(token);
    const now = Date.now();
    const expires = now + 30 * 24 * 60 * 60 * 1000;

    await dbRun(
        `INSERT INTO sessions
         (user_id, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?)`,
        [userId, tokenHash, expires, now]
    );

    return token;
}

async function authMiddleware(req, res, next) {
    try {
        const header = req.headers.authorization || '';

        const token = header.startsWith('Bearer ')
            ? header.slice(7)
            : '';

        if (!token) {
            return res.status(401).json({
                message: 'Необходим вход'
            });
        }

        const session = await dbGet(
            `SELECT users.*, sessions.id AS session_id,
             sessions.expires_at
             FROM sessions
             JOIN users ON users.id = sessions.user_id
             WHERE sessions.token_hash = ?`,
            [hashSecret(token)]
        );

        if (!session || session.expires_at < Date.now()) {
            return res.status(401).json({
                message: 'Сессия истекла'
            });
        }

        req.user = session;
        req.sessionId = session.session_id;

        next();
    } catch (err) {
        console.error('AUTH MIDDLEWARE:', err);

        res.status(500).json({
            message: 'Ошибка авторизации'
        });
    }
}

// ==========================================
// 8. ПРОВЕРКА USERNAME
// ==========================================

app.get('/api/auth/check-username', async (req, res) => {
    try {
        const username = String(req.query.username || '').trim();

        if (!validUsername(username)) {
            return res.json({
                available: false,
                message: 'Имя: 3–24 символа, латинские буквы, цифры и _'
            });
        }

        const existing = await dbGet(
            'SELECT id FROM users WHERE username_norm = ?',
            [normalizeUsername(username)]
        );

        res.json({
            available: !existing,
            message: existing ? 'Имя уже занято' : 'Имя свободно'
        });
    } catch (err) {
        console.error('CHECK USERNAME:', err);

        res.status(500).json({
            message: 'Ошибка базы данных'
        });
    }
});

// ==========================================
// 9. РЕГИСТРАЦИЯ: ЗАПРОС КОДА
// ==========================================

app.post('/api/auth/register/request-code', async (req, res) => {
    try {
        const body = req.body || {};

        const username = String(body.username || '').trim();
        const email = normalizeEmail(body.email);
        const password = String(body.password || '');

        if (!validUsername(username)) {
            return res.status(400).json({
                message: 'Некорректное имя пользователя'
            });
        }

        if (!validEmail(email)) {
            return res.status(400).json({
                message: 'Некорректный email'
            });
        }

        if (password.length < 8 || password.length > 128) {
            return res.status(400).json({
                message: 'Пароль должен содержать от 8 до 128 символов'
            });
        }

        if (!CODE_PEPPER || !mailer) {
            return res.status(503).json({
                message: 'Почтовый сервис пока не настроен'
            });
        }

        const existing = await dbGet(
            `SELECT id FROM users
             WHERE username_norm = ? OR email_norm = ?`,
            [normalizeUsername(username), email]
        );

        if (existing) {
            return res.status(409).json({
                message: 'Имя пользователя или email уже зарегистрированы'
            });
        }

        const previous = await dbGet(
            `SELECT created_at FROM auth_codes
             WHERE purpose = 'register' AND email_norm = ?
             ORDER BY id DESC LIMIT 1`,
            [email]
        );

        if (previous && Date.now() - previous.created_at < 60000) {
            return res.status(429).json({
                message: 'Подожди 60 секунд перед повторной отправкой'
            });
        }

        const passwordHash = await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: 19456,
            timeCost: 2,
            parallelism: 1
        });

        const code = String(crypto.randomInt(100000, 1000000));
        const now = Date.now();

        await dbRun(
            `DELETE FROM auth_codes
             WHERE purpose = 'register' AND email_norm = ?`,
            [email]
        );

        await dbRun(
            `INSERT INTO auth_codes
             (purpose, email_norm, username, password_hash,
              code_hash, expires_at, attempts, created_at)
             VALUES ('register', ?, ?, ?, ?, ?, 0, ?)`,
            [
                email,
                username,
                passwordHash,
                hashCode(email, 'register', code),
                now + 10 * 60 * 1000,
                now
            ]
        );

        try {
            await sendVerificationCode(email, code, 'register');
        } catch (mailError) {
            await dbRun(
                `DELETE FROM auth_codes
                 WHERE purpose = 'register' AND email_norm = ?`,
                [email]
            );

            throw mailError;
        }

        res.json({
            success: true,
            message: 'Код подтверждения отправлен на email'
        });
    } catch (err) {
        console.error('REGISTER REQUEST:', err);

        res.status(500).json({
            message: 'Не удалось отправить код'
        });
    }
});

// ==========================================
// 10. РЕГИСТРАЦИЯ: ПОДТВЕРЖДЕНИЕ
// ==========================================

app.post('/api/auth/register/verify', async (req, res) => {
    try {
        const body = req.body || {};

        const email = normalizeEmail(body.email);
        const code = String(body.code || '').trim();

        if (!validEmail(email) || !/^\d{6}$/.test(code)) {
            return res.status(400).json({
                message: 'Неверные данные'
            });
        }

        const pending = await dbGet(
            `SELECT * FROM auth_codes
             WHERE purpose = 'register' AND email_norm = ?
             ORDER BY id DESC LIMIT 1`,
            [email]
        );

        if (!pending || pending.expires_at < Date.now()) {
            return res.status(400).json({
                message: 'Код истёк или не найден'
            });
        }

        if (pending.attempts >= 5) {
            return res.status(429).json({
                message: 'Слишком много попыток. Запроси новый код'
            });
        }

        if (!safeEqual(
            pending.code_hash,
            hashCode(email, 'register', code)
        )) {
            await dbRun(
                'UPDATE auth_codes SET attempts = attempts + 1 WHERE id = ?',
                [pending.id]
            );

            return res.status(400).json({
                message: 'Неверный код'
            });
        }

        const collision = await dbGet(
            `SELECT id FROM users
             WHERE username_norm = ? OR email_norm = ?`,
            [normalizeUsername(pending.username), email]
        );

        if (collision) {
            return res.status(409).json({
                message: 'Имя пользователя или email уже заняты'
            });
        }

        const result = await dbRun(
            `INSERT INTO users
             (username, username_norm, email, email_norm,
              password_hash, created_at)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                pending.username,
                normalizeUsername(pending.username),
                email,
                email,
                pending.password_hash,
                Date.now()
            ]
        );

        await dbRun(
            'DELETE FROM auth_codes WHERE id = ?',
            [pending.id]
        );

        const user = await dbGet(
            'SELECT * FROM users WHERE id = ?',
            [result.lastID]
        );

        const token = await createSession(user.id);

        res.json({
            success: true,
            token,
            user: publicUser(user)
        });
    } catch (err) {
        console.error('REGISTER VERIFY:', err);

        res.status(500).json({
            message: 'Ошибка регистрации'
        });
    }
});

// ==========================================
// 11. ВХОД
// ==========================================

app.post('/api/auth/login', async (req, res) => {
    try {
        const body = req.body || {};

        const username = normalizeUsername(body.username);
        const password = String(body.password || '');

        const user = await dbGet(
            'SELECT * FROM users WHERE username_norm = ?',
            [username]
        );

        if (!user) {
            return res.status(401).json({
                message: 'Неверный логин или пароль'
            });
        }

        const valid = await argon2.verify(
            user.password_hash,
            password
        );

        if (!valid) {
            return res.status(401).json({
                message: 'Неверный логин или пароль'
            });
        }

        const token = await createSession(user.id);

        res.json({
            success: true,
            token,
            user: publicUser(user)
        });
    } catch (err) {
        console.error('LOGIN:', err);

        res.status(500).json({
            message: 'Ошибка входа'
        });
    }
});

// ==========================================
// 12. ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ
// ==========================================

app.get('/api/auth/me', authMiddleware, (req, res) => {
    res.json({
        user: publicUser(req.user)
    });
});

// ==========================================
// 13. ИЗМЕНЕНИЕ ПРОФИЛЯ
// ==========================================

app.patch('/api/profile', authMiddleware, async (req, res) => {
    try {
        const body = req.body || {};

        const username = String(
            body.username ?? req.user.username
        ).trim();

        const avatar = body.avatar ?? req.user.avatar;
        const cover = body.cover ?? req.user.cover;

        if (!validUsername(username)) {
            return res.status(400).json({
                message: 'Некорректное имя пользователя'
            });
        }

        if (
            typeof avatar !== 'string' ||
            typeof cover !== 'string' ||
            avatar.length > 7 * 1024 * 1024 ||
            cover.length > 7 * 1024 * 1024
        ) {
            return res.status(400).json({
                message: 'Некорректное изображение'
            });
        }

        const collision = await dbGet(
            `SELECT id FROM users
             WHERE username_norm = ? AND id != ?`,
            [normalizeUsername(username), req.user.id]
        );

        if (collision) {
            return res.status(409).json({
                message: 'Это имя уже занято'
            });
        }

        await dbRun(
            `UPDATE users
             SET username = ?, username_norm = ?, avatar = ?, cover = ?
             WHERE id = ?`,
            [
                username,
                normalizeUsername(username),
                avatar,
                cover,
                req.user.id
            ]
        );

        const user = await dbGet(
            'SELECT * FROM users WHERE id = ?',
            [req.user.id]
        );

        res.json({
            success: true,
            user: publicUser(user)
        });
    } catch (err) {
        console.error('PROFILE:', err);

        res.status(500).json({
            message: 'Не удалось сохранить профиль'
        });
    }
});

// ==========================================
// 14. ВОССТАНОВЛЕНИЕ ПАРОЛЯ: ЗАПРОС КОДА
// ==========================================

app.post('/api/auth/password/request-code', async (req, res) => {
    const body = req.body || {};
    const email = normalizeEmail(body.email);

    const genericResponse = {
        success: true,
        message: 'Если аккаунт существует, код будет отправлен на почту'
    };

    try {
        if (!validEmail(email)) {
            return res.json(genericResponse);
        }

        if (!CODE_PEPPER || !mailer) {
            return res.status(503).json({
                message: 'Почтовый сервис пока не настроен'
            });
        }

        const user = await dbGet(
            'SELECT id FROM users WHERE email_norm = ?',
            [email]
        );

        if (!user) {
            return res.json(genericResponse);
        }

        const previous = await dbGet(
            `SELECT created_at FROM auth_codes
             WHERE purpose = 'reset' AND email_norm = ?
             ORDER BY id DESC LIMIT 1`,
            [email]
        );

        if (previous && Date.now() - previous.created_at < 60000) {
            return res.json(genericResponse);
        }

        const code = String(crypto.randomInt(100000, 1000000));
        const now = Date.now();

        await dbRun(
            `DELETE FROM auth_codes
             WHERE purpose = 'reset' AND email_norm = ?`,
            [email]
        );

        await dbRun(
            `INSERT INTO auth_codes
             (purpose, email_norm, code_hash, expires_at, attempts, created_at)
             VALUES ('reset', ?, ?, ?, 0, ?)`,
            [
                email,
                hashCode(email, 'reset', code),
                now + 10 * 60 * 1000,
                now
            ]
        );

        try {
            await sendVerificationCode(email, code, 'reset');
        } catch (mailError) {
            await dbRun(
                `DELETE FROM auth_codes
                 WHERE purpose = 'reset' AND email_norm = ?`,
                [email]
            );

            throw mailError;
        }

        res.json(genericResponse);
    } catch (err) {
        console.error('RESET REQUEST:', err);

        res.status(500).json({
            message: 'Ошибка отправки письма'
        });
    }
});

// ==========================================
// 15. ВОССТАНОВЛЕНИЕ ПАРОЛЯ: СБРОС
// ==========================================

app.post('/api/auth/password/reset', async (req, res) => {
    try {
        const body = req.body || {};

        const email = normalizeEmail(body.email);
        const code = String(body.code || '').trim();
        const newPassword = String(body.newPassword || '');

        if (!validEmail(email) || !/^\d{6}$/.test(code)) {
            return res.status(400).json({
                message: 'Неверные данные'
            });
        }

        if (newPassword.length < 8 || newPassword.length > 128) {
            return res.status(400).json({
                message: 'Пароль должен содержать от 8 до 128 символов'
            });
        }

        const pending = await dbGet(
            `SELECT * FROM auth_codes
             WHERE purpose = 'reset' AND email_norm = ?
             ORDER BY id DESC LIMIT 1`,
            [email]
        );

        if (!pending || pending.expires_at < Date.now()) {
            return res.status(400).json({
                message: 'Код истёк или не найден'
            });
        }

        if (pending.attempts >= 5) {
            return res.status(429).json({
                message: 'Слишком много попыток. Запроси новый код'
            });
        }

        if (!safeEqual(
            pending.code_hash,
            hashCode(email, 'reset', code)
        )) {
            await dbRun(
                'UPDATE auth_codes SET attempts = attempts + 1 WHERE id = ?',
                [pending.id]
            );

            return res.status(400).json({
                message: 'Неверный код'
            });
        }

        const user = await dbGet(
            'SELECT id FROM users WHERE email_norm = ?',
            [email]
        );

        if (!user) {
            return res.status(400).json({
                message: 'Аккаунт не найден'
            });
        }

        const passwordHash = await argon2.hash(newPassword, {
            type: argon2.argon2id,
            memoryCost: 19456,
            timeCost: 2,
            parallelism: 1
        });

        await dbRun(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            [passwordHash, user.id]
        );

        await dbRun(
            'DELETE FROM sessions WHERE user_id = ?',
            [user.id]
        );

        await dbRun(
            'DELETE FROM auth_codes WHERE id = ?',
            [pending.id]
        );

        res.json({
            success: true,
            message: 'Пароль успешно изменён'
        });
    } catch (err) {
        console.error('PASSWORD RESET:', err);

        res.status(500).json({
            message: 'Ошибка восстановления пароля'
        });
    }
});

// ==========================================
// 16. ВЫХОД
// ==========================================

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
    try {
        await dbRun(
            'DELETE FROM sessions WHERE id = ?',
            [req.sessionId]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('LOGOUT:', err);

        res.status(500).json({
            message: 'Ошибка выхода'
        });
    }
});

// ==========================================
// 17. ВЫДАЧА PREMIUM KEY
// ==========================================

app.post('/api/get-key', async (req, res) => {
    try {
        const body = req.body || {};
        const duration = body.duration;

        let foundKey = null;

        for (const [key, data] of Object.entries(secretKeys)) {
            if (
                data.duration === duration &&
                !data.gived &&
                !data.used
            ) {
                foundKey = key;
                break;
            }
        }

        if (!foundKey) {
            return res.status(404).json({
                success: false,
                message: 'Нет свободных ключей для этого тарифа'
            });
        }

        await dbRun(
            `INSERT OR REPLACE INTO key_status (key_id, gived)
             VALUES (?, 1)`,
            [foundKey]
        );

        secretKeys[foundKey].gived = true;

        console.log(`Ключ ${foundKey} выдан`);

        res.json({
            success: true,
            key: foundKey
        });
    } catch (err) {
        console.error('GET KEY:', err);

        res.status(500).json({
            success: false,
            message: 'Ошибка базы данных'
        });
    }
});

// ==========================================
// 18. АКТИВАЦИЯ PREMIUM KEY
// ==========================================

app.post('/api/activate', (req, res) => {
    try {
        const body = req.body || {};

        const { key, deviceId } = body;

        if (
            typeof key !== 'string' ||
            typeof deviceId !== 'string' ||
            !key.trim() ||
            !deviceId.trim()
        ) {
            return res.status(400).json({
                success: false,
                message: 'Не переданы данные'
            });
        }

        const cleanKey = key.trim().toUpperCase();
        const cleanDeviceId = deviceId.trim();

        const keyConfig = secretKeys[cleanKey];

        if (!keyConfig) {
            return res.status(404).json({
                success: false,
                message: 'invalid_key'
            });
        }

        db.get(
            `SELECT * FROM activations
             WHERE key_id = ? AND device_id = ?`,
            [cleanKey, cleanDeviceId],
            (err, row) => {
                if (err) {
                    console.error('ACTIVATE SELECT:', err);

                    return res.status(500).json({
                        success: false,
                        message: 'db_error'
                    });
                }

                if (row) {
                    return res.status(400).json({
                        success: false,
                        message: 'already_activated_here'
                    });
                }

                db.get(
                    `SELECT COUNT(*) AS count
                     FROM activations WHERE key_id = ?`,
                    [cleanKey],
                    (err, result) => {
                        if (err) {
                            console.error('ACTIVATE COUNT:', err);

                            return res.status(500).json({
                                success: false,
                                message: 'db_error'
                            });
                        }

                        if (
                            result.count >=
                            Number(keyConfig.max_activations || 1)
                        ) {
                            return res.status(400).json({
                                success: false,
                                message: 'exhausted'
                            });
                        }

                        const now = Date.now();
                        let ms = 30 * 24 * 60 * 60 * 1000;

                        if (keyConfig.duration === '7_days') {
                            ms = 7 * 24 * 60 * 60 * 1000;
                        }

                        if (keyConfig.duration === '3_months') {
                            ms = 90 * 24 * 60 * 60 * 1000;
                        }

                        if (keyConfig.duration === '6_months') {
                            ms = 180 * 24 * 60 * 60 * 1000;
                        }

                        if (keyConfig.duration === 'forever') {
                            ms = 3650 * 24 * 60 * 60 * 1000;
                        }

                        const expires = now + ms;

                        db.run(
                            `INSERT INTO activations
                             (key_id, device_id, expires)
                             VALUES (?, ?, ?)`,
                            [cleanKey, cleanDeviceId, expires],
                            err => {
                                if (err) {
                                    console.error('ACTIVATE INSERT:', err);

                                    return res.status(500).json({
                                        success: false,
                                        message: 'db_error'
                                    });
                                }

                                if (
                                    result.count + 1 >=
                                    Number(keyConfig.max_activations || 1)
                                ) {
                                    secretKeys[cleanKey].used = true;
                                }

                                res.json({
                                    success: true,
                                    message: 'premium_activated',
                                    duration: keyConfig.duration,
                                    expires
                                });
                            }
                        );
                    }
                );
            }
        );
    } catch (err) {
        console.error('ACTIVATE:', err);

        res.status(500).json({
            success: false,
            message: 'server_error'
        });
    }
});

// ==========================================
// 19. ПРОВЕРКА СТАТУСА
// ==========================================

app.get('/api/status', (req, res) => {
    const deviceId = String(req.query.deviceId || '').trim();

    if (!deviceId) {
        return res.status(400).json({
            active: false
        });
    }

    db.get(
        `SELECT * FROM activations
         WHERE device_id = ?
         ORDER BY expires DESC LIMIT 1`,
        [deviceId],
        (err, row) => {
            if (err) {
                console.error('STATUS:', err);

                return res.status(500).json({
                    active: false
                });
            }

            if (row && Date.now() < row.expires) {
                const keyConfig = secretKeys[row.key_id] || {};

                return res.json({
                    active: true,
                    expires: row.expires,
                    duration: keyConfig.duration || '1_month'
                });
            }

            res.json({
                active: false
            });
        }
    );
});

// ==========================================
// 20. HEALTH CHECK
// ==========================================

app.get('/', (req, res) => {
    res.send('ProxyGem API работает ✅');
});

app.get('/api/health', async (req, res) => {
    try {
        await dbGet('SELECT 1');

        res.json({
            success: true,
            server: true,
            database: true,
            mailConfigured: Boolean(mailer),
            time: new Date().toISOString()
        });
    } catch (err) {
        console.error('HEALTH:', err);

        res.status(500).json({
            success: false,
            server: true,
            database: false
        });
    }
});

// ==========================================
// 21. ОБРАБОТКА ОШИБОК
// ==========================================

app.use((err, req, res, next) => {
    console.error('UNHANDLED ERROR:', err);

    if (res.headersSent) {
        return next(err);
    }

    res.status(500).json({
        success: false,
        message: 'Внутренняя ошибка сервера'
    });
});

// ==========================================
// 22. ЗАПУСК ПОСЛЕ SQLITE
// ==========================================

initializeDatabase()
    .then(() => {
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`ProxyGem API запущен на порту ${PORT}`);
            console.log('База данных готова');
            console.log('SMTP настроен:', Boolean(mailer));
        });
    })
    .catch(err => {
        console.error('Не удалось инициализировать базу:', err);
        process.exit(1);
    });
