const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const axios = require('axios');
const querystring = require('querystring');
const { jwtVerify, createRemoteJWKSet } = require('jose');

const app = express();

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '2mb' }));
app.get('/health', (req, res) => res.status(200).send('OK'));

const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '') || null;
const SITE_URL = (process.env.SITE_URL || '').replace(/\/+$/, '') || null;

const ALLOWED_RETURN_HOSTS = [
    'proxygem.github.io',
    'proxygem-api.onrender.com',
    'localhost',
    '127.0.0.1'
];

function normalizeReturnUrl(input) {
    if (!input) return SITE_URL || '/';
    let raw = String(input).trim();
    if (raw.startsWith('/')) {
        if (SITE_URL) return SITE_URL + raw;
        return raw;
    }
    try {
        const u = new URL(raw);
        if (!ALLOWED_RETURN_HOSTS.includes(u.hostname)) {
            console.warn('⚠️ return URL не в whitelist:', u.hostname, '→ fallback:', SITE_URL || '/');
            return SITE_URL || '/';
        }
        return u.toString();
    } catch (e) {
        console.warn('⚠️ Невалидный return URL:', raw, '→ fallback:', SITE_URL || '/');
        return SITE_URL || '/';
    }
}

function serverOrigin(req) {
    if (PUBLIC_URL) return PUBLIC_URL;
    return 'https://' + req.get('host');
}

// ==========================================
// 1. КЛЮЧИ
// ==========================================
let secretKeys = {};

function normalizeKeyConfig(cfg) {
    return {
        duration: cfg.duration || '1_month',
        max_activations: Number(cfg.max_activations) || 1,
        used: Boolean(cfg.used),
        gived: Boolean(cfg.gived)
    };
}

function loadKeys() {
    try {
        let rawData = null;
        const filePath = path.join(__dirname, 'keys.json');
        if (fs.existsSync(filePath)) {
            rawData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            console.log('📁 Ключи загружены из keys.json');
        } else if (process.env.premium_keys) {
            rawData = JSON.parse(process.env.premium_keys);
            console.log('🌍 Ключи загружены из env premium_keys');
        } else {
            throw new Error('Нет ни keys.json, ни premium_keys');
        }

        const keysArray = Array.isArray(rawData) ? rawData : rawData.codes;
        if (Array.isArray(keysArray)) {
            keysArray.forEach(k => {
                if (!k || !k.id) return;
                secretKeys[k.id] = normalizeKeyConfig(k);
            });
        } else if (rawData && typeof rawData === 'object') {
            for (const [id, cfg] of Object.entries(rawData)) {
                secretKeys[id] = normalizeKeyConfig(cfg || {});
            }
        } else {
            throw new Error('Неизвестный формат ключей');
        }
        console.log(`✅ Загружено ${Object.keys(secretKeys).length} ключей`);
        if (secretKeys['PROXYGEM']) console.log('🎁 Триал PROXYGEM загружен');
        else console.warn('⚠️ Ключ PROXYGEM не найден');
    } catch (e) {
        console.error('❌ Ошибка загрузки ключей:', e.message);
        secretKeys = {
            'TEST-KEY-123': { duration: '1_month', max_activations: 1, used: false, gived: false },
            'PROXYGEM':     { duration: '7_days',  max_activations: 1, used: false, gived: false }
        };
    }
}
loadKeys();

// ==========================================
// 2. БД
// ==========================================
function ensureDir(filePath) {
    const dir = path.dirname(filePath);
    try { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); } catch (e) {}
}
function pickDbPath() {
    const candidates = [process.env.DB_PATH, '/tmp/database.sqlite', path.join(__dirname, 'database.sqlite')].filter(Boolean);
    for (const p of candidates) {
        try { ensureDir(p); fs.closeSync(fs.openSync(p, 'a')); return p; } catch (e) {}
    }
    return ':memory:';
}
const DB_PATH = pickDbPath();
console.log(`📦 БД: ${DB_PATH}`);

const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error('❌ Ошибка БД:', err.message);
    else console.log('✅ SQLite подключена');
});
db.run('PRAGMA journal_mode = WAL;');
db.run('PRAGMA busy_timeout = 5000;');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS activations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, key_id TEXT, device_id TEXT, expires INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS key_status (key_id TEXT PRIMARY KEY, gived INTEGER DEFAULT 0)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_activations_key ON activations(key_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_activations_device ON activations(device_id)`);
});

db.all(`SELECT key_id FROM key_status WHERE gived = 1`, (err, rows) => {
    if (err || !rows) return;
    let restored = 0;
    rows.forEach(r => { if (secretKeys[r.key_id]) { secretKeys[r.key_id].gived = true; restored++; } });
    console.log(`✅ gived восстановлено: ${restored}`);
});

db.all(`SELECT key_id, COUNT(*) as cnt FROM activations GROUP BY key_id`, (err, rows) => {
    if (err || !rows) return;
    let restored = 0;
    rows.forEach(r => {
        if (r.key_id === 'PROXYGEM') return;
        const cfg = secretKeys[r.key_id];
        if (cfg && r.cnt >= cfg.max_activations) { cfg.used = true; restored++; }
    });
    console.log(`✅ used восстановлено: ${restored}`);
});

// ==========================================
// 3. API ДЛЯ САЙТА
// ==========================================
app.post('/api/get-key', (req, res) => {
    const { duration } = req.body || {};
    if (!duration) return res.status(400).json({ success: false, message: 'Не указан duration' });
    let foundKey = null;
    for (const [key, data] of Object.entries(secretKeys)) {
        if (key === 'PROXYGEM') continue;
        if (data.duration === duration && !data.gived && !data.used) { foundKey = key; break; }
    }
    if (!foundKey) return res.status(404).json({ success: false, message: 'Нет свободных ключей' });
    db.run(`INSERT OR REPLACE INTO key_status (key_id, gived) VALUES (?, 1)`, [foundKey], (err) => {
        if (err) return res.status(500).json({ success: false, message: 'db_error' });
        secretKeys[foundKey].gived = true;
        return res.json({ success: true, key: foundKey });
    });
});

// ==========================================
// 4. API ДЛЯ ПРОГРАММЫ
// ==========================================
app.post('/api/activate', (req, res) => {
    const { key, deviceId } = req.body || {};
    if (!key || !deviceId) return res.status(400).json({ success: false, message: 'Не переданы данные' });
    const cleanKey = String(key).trim().toUpperCase();
    const keyConfig = secretKeys[cleanKey];
    if (!keyConfig) return res.status(404).json({ success: false, message: 'invalid_key' });

    if (cleanKey === 'PROXYGEM') {
        db.get(`SELECT * FROM activations WHERE key_id = ? AND device_id = ?`, [cleanKey, deviceId], (err, row) => {
            if (err) return res.status(500).json({ success: false, message: 'db_error' });
            if (row) return res.status(400).json({ success: false, message: 'trial_already_used' });
            const expires = Date.now() + 7 * 24 * 60 * 60 * 1000;
            db.run(`INSERT INTO activations (key_id, device_id, expires) VALUES (?, ?, ?)`, [cleanKey, deviceId, expires], (err) => {
                if (err) return res.status(500).json({ success: false, message: 'db_error' });
                return res.json({ success: true, message: 'trial_activated', duration: '7_days', expires });
            });
        });
        return;
    }

    if (keyConfig.used && keyConfig.max_activations === 1)
        return res.status(400).json({ success: false, message: 'exhausted' });

    db.get(`SELECT * FROM activations WHERE key_id = ? AND device_id = ?`, [cleanKey, deviceId], (err, row) => {
        if (err) return res.status(500).json({ success: false, message: 'db_error' });
        if (row) return res.status(400).json({ success: false, message: 'already_activated_here' });
        db.get(`SELECT COUNT(*) as count FROM activations WHERE key_id = ?`, [cleanKey], (err, result) => {
            if (err) return res.status(500).json({ success: false, message: 'db_error' });
            if (result.count >= keyConfig.max_activations) {
                secretKeys[cleanKey].used = true;
                return res.status(400).json({ success: false, message: 'exhausted' });
            }
            const now = Date.now();
            let ms = 30 * 24 * 60 * 60 * 1000;
            if (keyConfig.duration === '7_days') ms = 7 * 24 * 60 * 60 * 1000;
            if (keyConfig.duration === '3_months') ms = 90 * 24 * 60 * 60 * 1000;
            if (keyConfig.duration === '6_months') ms = 180 * 24 * 60 * 60 * 1000;
            if (keyConfig.duration === 'forever') ms = 3650 * 24 * 60 * 60 * 1000;
            const expires = now + ms;
            db.run(`INSERT INTO activations (key_id, device_id, expires) VALUES (?, ?, ?)`, [cleanKey, deviceId, expires], (err) => {
                if (err) return res.status(500).json({ success: false, message: 'db_error' });
                if (result.count + 1 >= keyConfig.max_activations) secretKeys[cleanKey].used = true;
                return res.json({ success: true, message: 'premium_activated', duration: keyConfig.duration, expires });
            });
        });
    });
});

app.get('/api/status', (req, res) => {
    const { deviceId } = req.query;
    if (!deviceId) return res.status(400).json({ active: false });
    db.get(`SELECT * FROM activations WHERE device_id = ? ORDER BY expires DESC LIMIT 1`, [deviceId], (err, row) => {
        if (err) return res.status(500).json({ active: false });
        if (row && Date.now() < row.expires) {
            const keyConfig = secretKeys[row.key_id] || {};
            return res.json({ active: true, expires: row.expires, duration: keyConfig.duration || '1_month' });
        }
        return res.json({ active: false });
    });
});

// ==========================================
// 6. АУТЕНТИФИКАЦИЯ И ПРОФИЛЬ
// ==========================================
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT UNIQUE NOT NULL,
        password_hash TEXT, nick TEXT, avatar TEXT, banner TEXT,
        created_at INTEGER NOT NULL, last_login INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`);
    db.run(`CREATE TABLE IF NOT EXISTS user_providers (
        user_id INTEGER NOT NULL, provider TEXT NOT NULL, provider_id TEXT,
        UNIQUE(user_id, provider))`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
    db.run(`CREATE TABLE IF NOT EXISTS tg_pkce (
        state TEXT PRIMARY KEY, verifier TEXT NOT NULL,
        return_url TEXT NOT NULL, expires_at INTEGER NOT NULL)`);
});

function genToken() { return crypto.randomBytes(32).toString('hex'); }
function authUser(req) {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return Promise.resolve(null);
    return new Promise((resolve) => {
        db.get(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                WHERE s.token = ? AND s.expires_at > ?`, [token, Date.now()],
            (err, row) => resolve(err ? null : row));
    });
}
async function requireAuth(req, res, next) {
    const u = await authUser(req);
    if (!u) return res.status(401).json({ message: 'Не авторизован' });
    req.user = u; next();
}
function publicUser(u, extra = {}) {
    return {
        id: u.id, login: u.login, nick: u.nick || u.login,
        avatar: u.avatar || null, banner: u.banner || null,
        regDate: new Date(u.created_at).toISOString(),
        lastLogin: u.last_login ? new Date(u.last_login).toISOString() : null,
        telegram: false, google: false, ...extra
    };
}
function getUserProviders(userId) {
    return new Promise((resolve) => {
        db.all(`SELECT provider FROM user_providers WHERE user_id = ?`, [userId], (err, rows) => {
            if (err || !rows) return resolve([]);
            resolve(rows.map(r => r.provider));
        });
    });
}

app.post('/auth/register', async (req, res) => {
    try {
        const { login, password } = req.body || {};
        const cleanLogin = String(login || '').trim();
        const pass = String(password || '');
        if (!/^[A-Za-z0-9_.\-]{3,24}$/.test(cleanLogin))
            return res.status(400).json({ message: 'Логин: 3–24 символа' });
        if (pass.length < 8 || pass.length > 72)
            return res.status(400).json({ message: 'Пароль: 8–72 символа' });

        db.get(`SELECT id FROM users WHERE login = ? COLLATE NOCASE`, [cleanLogin], async (err, row) => {
            if (err) return res.status(500).json({ message: 'db_error' });
            if (row) return res.status(409).json({ message: 'Логин занят' });
            const hash = await bcrypt.hash(pass, 10);
            const now = Date.now();
            db.run(`INSERT INTO users (login, password_hash, nick, created_at, last_login) VALUES (?, ?, ?, ?, ?)`,
                [cleanLogin, hash, cleanLogin, now, now], function (err2) {
                    if (err2) {
                        if (String(err2.message).includes('UNIQUE')) return res.status(409).json({ message: 'Логин занят' });
                        return res.status(500).json({ message: 'db_error' });
                    }
                    const userId = this.lastID;
                    const token = genToken();
                    const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
                    db.run(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
                        [token, userId, Date.now(), expires], (err3) => {
                            if (err3) return res.status(500).json({ message: 'session_error' });
                            db.get(`SELECT * FROM users WHERE id = ?`, [userId], (e, u) => {
                                res.json({ token, user: publicUser(u) });
                            });
                        });
                });
        });
    } catch (e) { res.status(500).json({ message: 'server_error' }); }
});

app.post('/auth/login', (req, res) => {
    const { login, password } = req.body || {};
    const cleanLogin = String(login || '').trim();
    const pass = String(password || '');
    if (!cleanLogin || !pass) return res.status(400).json({ message: 'Заполните поля' });
    db.get(`SELECT * FROM users WHERE login = ? COLLATE NOCASE`, [cleanLogin], async (err, u) => {
        if (err) return res.status(500).json({ message: 'db_error' });
        if (!u || !u.password_hash) return res.status(401).json({ message: 'Неверный логин или пароль' });
        const ok = await bcrypt.compare(pass, u.password_hash);
        if (!ok) return res.status(401).json({ message: 'Неверный логин или пароль' });
        const token = genToken();
        const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
        db.run(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
            [token, u.id, Date.now(), expires], (e2) => {
                if (e2) return res.status(500).json({ message: 'session_error' });
                db.run(`UPDATE users SET last_login = ? WHERE id = ?`, [Date.now(), u.id]);
                res.json({ token, user: publicUser(u) });
            });
    });
});

app.get('/auth/me', async (req, res) => {
    const u = await authUser(req);
    if (!u) return res.status(401).json({ message: 'Не авторизован' });
    const providers = await getUserProviders(u.id);
    res.json({ user: publicUser(u, {
        telegram: providers.includes('telegram'),
        google: providers.includes('google')
    }) });
});

app.post('/auth/logout', (req, res) => {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.json({ ok: true });
    db.run(`DELETE FROM sessions WHERE token = ?`, [token], () => res.json({ ok: true }));
});

app.patch('/profile', requireAuth, (req, res) => {
    const allowed = ['nick', 'avatar', 'banner'];
    const updates = [], values = [];
    for (const k of allowed) {
        if (k in (req.body || {})) { updates.push(`${k} = ?`); values.push(req.body[k]); }
    }
    if (!updates.length) return res.json({ user: publicUser(req.user) });
    values.push(req.user.id);
    db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, values, (err) => {
        if (err) return res.status(500).json({ message: 'db_error' });
        db.get(`SELECT * FROM users WHERE id = ?`, [req.user.id], async (e, u) => {
            const providers = await getUserProviders(u.id);
            res.json({ user: publicUser(u, {
                telegram: providers.includes('telegram'),
                google: providers.includes('google')
            }) });
        });
    });
});

app.post('/profile/unlink', requireAuth, (req, res) => {
    const provider = (req.body || {}).provider;
    if (!['telegram', 'google'].includes(provider))
        return res.status(400).json({ message: 'Неверный провайдер' });
    getUserProviders(req.user.id).then(providers => {
        const others = providers.filter(p => p !== provider);
        const hasPassword = !!req.user.password_hash;
        if (others.length === 0 && !hasPassword)
            return res.status(400).json({ message: 'Нельзя отвязать единственный способ' });
        db.run(`DELETE FROM user_providers WHERE user_id = ? AND provider = ?`,
            [req.user.id, provider], (err) => {
                if (err) return res.status(500).json({ message: 'db_error' });
                res.json({ ok: true });
            });
    });
});

const uploadDir = path.join(__dirname, 'uploads');
try { if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true }); } catch (e) {}
app.use('/uploads', express.static(uploadDir));

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, uploadDir),
        filename: (req, file, cb) => {
            const ext = (file.originalname.split('.').pop() || 'png').toLowerCase();
            cb(null, Date.now() + '_' + crypto.randomBytes(6).toString('hex') + '.' + ext);
        }
    }),
    limits: { fileSize: 8 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ok = ['image/png', 'image/jpeg', 'image/webp'];
        if (!ok.includes(file.mimetype)) return cb(new Error('bad_type'));
        cb(null, true);
    }
});

app.post('/profile/upload', requireAuth, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'Файл не принят' });
    const kind = req.body.kind === 'avatar' ? 'avatar' : 'banner';
    const url = '/uploads/' + req.file.filename;
    db.run(`UPDATE users SET ${kind} = ? WHERE id = ?`, [url, req.user.id], (err) => {
        if (err) return res.status(500).json({ message: 'db_error' });
        res.json({ url, kind });
    });
});

// ==========================================
// TELEGRAM — OIDC + PKCE
// ==========================================
const TG_ISSUER = 'https://oauth.telegram.org';
const TG_JWKS = createRemoteJWKSet(new URL(TG_ISSUER + '/.well-known/jwks.json'));

function base64url(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

app.get('/auth/telegram/start', (req, res) => {
    const clientId = process.env.TG_CLIENT_ID;
    if (!clientId) return res.status(500).send('TG_CLIENT_ID not set');

    const returnUrl = normalizeReturnUrl(req.query.redirect);
    const origin = serverOrigin(req);
    const redirectUri = `${origin}/auth/telegram/callback`;

    const verifier = base64url(crypto.randomBytes(32));
    const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
    const state = crypto.randomBytes(16).toString('hex');

    db.run(`INSERT OR REPLACE INTO tg_pkce (state, verifier, return_url, expires_at) VALUES (?, ?, ?, ?)`,
        [state, verifier, returnUrl, Date.now() + 10 * 60 * 1000], (err) => {
            if (err) { console.error('tg_pkce:', err.message); return res.status(500).send('state_store_error'); }
            db.run(`DELETE FROM tg_pkce WHERE expires_at < ?`, [Date.now()]);
            const params = querystring.stringify({
                client_id: clientId, redirect_uri: redirectUri,
                response_type: 'code', scope: 'openid profile',
                state, code_challenge: challenge, code_challenge_method: 'S256'
            });
            console.log('🔹 TG start → return:', returnUrl);
            res.redirect(`${TG_ISSUER}/auth?${params}`);
        });
});

app.get('/auth/telegram/callback', async (req, res) => {
    try {
        const { code, state, error } = req.query;
        const fallback = SITE_URL || '/';
        const sep = fallback.includes('?') ? '&' : '?';

        if (error) return res.redirect(`${fallback}${sep}error=${encodeURIComponent(error)}&provider=telegram`);
        if (!code || !state) return res.redirect(`${fallback}${sep}error=missing_code&provider=telegram`);

        const stored = await new Promise((resolve) => {
            db.get(`SELECT * FROM tg_pkce WHERE state = ? AND expires_at > ?`, [state, Date.now()],
                (err, row) => resolve(err ? null : row));
        });

        if (!stored) {
            console.warn('⚠️ TG state не найден:', state);
            return res.redirect(`${fallback}${sep}error=state_expired&provider=telegram`);
        }
        db.run(`DELETE FROM tg_pkce WHERE state = ?`, [state]);

        const clientId = process.env.TG_CLIENT_ID;
        const clientSecret = process.env.TG_CLIENT_SECRET;
        if (!clientId || !clientSecret) return res.status(500).send('Telegram OIDC not configured');

        const origin = serverOrigin(req);
        const redirectUri = `${origin}/auth/telegram/callback`;

        const body = new URLSearchParams({
            grant_type: 'authorization_code', code,
            redirect_uri: redirectUri, client_id: clientId,
            code_verifier: stored.verifier
        });

        const tokenRes = await axios.post(`${TG_ISSUER}/token`, body.toString(), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Authorization: 'Basic ' + Buffer.from(`${clientId}:${clientSecret}`).toString('base64')
            }
        });

        const { id_token } = tokenRes.data;
        if (!id_token) return res.redirect(`${fallback}${sep}error=no_id_token&provider=telegram`);

        const { payload } = await jwtVerify(id_token, TG_JWKS, {
            issuer: TG_ISSUER, audience: clientId
        });

        // FIX: ник = @username (или имя+фамилия), аватар = photo_url
        const providerId = String(payload.id || payload.sub);
        const username = payload.preferred_username || null;
        const displayNick = username
            ? (username.startsWith('@') ? username : '@' + username)
            : [payload.given_name, payload.family_name].filter(Boolean).join(' ') || (payload.name || 'tg_' + providerId);
        const login = (username || 'tg_' + providerId)
            .replace(/[^A-Za-z0-9_.\-]/g, '_').slice(0, 24) || ('tg_' + providerId);
        const avatar = payload.picture || null;

        db.get(`SELECT u.* FROM user_providers p JOIN users u ON u.id = p.user_id
                WHERE p.provider = 'telegram' AND p.provider_id = ?`, [providerId], (err, existing) => {
            if (err) return res.redirect(`${fallback}${sep}error=db_error&provider=telegram`);

            const finish = (user) => {
                const token = genToken();
                const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
                db.run(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
                    [token, user.id, Date.now(), expires], () => {
                        const target = stored.return_url || fallback;
                        const s = target.includes('?') ? '&' : '?';
                        console.log('🔹 TG finish →', target);
                        res.redirect(`${target}${s}token=${token}&provider=telegram`);
                    });
            };

            if (existing) {
                // обновляем ник/аватар из Telegram при каждом входе
                db.run(`UPDATE users SET nick = ?, avatar = ?, last_login = ? WHERE id = ?`,
                    [displayNick, avatar, Date.now(), existing.id], () => {
                        db.get(`SELECT * FROM users WHERE id = ?`, [existing.id], (e, u) => finish(u || existing));
                    });
                return;
            }

            const now = Date.now();
            const tryInsert = (attempt) => {
                const tryLogin = attempt === 0 ? login : (login.slice(0, 20) + '_' + Math.random().toString(36).slice(2, 6));
                db.run(`INSERT INTO users (login, nick, avatar, created_at, last_login) VALUES (?, ?, ?, ?, ?)`,
                    [tryLogin, displayNick, avatar, now, now], function (e2) {
                        if (e2) {
                            if (String(e2.message).includes('UNIQUE') && attempt < 3) return tryInsert(attempt + 1);
                            return res.redirect(`${fallback}${sep}error=db_error&provider=telegram`);
                        }
                        const userId = this.lastID;
                        db.run(`INSERT OR IGNORE INTO user_providers (user_id, provider, provider_id) VALUES (?, 'telegram', ?)`,
                            [userId, providerId]);
                        db.get(`SELECT * FROM users WHERE id = ?`, [userId], (e3, nu) => finish(nu));
                    });
            };
            tryInsert(0);
        });
    } catch (e) {
        console.error('telegram callback:', e.response ? e.response.data : e.message);
        const fallback = SITE_URL || '/';
        const sep = fallback.includes('?') ? '&' : '?';
        res.redirect(`${fallback}${sep}error=telegram_error&provider=telegram`);
    }
});

// ==========================================
// GOOGLE — только CLIENT_ID (implicit flow)
// FIX: state больше не содержит returnUrl — returnUrl уже в sessionStorage на сайте.
// Сервер всегда возвращает на SITE_URL.
// ==========================================
app.get('/auth/google/start', (req, res) => {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId) return res.status(500).send('GOOGLE_CLIENT_ID not set');

    const returnUrl = normalizeReturnUrl(req.query.redirect);
    const origin = serverOrigin(req);
    const redirectUri = `${origin}/auth/google/callback`;

    // FIX: state = случайный идентификатор (без URL внутри).
    // Возврат на сайт задан через SITE_URL.
    const state = crypto.randomBytes(16).toString('hex');

    // Сохраняем state → returnUrl в tg_pkce-подобной таблице (переиспользуем)
    db.run(`INSERT OR REPLACE INTO tg_pkce (state, verifier, return_url, expires_at) VALUES (?, ?, ?, ?)`,
        [state, 'google', returnUrl, Date.now() + 10 * 60 * 1000], (err) => {
            if (err) console.error('google state:', err.message);
            const params = querystring.stringify({
                client_id: clientId, redirect_uri: redirectUri,
                response_type: 'token', scope: 'openid email profile',
                include_granted_scopes: 'true', state, prompt: 'select_account'
            });
            console.log('🔹 GOOGLE start → return:', returnUrl);
            res.redirect('https://accounts.google.com/o/oauth2/v2/auth?' + params);
        });
});

app.get('/auth/google/callback', (req, res) => {
    const { state, error } = req.query;
    if (error) return res.status(400).send('google_error: ' + error);

    const safeState = JSON.stringify(String(state || ''));
    res.type('html').send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Google…</title>
<style>body{background:#040404;color:#fff;font-family:Inter,system-ui,sans-serif;
display:grid;place-items:center;height:100vh;margin:0}
.m{opacity:.7;font-size:14px}</style></head>
<body><div class="m">Завершаем вход через Google…</div>
<script>
(function(){
  var state = ${safeState};
  var hash = new URLSearchParams(location.hash.replace(/^#/, ''));
  var accessToken = hash.get('access_token');
  var err = hash.get('error');
  if(err){ location.replace(${JSON.stringify(SITE_URL || '/')} + '?error=' + encodeURIComponent(err) + '&provider=google'); return; }
  if(!accessToken){ location.replace(${JSON.stringify(SITE_URL || '/')} + '?error=no_token&provider=google'); return; }
  fetch('/auth/google/exchange', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ access_token: accessToken, state: state })
  })
  .then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
  .then(function(x){
    if(!x.ok){ location.replace(${JSON.stringify(SITE_URL || '/')} + '?error=' + encodeURIComponent(x.d&&x.d.message||'unknown') + '&provider=google'); return; }
    location.replace(x.d.redirect);
  })
  .catch(function(e){ location.replace(${JSON.stringify(SITE_URL || '/')} + '?error=' + encodeURIComponent(e.message) + '&provider=google'); });
})();
</script></body></html>`);
});

app.post('/auth/google/exchange', async (req, res) => {
    try {
        const { access_token, state } = req.body || {};
        if (!access_token) return res.status(400).json({ message: 'access_token required' });

        let info;
        try {
            const r = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
                headers: { Authorization: 'Bearer ' + access_token }
            });
            info = r.data;
        } catch (e) {
            return res.status(401).json({ message: 'Неверный Google токен' });
        }
        if (!info || !info.sub) return res.status(401).json({ message: 'Google userinfo пуст' });

        // FIX: returnUrl берём из БД по state (а не из state)
        let returnUrl = SITE_URL || '/';
        if (state) {
            const row = await new Promise((resolve) => {
                db.get(`SELECT * FROM tg_pkce WHERE state = ? AND expires_at > ?`,
                    [state, Date.now()], (err, r) => resolve(err ? null : r));
            });
            if (row) {
                returnUrl = normalizeReturnUrl(row.return_url);
                db.run(`DELETE FROM tg_pkce WHERE state = ?`, [state]);
            }
        }

        const providerId = String(info.sub);
        // FIX: ник = "Имя Фамилия", аватар = picture
        const displayNick = info.name || [info.given_name, info.family_name].filter(Boolean).join(' ') || info.email || ('g_' + providerId);
        const avatar = info.picture || null;

        db.get(`SELECT u.* FROM user_providers p JOIN users u ON u.id = p.user_id
                WHERE p.provider = 'google' AND p.provider_id = ?`, [providerId], (err, existing) => {
            if (err) return res.status(500).json({ message: 'db_error' });

            const finish = (user) => {
                const token = genToken();
                const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
                db.run(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
                    [token, user.id, Date.now(), expires], () => {
                        const sep = returnUrl.includes('?') ? '&' : '?';
                        res.json({ redirect: `${returnUrl}${sep}token=${token}&provider=google` });
                    });
            };

            if (existing) {
                db.run(`UPDATE users SET nick = ?, avatar = ?, last_login = ? WHERE id = ?`,
                    [displayNick, avatar, Date.now(), existing.id], () => {
                        db.get(`SELECT * FROM users WHERE id = ?`, [existing.id], (e, u) => finish(u || existing));
                    });
                return;
            }

            const loginBase = (info.email ? info.email.split('@')[0] : 'g_' + providerId)
                .replace(/[^A-Za-z0-9_.\-]/g, '_').slice(0, 24) || ('g_' + providerId);
            const now = Date.now();
            const tryInsert = (attempt) => {
                const login = attempt === 0 ? loginBase : (loginBase.slice(0, 20) + '_' + Math.random().toString(36).slice(2, 6));
                db.run(`INSERT INTO users (login, nick, avatar, created_at, last_login) VALUES (?, ?, ?, ?, ?)`,
                    [login, displayNick, avatar, now, now], function (e2) {
                        if (e2) {
                            if (String(e2.message).includes('UNIQUE') && attempt < 3) return tryInsert(attempt + 1);
                            return res.status(500).json({ message: 'db_error' });
                        }
                        const userId = this.lastID;
                        db.run(`INSERT OR IGNORE INTO user_providers (user_id, provider, provider_id) VALUES (?, 'google', ?)`,
                            [userId, providerId]);
                        db.get(`SELECT * FROM users WHERE id = ?`, [userId], (e3, nu) => finish(nu));
                    });
            };
            tryInsert(0);
        });
    } catch (e) {
        console.error('google exchange:', e.message);
        res.status(500).json({ message: 'server_error' });
    }
});

app.delete('/account', requireAuth, (req, res) => {
    const id = req.user.id;
    db.run(`DELETE FROM sessions WHERE user_id = ?`, [id]);
    db.run(`DELETE FROM user_providers WHERE user_id = ?`, [id]);
    db.run(`DELETE FROM users WHERE id = ?`, [id], (err) => {
        if (err) return res.status(500).json({ message: 'db_error' });
        res.json({ ok: true });
    });
});

// ==========================================
// 5. ЗАПУСК
// ==========================================
app.get('/', (req, res) => res.send('ProxyGem API работает ✅'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Сервер на порту ${PORT}`);
    console.log(`   PUBLIC_URL = ${PUBLIC_URL || '(auto)'}`);
    console.log(`   SITE_URL   = ${SITE_URL || '(not set)'}`);
});

process.on('SIGTERM', () => {
    console.log('SIGTERM');
    db.close(() => process.exit(0));
});
