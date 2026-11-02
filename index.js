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
const FALLBACK_SITE = SITE_URL || 'https://proxygem.github.io/site/profile';

const ALLOWED_RETURN_HOSTS = [
    'proxygem.github.io',
    'proxygem-api.onrender.com',
    'localhost',
    '127.0.0.1'
];

function normalizeReturnUrl(input) {
    if (!input) return FALLBACK_SITE;
    let raw = String(input).trim();
    if (raw.startsWith('/')) return FALLBACK_SITE.replace(/\/+$/, '') + raw;
    try {
        const u = new URL(raw);
        if (!ALLOWED_RETURN_HOSTS.includes(u.hostname)) return FALLBACK_SITE;
        return u.toString();
    } catch (e) { return FALLBACK_SITE; }
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
            console.log('📁 Ключи из keys.json');
        } else if (process.env.premium_keys) {
            rawData = JSON.parse(process.env.premium_keys);
            console.log('🌍 Ключи из env');
        } else { throw new Error('Нет ключей'); }
        const keysArray = Array.isArray(rawData) ? rawData : rawData.codes;
        if (Array.isArray(keysArray)) {
            keysArray.forEach(k => { if (k && k.id) secretKeys[k.id] = normalizeKeyConfig(k); });
        } else if (rawData && typeof rawData === 'object') {
            for (const [id, cfg] of Object.entries(rawData)) secretKeys[id] = normalizeKeyConfig(cfg || {});
        } else throw new Error('Формат');
        console.log(`✅ Ключей: ${Object.keys(secretKeys).length}`);
    } catch (e) {
        console.error('❌ Ключи:', e.message);
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
    if (err) console.error('❌ БД:', err.message);
    else console.log('✅ SQLite OK');
});
db.run('PRAGMA journal_mode = WAL;');
db.run('PRAGMA busy_timeout = 5000;');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS activations (
        id INTEGER PRIMARY KEY AUTOINCREMENT, key_id TEXT, device_id TEXT, expires INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS key_status (key_id TEXT PRIMARY KEY, gived INTEGER DEFAULT 0)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_activations_key ON activations(key_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_activations_device ON activations(device_id)`);

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
    db.run(`CREATE TABLE IF NOT EXISTS oauth_state (
        state TEXT PRIMARY KEY, verifier TEXT, return_url TEXT NOT NULL,
        provider TEXT NOT NULL, expires_at INTEGER NOT NULL)`);

    // Друзья
    db.run(`CREATE TABLE IF NOT EXISTS friendships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        friend_id INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        UNIQUE(user_id, friend_id))`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_friendships_user ON friendships(user_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_friendships_friend ON friendships(friend_id)`);

    // Сообщения
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        type TEXT NOT NULL DEFAULT 'text',
        content TEXT,
        url TEXT,
        filename TEXT,
        created_at INTEGER NOT NULL,
        read_at INTEGER)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_pair
            ON messages(sender_id, receiver_id, created_at)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_receiver
            ON messages(receiver_id, read_at)`);
});

// Миграция: user_id в activations
db.all(`PRAGMA table_info(activations)`, (err, cols) => {
    if (err || !cols) return;
    const hasUserId = cols.some(c => c.name === 'user_id');
    if (!hasUserId) {
        db.run(`ALTER TABLE activations ADD COLUMN user_id INTEGER`, (e) => {
            if (e) console.warn('ALTER activations:', e.message);
            else console.log('✅ user_id добавлен');
            db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_activations_user_key
                    ON activations(key_id, user_id)`);
        });
    } else {
        db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_activations_user_key
                ON activations(key_id, user_id)`);
    }
});

db.all(`SELECT key_id FROM key_status WHERE gived = 1`, (err, rows) => {
    if (err || !rows) return;
    let n = 0;
    rows.forEach(r => { if (secretKeys[r.key_id]) { secretKeys[r.key_id].gived = true; n++; } });
    console.log(`✅ gived: ${n}`);
});
db.all(`SELECT key_id, COUNT(*) as cnt FROM activations GROUP BY key_id`, (err, rows) => {
    if (err || !rows) return;
    let n = 0;
    rows.forEach(r => {
        if (r.key_id === 'PROXYGEM') return;
        const cfg = secretKeys[r.key_id];
        if (cfg && r.cnt >= cfg.max_activations) { cfg.used = true; n++; }
    });
    console.log(`✅ used: ${n}`);
});

// ==========================================
// 3. УТИЛИТЫ
// ==========================================
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
function createSession(userId) {
    return new Promise((resolve) => {
        const token = genToken();
        const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
        db.run(`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
            [token, userId, Date.now(), expires], (err) => resolve(err ? null : token));
    });
}
function areFriends(a, b) {
    return new Promise((resolve) => {
        db.get(`SELECT id FROM friendships
                WHERE status = 'accepted' AND (
                    (user_id = ? AND friend_id = ?) OR
                    (user_id = ? AND friend_id = ?)
                ) LIMIT 1`,
            [a, b, b, a], (err, row) => resolve(!err && !!row));
    });
}
function publicFriend(u) {
    return { id: u.id, login: u.login, nick: u.nick || u.login, avatar: u.avatar || null };
}
function redirectToSite(res, siteUrl, token, provider) {
    const sep = siteUrl.includes('?') ? '&' : '?';
    const url = `${siteUrl}${sep}token=${encodeURIComponent(token)}&provider=${encodeURIComponent(provider)}`;
    console.log('🔹 REDIRECT →', url);
    res.redirect(url);
}
function redirectToSiteError(res, siteUrl, code) {
    const sep = siteUrl.includes('?') ? '&' : '?';
    const url = `${siteUrl}${sep}error=${encodeURIComponent(code)}`;
    console.log('🔹 REDIRECT ERROR →', url);
    res.redirect(url);
}

// ==========================================
// 4. ЗАГРУЗКА ФАЙЛОВ
// ==========================================
const uploadDir = path.join(__dirname, 'uploads');
try { if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true }); } catch (e) {}
app.use('/uploads', express.static(uploadDir));

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => cb(null, uploadDir),
        filename: (req, file, cb) => {
            const ext = (file.originalname.split('.').pop() || 'bin').toLowerCase();
            cb(null, Date.now() + '_' + crypto.randomBytes(6).toString('hex') + '.' + ext);
        }
    }),
    limits: { fileSize: 25 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const ok = [
            'image/png', 'image/jpeg', 'image/webp',
            'audio/mpeg', 'audio/mp3', 'audio/ogg', 'audio/wav',
            'audio/webm', 'audio/mp4', 'audio/x-m4a', 'audio/aac'
        ];
        if (!ok.includes(file.mimetype)) return cb(new Error('bad_type'));
        cb(null, true);
    }
});

// ==========================================
// 5. КЛЮЧИ — API
// ==========================================
app.post('/api/get-key', requireAuth, (req, res) => {
    const { duration } = req.body || {};
    if (!duration) return res.status(400).json({ success: false, message: 'Не указан duration' });
    let foundKey = null;
    for (const [key, data] of Object.entries(secretKeys)) {
        if (key === 'PROXYGEM') continue;
        if (data.duration === duration && !data.gived && !data.used) { foundKey = key; break; }
    }
    if (!foundKey) return res.status(404).json({ success: false, message: 'Нет ключей' });
    db.run(`INSERT OR REPLACE INTO key_status (key_id, gived) VALUES (?, 1)`, [foundKey], (err) => {
        if (err) return res.status(500).json({ success: false, message: 'db_error' });
        secretKeys[foundKey].gived = true;
        return res.json({ success: true, key: foundKey });
    });
});

app.post('/api/activate', async (req, res) => {
    const user = await authUser(req);
    if (!user) return res.status(401).json({ success: false, message: 'auth_required' });
    const { key } = req.body || {};
    if (!key) return res.status(400).json({ success: false, message: 'no_key' });
    const cleanKey = String(key).trim().toUpperCase();
    const keyConfig = secretKeys[cleanKey];
    if (!keyConfig) return res.status(404).json({ success: false, message: 'invalid_key' });

    if (cleanKey === 'PROXYGEM') {
        db.get(`SELECT * FROM activations WHERE key_id = ? AND user_id = ?`,
            [cleanKey, user.id], (err, row) => {
                if (err) return res.status(500).json({ success: false, message: 'db_error' });
                if (row) return res.status(400).json({ success: false, message: 'trial_already_used' });
                const expires = Date.now() + 7 * 24 * 60 * 60 * 1000;
                db.run(`INSERT INTO activations (key_id, user_id, expires) VALUES (?, ?, ?)`,
                    [cleanKey, user.id, expires], (e) => {
                        if (e) return res.status(500).json({ success: false, message: 'db_error' });
                        return res.json({ success: true, message: 'trial_activated', duration: '7_days', expires });
                    });
            });
        return;
    }
    if (keyConfig.used && keyConfig.max_activations === 1)
        return res.status(400).json({ success: false, message: 'exhausted' });

    db.get(`SELECT * FROM activations WHERE key_id = ? AND user_id = ?`,
        [cleanKey, user.id], (err, row) => {
            if (err) return res.status(500).json({ success: false, message: 'db_error' });
            if (row) return res.status(400).json({ success: false, message: 'already_activated_by_you' });
            db.get(`SELECT COUNT(*) as count FROM activations WHERE key_id = ?`,
                [cleanKey], (err, result) => {
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
                    db.run(`INSERT INTO activations (key_id, user_id, expires) VALUES (?, ?, ?)`,
                        [cleanKey, user.id, expires], (e) => {
                            if (e) return res.status(500).json({ success: false, message: 'db_error' });
                            if (result.count + 1 >= keyConfig.max_activations) secretKeys[cleanKey].used = true;
                            return res.json({ success: true, message: 'premium_activated', duration: keyConfig.duration, expires });
                        });
                });
        });
});

app.get('/api/status', async (req, res) => {
    const user = await authUser(req);
    if (!user) return res.status(401).json({ active: false, message: 'auth_required' });
    db.get(`SELECT * FROM activations WHERE user_id = ? ORDER BY expires DESC LIMIT 1`,
        [user.id], (err, row) => {
            if (err) return res.status(500).json({ active: false });
            if (row && Date.now() < row.expires) {
                const keyConfig = secretKeys[row.key_id] || {};
                return res.json({ active: true, expires: row.expires, duration: keyConfig.duration || '1_month', key: row.key_id });
            }
            return res.json({ active: false });
        });
});

// ==========================================
// 6. АУТЕНТИФИКАЦИЯ
// ==========================================
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
                    createSession(userId).then(token => {
                        if (!token) return res.status(500).json({ message: 'session_error' });
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
        createSession(u.id).then(token => {
            if (!token) return res.status(500).json({ message: 'session_error' });
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
// 7. ДРУЗЬЯ
// ==========================================
app.get('/friends', requireAuth, (req, res) => {
    const uid = req.user.id;
    db.all(`SELECT f.status, f.user_id, f.friend_id,
                   u1.id AS u1_id, u1.login AS u1_login, u1.nick AS u1_nick, u1.avatar AS u1_avatar,
                   u2.id AS u2_id, u2.login AS u2_login, u2.nick AS u2_nick, u2.avatar AS u2_avatar
            FROM friendships f
            JOIN users u1 ON u1.id = f.user_id
            JOIN users u2 ON u2.id = f.friend_id
            WHERE f.user_id = ? OR f.friend_id = ?`,
        [uid, uid], (err, rows) => {
            if (err) return res.status(500).json({ message: 'db_error' });
            const friends = [], incoming = [], outgoing = [];
            for (const r of rows) {
                const other = r.user_id === uid
                    ? { id: r.u2_id, login: r.u2_login, nick: r.u2_nick, avatar: r.u2_avatar }
                    : { id: r.u1_id, login: r.u1_login, nick: r.u1_nick, avatar: r.u1_avatar };
                const item = { ...publicFriend(other), status: r.status };
                if (r.status === 'accepted') friends.push(item);
                else if (r.status === 'pending') {
                    if (r.user_id === uid) outgoing.push(item);
                    else incoming.push(item);
                }
            }
            res.json({ friends, incoming, outgoing, myId: uid });
        });
});

app.get('/friends/search', requireAuth, (req, res) => {
    const q = String(req.query.q || '').trim();
    if (!q) return res.json({ users: [] });
    const uid = req.user.id;
    db.all(`SELECT id, login, nick, avatar FROM users
            WHERE id != ? AND (login LIKE ? OR nick LIKE ?)
            LIMIT 20`,
        [uid, '%' + q + '%', '%' + q + '%'], (err, rows) => {
            if (err) return res.status(500).json({ message: 'db_error' });
            res.json({ users: rows.map(publicFriend) });
        });
});

app.post('/friends/request', requireAuth, (req, res) => {
    const uid = req.user.id;
    const targetId = parseInt(req.body && req.body.id, 10);
    if (!targetId || targetId === uid) return res.status(400).json({ message: 'Неверный ID' });
    db.get(`SELECT id, login, nick, avatar FROM users WHERE id = ?`, [targetId], (err, target) => {
        if (err) return res.status(500).json({ message: 'db_error' });
        if (!target) return res.status(404).json({ message: 'Пользователь не найден' });
        db.get(`SELECT * FROM friendships
                WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)`,
            [uid, targetId, targetId, uid], (err, existing) => {
                if (err) return res.status(500).json({ message: 'db_error' });
                if (existing) {
                    if (existing.status === 'accepted') return res.status(400).json({ message: 'Уже друзья' });
                    if (existing.status === 'pending') {
                        if (existing.user_id === uid) return res.status(400).json({ message: 'Заявка уже отправлена' });
                        return db.run(`UPDATE friendships SET status = 'accepted' WHERE id = ?`,
                            [existing.id], (e2) => {
                                if (e2) return res.status(500).json({ message: 'db_error' });
                                res.json({ ok: true, accepted: true, friend: publicFriend(target) });
                            });
                    }
                    return db.run(`UPDATE friendships SET status = 'pending', user_id = ?, friend_id = ?, created_at = ? WHERE id = ?`,
                        [uid, targetId, Date.now(), existing.id], (e3) => {
                            if (e3) return res.status(500).json({ message: 'db_error' });
                            res.json({ ok: true, pending: true });
                        });
                }
                db.run(`INSERT INTO friendships (user_id, friend_id, status, created_at) VALUES (?, ?, 'pending', ?)`,
                    [uid, targetId, Date.now()], (e4) => {
                        if (e4) return res.status(500).json({ message: 'db_error' });
                        res.json({ ok: true, pending: true, friend: publicFriend(target) });
                    });
            });
    });
});

app.post('/friends/respond', requireAuth, (req, res) => {
    const uid = req.user.id;
    const fromId = parseInt(req.body && req.body.id, 10);
    const accept = !!(req.body && req.body.accept);
    if (!fromId) return res.status(400).json({ message: 'Неверный ID' });
    db.get(`SELECT * FROM friendships WHERE user_id = ? AND friend_id = ? AND status = 'pending'`,
        [fromId, uid], (err, row) => {
            if (err) return res.status(500).json({ message: 'db_error' });
            if (!row) return res.status(404).json({ message: 'Заявка не найдена' });
            db.run(`UPDATE friendships SET status = ? WHERE id = ?`,
                [accept ? 'accepted' : 'declined', row.id], (e2) => {
                    if (e2) return res.status(500).json({ message: 'db_error' });
                    res.json({ ok: true, accepted: accept });
                });
        });
});

app.post('/friends/remove', requireAuth, (req, res) => {
    const uid = req.user.id;
    const otherId = parseInt(req.body && req.body.id, 10);
    if (!otherId) return res.status(400).json({ message: 'Неверный ID' });
    db.run(`DELETE FROM friendships
            WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)`,
        [uid, otherId, otherId, uid], (err) => {
            if (err) return res.status(500).json({ message: 'db_error' });
            res.json({ ok: true });
        });
});

// ==========================================
// 8. СООБЩЕНИЯ
// ==========================================
app.get('/messages/:id', requireAuth, async (req, res) => {
    const uid = req.user.id;
    const otherId = parseInt(req.params.id, 10);
    if (!otherId) return res.status(400).json({ message: 'Неверный ID' });
    if (!(await areFriends(uid, otherId)))
        return res.status(403).json({ message: 'Вы не друзья' });
    db.all(`SELECT * FROM messages
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
            ORDER BY created_at ASC LIMIT 200`,
        [uid, otherId, otherId, uid], (err, rows) => {
            if (err) return res.status(500).json({ message: 'db_error' });
            db.run(`UPDATE messages SET read_at = ? WHERE receiver_id = ? AND sender_id = ? AND read_at IS NULL`,
                [Date.now(), uid, otherId]);
            const msgs = rows.map(m => ({
                id: m.id, from: m.sender_id, to: m.receiver_id,
                type: m.type, content: m.content, url: m.url, filename: m.filename,
                createdAt: m.created_at, readAt: m.read_at
            }));
            res.json({ messages: msgs });
        });
});

app.post('/messages/:id', requireAuth, async (req, res) => {
    const uid = req.user.id;
    const otherId = parseInt(req.params.id, 10);
    if (!otherId) return res.status(400).json({ message: 'Неверный ID' });
    if (!(await areFriends(uid, otherId)))
        return res.status(403).json({ message: 'Вы не друзья' });
    const { type = 'text', content, url, filename } = req.body || {};
    if (type === 'text' && (!content || !String(content).trim()))
        return res.status(400).json({ message: 'Пустое сообщение' });
    if ((type === 'image' || type === 'audio') && !url)
        return res.status(400).json({ message: 'Нет файла' });
    db.run(`INSERT INTO messages (sender_id, receiver_id, type, content, url, filename, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [uid, otherId, type, content || null, url || null, filename || null, Date.now()],
        function (err) {
            if (err) return res.status(500).json({ message: 'db_error' });
            res.json({ ok: true, id: this.lastID, createdAt: Date.now() });
        });
});

app.post('/messages/:id/upload', requireAuth, upload.single('file'), async (req, res) => {
    const uid = req.user.id;
    const otherId = parseInt(req.params.id, 10);
    if (!otherId) return res.status(400).json({ message: 'Неверный ID' });
    if (!(await areFriends(uid, otherId)))
        return res.status(403).json({ message: 'Вы не друзья' });
    if (!req.file) return res.status(400).json({ message: 'Файл не принят' });
    const isAudio = req.file.mimetype.startsWith('audio/');
    const type = isAudio ? 'audio' : 'image';
    const url = '/uploads/' + req.file.filename;
    db.run(`INSERT INTO messages (sender_id, receiver_id, type, url, filename, created_at)
            VALUES (?, ?, ?, ?, ?, ?)`,
        [uid, otherId, type, url, req.file.originalname, Date.now()],
        function (err) {
            if (err) return res.status(500).json({ message: 'db_error' });
            res.json({ ok: true, id: this.lastID, type, url, filename: req.file.originalname });
        });
});

// ==========================================
// TELEGRAM
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
    db.run(`INSERT OR REPLACE INTO oauth_state (state, verifier, return_url, provider, expires_at) VALUES (?, ?, ?, 'telegram', ?)`,
        [state, verifier, returnUrl, Date.now() + 10 * 60 * 1000], (err) => {
            if (err) { console.error('oauth_state:', err.message); return res.status(500).send('state_error'); }
            db.run(`DELETE FROM oauth_state WHERE expires_at < ?`, [Date.now()]);
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
    const site = FALLBACK_SITE;
    try {
        const { code, state, error } = req.query;
        if (error) return redirectToSiteError(res, site, 'telegram_' + error);
        if (!code || !state) return redirectToSiteError(res, site, 'missing_code');
        const stored = await new Promise((resolve) => {
            db.get(`SELECT * FROM oauth_state WHERE state = ? AND expires_at > ?`, [state, Date.now()],
                (err, row) => resolve(err ? null : row));
        });
        if (!stored) { console.warn('⚠️ state not found:', state); return redirectToSiteError(res, site, 'state_expired'); }
        db.run(`DELETE FROM oauth_state WHERE state = ?`, [state]);
        const clientId = process.env.TG_CLIENT_ID;
        const clientSecret = process.env.TG_CLIENT_SECRET;
        if (!clientId || !clientSecret) return redirectToSiteError(res, site, 'server_config');
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
        if (!id_token) return redirectToSiteError(res, site, 'no_id_token');
        const { payload } = await jwtVerify(id_token, TG_JWKS, {
            issuer: TG_ISSUER, audience: clientId
        });
        const providerId = String(payload.id || payload.sub);
        const username = payload.preferred_username || null;
        const displayNick = username
            ? (username.startsWith('@') ? username : '@' + username)
            : ([payload.given_name, payload.family_name].filter(Boolean).join(' ') || payload.name || 'tg_' + providerId);
        const login = (username || 'tg_' + providerId).replace(/[^A-Za-z0-9_.\-]/g, '_').slice(0, 24) || ('tg_' + providerId);
        const avatar = payload.picture || null;
        db.get(`SELECT u.* FROM user_providers p JOIN users u ON u.id = p.user_id
                WHERE p.provider = 'telegram' AND p.provider_id = ?`, [providerId], async (err, existing) => {
            if (err) return redirectToSiteError(res, site, 'db_error');
            if (existing) {
                db.run(`UPDATE users SET nick = ?, avatar = ?, last_login = ? WHERE id = ?`,
                    [displayNick, avatar, Date.now(), existing.id], async () => {
                        const token = await createSession(existing.id);
                        if (!token) return redirectToSiteError(res, site, 'session_error');
                        redirectToSite(res, normalizeReturnUrl(stored.return_url), token, 'telegram');
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
                            return redirectToSiteError(res, site, 'db_error');
                        }
                        const userId = this.lastID;
                        db.run(`INSERT OR IGNORE INTO user_providers (user_id, provider, provider_id) VALUES (?, 'telegram', ?)`,
                            [userId, providerId], async () => {
                                const token = await createSession(userId);
                                if (!token) return redirectToSiteError(res, site, 'session_error');
                                redirectToSite(res, normalizeReturnUrl(stored.return_url), token, 'telegram');
                            });
                    });
            };
            tryInsert(0);
        });
    } catch (e) {
        console.error('❌ TELEGRAM CALLBACK ERROR:', {
            message: e.message,
            status: e.response && e.response.status,
            data: e.response && e.response.data,
            stack: e.stack && e.stack.split('\n').slice(0, 3)
        });
        redirectToSiteError(res, site, 'telegram_error');
    }
});

// ==========================================
// GOOGLE
// ==========================================
app.get('/auth/google/start', (req, res) => {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    if (!clientId) return res.status(500).send('GOOGLE_CLIENT_ID not set');
    const returnUrl = normalizeReturnUrl(req.query.redirect);
    const origin = serverOrigin(req);
    const redirectUri = `${origin}/auth/google/callback`;
    const state = crypto.randomBytes(16).toString('hex');
    db.run(`INSERT OR REPLACE INTO oauth_state (state, verifier, return_url, provider, expires_at) VALUES (?, ?, ?, 'google', ?)`,
        [state, null, returnUrl, Date.now() + 10 * 60 * 1000], (err) => {
            if (err) { console.error('oauth_state:', err.message); return res.status(500).send('state_error'); }
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
    if (error) return redirectToSiteError(res, FALLBACK_SITE, 'google_' + error);
    const site = FALLBACK_SITE;
    const safeState = JSON.stringify(String(state || ''));
    const safeSite = JSON.stringify(site);
    res.type('html').send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Google…</title>
<style>body{background:#040404;color:#fff;font-family:Inter,system-ui,sans-serif;
display:grid;place-items:center;height:100vh;margin:0}
.m{opacity:.7;font-size:14px}</style></head>
<body><div class="m">Завершаем вход через Google…</div>
<script>
(function(){
  var site = ${safeSite};
  var state = ${safeState};
  var hash = new URLSearchParams(location.hash.replace(/^#/, ''));
  var accessToken = hash.get('access_token');
  var err = hash.get('error');
  if(err){ location.replace(site + '?error=' + encodeURIComponent('google_' + err)); return; }
  if(!accessToken){ location.replace(site + '?error=no_token'); return; }
  fetch('/auth/google/exchange', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ access_token: accessToken, state: state })
  })
  .then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
  .then(function(x){
    if(!x.ok){ location.replace(site + '?error=' + encodeURIComponent(x.d&&x.d.message||'unknown')); return; }
    location.replace(x.d.redirect);
  })
  .catch(function(e){ location.replace(site + '?error=' + encodeURIComponent(e.message)); });
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
        } catch (e) { return res.status(401).json({ message: 'Неверный Google токен' }); }
        if (!info || !info.sub) return res.status(401).json({ message: 'userinfo пуст' });
        let returnUrl = FALLBACK_SITE;
        if (state) {
            const row = await new Promise((resolve) => {
                db.get(`SELECT * FROM oauth_state WHERE state = ? AND expires_at > ?`,
                    [state, Date.now()], (err, r) => resolve(err ? null : r));
            });
            if (row) {
                returnUrl = normalizeReturnUrl(row.return_url);
                db.run(`DELETE FROM oauth_state WHERE state = ?`, [state]);
            }
        }
        const providerId = String(info.sub);
        const displayNick = info.name || [info.given_name, info.family_name].filter(Boolean).join(' ') || info.email || ('g_' + providerId);
        const avatar = info.picture || null;
        db.get(`SELECT u.* FROM user_providers p JOIN users u ON u.id = p.user_id
                WHERE p.provider = 'google' AND p.provider_id = ?`, [providerId], async (err, existing) => {
            if (err) return res.status(500).json({ message: 'db_error' });
            if (existing) {
                db.run(`UPDATE users SET nick = ?, avatar = ?, last_login = ? WHERE id = ?`,
                    [displayNick, avatar, Date.now(), existing.id], async () => {
                        const token = await createSession(existing.id);
                        if (!token) return res.status(500).json({ message: 'session_error' });
                        const sep = returnUrl.includes('?') ? '&' : '?';
                        res.json({ redirect: `${returnUrl}${sep}token=${token}&provider=google` });
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
                            [userId, providerId], async () => {
                                const token = await createSession(userId);
                                if (!token) return res.status(500).json({ message: 'session_error' });
                                const sep = returnUrl.includes('?') ? '&' : '?';
                                res.json({ redirect: `${returnUrl}${sep}token=${token}&provider=google` });
                            });
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
    db.run(`DELETE FROM friendships WHERE user_id = ? OR friend_id = ?`, [id, id]);
    db.run(`DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?`, [id, id]);
    db.run(`DELETE FROM users WHERE id = ?`, [id], (err) => {
        if (err) return res.status(500).json({ message: 'db_error' });
        res.json({ ok: true });
    });
});

// ==========================================
// 9. ЗАПУСК
// ==========================================
app.get('/', (req, res) => res.send('ProxyGem API работает ✅'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Порт ${PORT}`);
    console.log(`   PUBLIC_URL = ${PUBLIC_URL || '(auto)'}`);
    console.log(`   SITE_URL   = ${SITE_URL || '(fallback ' + FALLBACK_SITE + ')'}`);
});

process.on('SIGTERM', () => {
    console.log('SIGTERM');
    db.close(() => process.exit(0));
});
