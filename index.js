const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const app = express();

// ==========================================
// 0. БАЗОВАЯ НАСТРОЙКА
// ==========================================
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '2mb' }));

// Health-check для Render
app.get('/health', (req, res) => res.status(200).send('OK'));

// ==========================================
// 1. ЗАГРУЗКА КЛЮЧЕЙ
// Приоритет: keys.json рядом со скриптом → env premium_keys → тест
// ==========================================
let secretKeys = {};

// Ключи, которые нельзя выдавать/активировать (админские/тестовые)
const BLOCKED_KEYS = new Set(['PROXYGEM']);

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
            // Формат: [{id, duration, max_activations, ...}]
            keysArray.forEach(k => {
                if (!k || !k.id) return;
                if (BLOCKED_KEYS.has(k.id)) return;
                secretKeys[k.id] = normalizeKeyConfig(k);
            });
        } else if (rawData && typeof rawData === 'object') {
            // ВАШ ФОРМАТ: { "KEY": {duration, max_activations}, ... }
            for (const [id, cfg] of Object.entries(rawData)) {
                if (BLOCKED_KEYS.has(id)) {
                    console.warn(`🚫 Ключ ${id} заблокирован (BLOCKED_KEYS)`);
                    continue;
                }
                secretKeys[id] = normalizeKeyConfig(cfg || {});
            }
        } else {
            throw new Error('Неизвестный формат ключей');
        }

        console.log(`✅ Загружено ${Object.keys(secretKeys).length} ключей`);
    } catch (e) {
        console.error('❌ Ошибка загрузки ключей:', e.message);
        secretKeys = {
            'TEST-KEY-123': { duration: '1_month', max_activations: 1, used: false, gived: false }
        };
    }
}
loadKeys();

// ==========================================
// 2. БАЗА ДАННЫХ
// На Render обязательно: Render Disk + DB_PATH=/data/database.sqlite
// ==========================================
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) console.error('Ошибка БД:', err.message);
    else console.log('✅ SQLite подключена:', DB_PATH);
});

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
    db.run(`CREATE INDEX IF NOT EXISTS idx_activations_key ON activations(key_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_activations_device ON activations(device_id)`);
});

// --- Восстановление флага gived из БД ---
db.all(`SELECT key_id FROM key_status WHERE gived = 1`, (err, rows) => {
    if (err || !rows) return;
    let restored = 0;
    rows.forEach(r => {
        if (secretKeys[r.key_id]) {
            secretKeys[r.key_id].gived = true;
            restored++;
        }
    });
    console.log(`✅ Восстановлено gived для ${restored} ключей`);
});

// --- Восстановление флага used по количеству активаций ---
db.all(
    `SELECT key_id, COUNT(*) as cnt FROM activations GROUP BY key_id`,
    (err, rows) => {
        if (err || !rows) return;
        let restored = 0;
        rows.forEach(r => {
            const cfg = secretKeys[r.key_id];
            if (cfg && r.cnt >= cfg.max_activations) {
                cfg.used = true;
                restored++;
            }
        });
        console.log(`✅ Восстановлено used для ${restored} ключей`);
    }
);

// ==========================================
// 3. API ДЛЯ САЙТА
// ==========================================
app.post('/api/get-key', (req, res) => {
    const { duration } = req.body || {};
    if (!duration) {
        return res.status(400).json({ success: false, message: 'Не указан duration' });
    }

    let foundKey = null;
    for (const [key, data] of Object.entries(secretKeys)) {
        if (data.duration === duration && !data.gived && !data.used) {
            foundKey = key;
            break;
        }
    }

    if (!foundKey) {
        return res.status(404).json({ success: false, message: 'Нет свободных ключей для этого тарифа' });
    }

    db.run(
        `INSERT OR REPLACE INTO key_status (key_id, gived) VALUES (?, 1)`,
        [foundKey],
        (err) => {
            if (err) {
                console.error('DB error get-key:', err.message);
                return res.status(500).json({ success: false, message: 'Ошибка базы данных' });
            }
            secretKeys[foundKey].gived = true;
            console.log(`🎁 Ключ ${foundKey} выдан на сайте`);
            return res.json({ success: true, key: foundKey });
        }
    );
});

// ==========================================
// 4. API ДЛЯ ПРОГРАММЫ
// ==========================================
app.post('/api/activate', (req, res) => {
    const { key, deviceId } = req.body || {};
    if (!key || !deviceId) {
        return res.status(400).json({ success: false, message: 'Не переданы данные' });
    }

    const cleanKey = String(key).trim().toUpperCase();
    const keyConfig = secretKeys[cleanKey];

    if (!keyConfig) return res.status(404).json({ success: false, message: 'invalid_key' });

    if (keyConfig.used && keyConfig.max_activations === 1) {
        return res.status(400).json({ success: false, message: 'exhausted' });
    }

    db.get(
        `SELECT * FROM activations WHERE key_id = ? AND device_id = ?`,
        [cleanKey, deviceId],
        (err, row) => {
            if (err) return res.status(500).json({ success: false, message: 'db_error' });
            if (row) return res.status(400).json({ success: false, message: 'already_activated_here' });

            db.get(
                `SELECT COUNT(*) as count FROM activations WHERE key_id = ?`,
                [cleanKey],
                (err, result) => {
                    if (err) return res.status(500).json({ success: false, message: 'db_error' });

                    if (result.count >= keyConfig.max_activations) {
                        // на всякий случай синхронизируем память
                        secretKeys[cleanKey].used = true;
                        return res.status(400).json({ success: false, message: 'exhausted' });
                    }

                    const now = Date.now();
                    let ms = 30 * 24 * 60 * 60 * 1000;
                    if (keyConfig.duration === '7_days')     ms = 7    * 24 * 60 * 60 * 1000;
                    if (keyConfig.duration === '3_months')   ms = 90   * 24 * 60 * 60 * 1000;
                    if (keyConfig.duration === '6_months')   ms = 180  * 24 * 60 * 60 * 1000;
                    if (keyConfig.duration === 'forever')    ms = 3650 * 24 * 60 * 60 * 1000;
                    const expires = now + ms;

                    db.run(
                        `INSERT INTO activations (key_id, device_id, expires) VALUES (?, ?, ?)`,
                        [cleanKey, deviceId, expires],
                        (err) => {
                            if (err) return res.status(500).json({ success: false, message: 'db_error' });

                            if (result.count + 1 >= keyConfig.max_activations) {
                                secretKeys[cleanKey].used = true;
                            }

                            console.log(`✅ Ключ ${cleanKey} активирован на ${deviceId}`);
                            return res.json({
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
});

app.get('/api/status', (req, res) => {
    const { deviceId } = req.query;
    if (!deviceId) return res.status(400).json({ active: false });

    db.get(
        `SELECT * FROM activations WHERE device_id = ? ORDER BY expires DESC LIMIT 1`,
        [deviceId],
        (err, row) => {
            if (err) return res.status(500).json({ active: false });
            if (row && Date.now() < row.expires) {
                const keyConfig = secretKeys[row.key_id] || {};
                return res.json({
                    active: true,
                    expires: row.expires,
                    duration: keyConfig.duration || '1_month'
                });
            }
            return res.json({ active: false });
        }
    );
});

// ==========================================
// 5. ЗАПУСК
// ==========================================
app.get('/', (req, res) => res.send('ProxyGem API работает ✅'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Сервер запущен на порту ${PORT}`);
});

// Graceful shutdown (Render шлёт SIGTERM)
process.on('SIGTERM', () => {
    console.log('SIGTERM, закрываю БД...');
    db.close(() => process.exit(0));
});
