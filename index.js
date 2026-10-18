const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(cors());
app.use(express.json());

// ==========================================
// 1. КЛЮЧИ (Читаются из переменной окружения premium_keys)
// ==========================================
let secretKeys = {};
try {
    if (process.env.premium_keys) {
        const rawData = JSON.parse(process.env.premium_keys);
        // Поддерживаем оба формата: {"codes": [...]} и просто [...]
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
            console.log(`✅ Загружено ${Object.keys(secretKeys).length} ключей из premium_keys`);
        } else {
            secretKeys = rawData;
            console.log("✅ Ключи загружены (прямой объект)");
        }
    } else {
        console.log("⚠️ ВНИМАНИЕ: premium_keys не найдена. Используются тестовые ключи.");
        secretKeys = { "TEST-KEY-123": { "duration": "1_month", "max_activations": 1, "used": false, "gived": false } };
    }
} catch (e) {
    console.error("❌ Ошибка в формате JSON в premium_keys:", e.message);
}

// ==========================================
// 2. БАЗА ДАННЫХ (SQLite)
// ==========================================
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error("Ошибка БД:", err.message);
    else console.log("✅ База данных SQLite подключена");
});

// Таблица для привязки ключа к устройству (программа)
db.run(`CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT,
    device_id TEXT,
    expires INTEGER
)`);

// Таблица для отслеживания, выдан ли ключ на сайте
db.run(`CREATE TABLE IF NOT EXISTS key_status (
    key_id TEXT PRIMARY KEY,
    gived INTEGER DEFAULT 0
)`);

// ==========================================
// 3. API ДЛЯ САЙТА
// ==========================================

// Выдача ключа после оплаты на сайте
app.post('/api/get-key', (req, res) => {
    const { duration } = req.body;
    
    // Ищем ключ, который еще не выдан на сайте (gived = false) и не активирован (used = false)
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

    // Помечаем в базе, что ключ выдан (gived = 1)
    db.run(`INSERT OR REPLACE INTO key_status (key_id, gived) VALUES (?, 1)`, [foundKey], (err) => {
        if (err) return res.status(500).json({ success: false, message: 'Ошибка базы данных' });
        
        secretKeys[foundKey].gived = true; // Обновляем в памяти
        console.log(`🎁 Ключ ${foundKey} выдан на сайте`);
        return res.json({ success: true, key: foundKey });
    });
});

// ==========================================
// 4. API ДЛЯ ПРОГРАММЫ
// ==========================================

// Активация ключа в приложении
app.post('/api/activate', (req, res) => {
    const { key, deviceId } = req.body;
    if (!key || !deviceId) return res.status(400).json({ success: false, message: 'Не переданы данные' });

    const cleanKey = key.trim().toUpperCase();
    const keyConfig = secretKeys[cleanKey];

    if (!keyConfig) return res.status(404).json({ success: false, message: 'invalid_key' });

    // Проверяем, не исчерпан ли лимит (если used = true и лимит 1, то отказ)
    if (keyConfig.used && keyConfig.max_activations === 1) {
        return res.status(400).json({ success: false, message: 'exhausted' });
    }

    // Проверяем, не активирован ли уже на этом устройстве
    db.get(`SELECT * FROM activations WHERE key_id = ? AND device_id = ?`, [cleanKey, deviceId], (err, row) => {
        if (row) return res.status(400).json({ success: false, message: 'already_activated_here' });

        // Считаем, сколько раз ключ уже активировали
        db.get(`SELECT COUNT(*) as count FROM activations WHERE key_id = ?`, [cleanKey], (err, result) => {
            if (result.count >= keyConfig.max_activations) {
                return res.status(400).json({ success: false, message: 'exhausted' });
            }

            // Вычисляем время окончания подписки
            const now = Date.now();
            let ms = 30 * 24 * 60 * 60 * 1000; // 1 месяц по умолчанию
            if (keyConfig.duration === '7_days') ms = 7 * 24 * 60 * 60 * 1000;
            if (keyConfig.duration === '3_months') ms = 90 * 24 * 60 * 60 * 1000;
            if (keyConfig.duration === '6_months') ms = 180 * 24 * 60 * 60 * 1000;
            if (keyConfig.duration === 'forever') ms = 3650 * 24 * 60 * 60 * 1000;
            
            const expires = now + ms;

            // Записываем активацию в базу
            db.run(`INSERT INTO activations (key_id, device_id, expires) VALUES (?, ?, ?)`, [cleanKey, deviceId, expires], (err) => {
                if (err) return res.status(500).json({ success: false, message: 'db_error' });
                
                // Если это была последняя возможная активация — ставим used = true
                if (result.count + 1 >= keyConfig.max_activations) {
                    secretKeys[cleanKey].used = true;
                }
                
                console.log(`✅ Ключ ${cleanKey} активирован на устройстве ${deviceId}`);
                return res.json({ 
                    success: true, 
                    message: 'premium_activated', 
                    duration: keyConfig.duration,
                    expires: expires
                });
            });
        });
    });
});

// Проверка статуса подписки для программы (при запуске)
app.get('/api/status', (req, res) => {
    const { deviceId } = req.query;
    if (!deviceId) return res.status(400).json({ active: false });

    db.get(`SELECT * FROM activations WHERE device_id = ? ORDER BY expires DESC LIMIT 1`, [deviceId], (err, row) => {
        if (row && Date.now() < row.expires) {
            const keyConfig = secretKeys[row.key_id] || {};
            return res.json({ 
                active: true, 
                expires: row.expires, 
                duration: keyConfig.duration || '1_month' 
            });
        }
        return res.json({ active: false });
    });
});

// ==========================================
// 5. ЗАПУСК СЕРВЕРА
// ==========================================
app.get('/', (req, res) => res.send('ProxyGem API работает ✅'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));
