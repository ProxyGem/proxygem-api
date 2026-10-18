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
        secretKeys = JSON.parse(process.env.premium_keys);
        console.log("✅ Ключи успешно загружены из premium_keys");
    } else {
        // Тестовый ключ, если переменная забыта
        secretKeys = { "TEST-KEY-123": { "duration": "1_month", "max_activations": 1 } };
        console.log("⚠️ ВНИМАНИЕ: premium_keys не найдена. Используются тестовые ключи.");
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

// Создаем таблицу для активаций
db.run(`CREATE TABLE IF NOT EXISTS activations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id TEXT,
    device_id TEXT,
    expires INTEGER
)`);

// ==========================================
// 3. API ЭНДПОИНТЫ
// ==========================================

// Активация ключа
app.post('/api/activate', (req, res) => {
    const { key, deviceId } = req.body;
    if (!key || !deviceId) return res.status(400).json({ success: false, message: 'Не переданы данные' });

    const cleanKey = key.trim().toUpperCase();
    const keyConfig = secretKeys[cleanKey];

    // 1. Проверка: существует ли такой ключ
    if (!keyConfig) {
        return res.status(404).json({ success: false, message: 'invalid_key' });
    }

    // 2. Проверяем базу: не активирован ли уже на этом устройстве?
    db.get(`SELECT * FROM activations WHERE key_id = ? AND device_id = ?`, [cleanKey, deviceId], (err, row) => {
        if (row) {
            return res.status(400).json({ success: false, message: 'already_activated_here' });
        }

        // 3. Проверяем лимит активаций
        db.get(`SELECT COUNT(*) as count FROM activations WHERE key_id = ?`, [cleanKey], (err, result) => {
            if (result.count >= keyConfig.max_activations) {
                return res.status(400).json({ success: false, message: 'exhausted' });
            }

            // 4. Вычисляем время окончания
            const now = Date.now();
            let ms = 30 * 24 * 60 * 60 * 1000; // 1 месяц по умолчанию
            if (keyConfig.duration === '7_days') ms = 7 * 24 * 60 * 60 * 1000;
            if (keyConfig.duration === 'forever') ms = 3650 * 24 * 60 * 60 * 1000;
            
            const expires = now + ms;

            // 5. Записываем в базу
            db.run(`INSERT INTO activations (key_id, device_id, expires) VALUES (?, ?, ?)`, [cleanKey, deviceId, expires], (err) => {
                if (err) return res.status(500).json({ success: false, message: 'db_error' });
                
                console.log(`✅ Ключ ${cleanKey} активирован на ${deviceId}`);
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

// Проверка статуса (при запуске клиента, чтобы подделать нельзя было)
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

app.get('/', (req, res) => res.send('ProxyGem API работает ✅'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));
