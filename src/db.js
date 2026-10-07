const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

// استخدام المجلد المؤقت /tmp لتسهيل الكتابة على Vercel
const dbPath = process.env.VERCEL ? path.join('/tmp', 'hamzawy.db') : path.join(__dirname, '..', 'hamzawy.db');
const db = new Database(dbPath);
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('customer','technician','admin')),
  approved INTEGER NOT NULL DEFAULT 0,
  balance INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  customer_id INTEGER NOT NULL,
  service_id INTEGER NOT NULL,
  area TEXT,
  address TEXT,
  problem TEXT,
  customer_price INTEGER,
  technician_fee INTEGER,
  status TEXT NOT NULL DEFAULT 'pending',
  opened_by_technician_id INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  opened_at TEXT,
  FOREIGN KEY(customer_id) REFERENCES users(id),
  FOREIGN KEY(service_id) REFERENCES services(id),
  FOREIGN KEY(opened_by_technician_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS recharge_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  technician_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  reference_number TEXT,
  receipt_path TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  rejection_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT,
  FOREIGN KEY(technician_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS wallet_settings (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  provider TEXT NOT NULL,
  wallet_number TEXT NOT NULL,
  owner_name TEXT NOT NULL,
  instructions TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS balance_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  technician_id INTEGER NOT NULL,
  order_id INTEGER,
  recharge_request_id INTEGER,
  type TEXT NOT NULL CHECK(type IN ('recharge','order_deduction')),
  amount INTEGER NOT NULL,
  balance_after INTEGER NOT NULL,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(technician_id) REFERENCES users(id),
  FOREIGN KEY(order_id) REFERENCES orders(id),
  FOREIGN KEY(recharge_request_id) REFERENCES recharge_requests(id)
);
`);

// إضافة خدمات حمزاوي سات الافتراضية
const count = db.prepare('SELECT COUNT(*) AS c FROM services').get().c;
if (!count) {
  const insert = db.prepare('INSERT INTO services (name, description) VALUES (?, ?)');
  insert.run('تركيب وصيانة الدش والريسيفر', 'تركيب وضبط وإصلاح الدش والريسيفرات');
  insert.run('تركيب وصيانة كاميرات المراقبة', 'تركيب وبرمجة وصيانة أنظمة المراقبة');
  insert.run('صيانة إضاءة LED للتلفزيون', 'تغيير وإصلاح شرائط LED لشاشات التلفزيون');
}

// إضافة إعدادات المحفظة
const wallet = db.prepare('SELECT id FROM wallet_settings WHERE id=1').get();
if (!wallet) {
  db.prepare(`
    INSERT INTO wallet_settings (id, provider, wallet_number, owner_name, instructions)
    VALUES (1, 'Vodafone Cash', '01152822263', 'حمزاوي سات', 'حوّل المبلغ ثم ارفع صورة الإيصال من التطبيق.')
  `).run();
}

// إنشاء حساب الأدمن الافتراضي تلقائياً
const adminExists = db.prepare("SELECT id FROM users WHERE role='admin'").get();
if (!adminExists) {
  const adminPhone = '01152822263';
  const adminPasswordHash = bcrypt.hashSync('admin123', 10);
  db.prepare(`
    INSERT INTO users (name, phone, password_hash, role, approved)
    VALUES ('الأدمن', ?, ?, 'admin', 1)
  `).run(adminPhone, adminPasswordHash);
}

module.exports = db;
