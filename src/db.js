const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const connectionString = process.env.DATABASE_URL || 'postgresql://neondb_owner:npg_rSPAi3ZDXp2R@ep-floral-dream-b413v6b8-pooler.c-6.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require';

const pool = new Pool({
  connectionString,
  ssl: { rejectUnauthorized: false }
});

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        phone TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('customer','technician','admin')),
        approved INT NOT NULL DEFAULT 0,
        balance INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        active INT NOT NULL DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        customer_id INT NOT NULL REFERENCES users(id),
        service_id INT NOT NULL REFERENCES services(id),
        area TEXT,
        address TEXT,
        problem TEXT,
        customer_price INT,
        technician_fee INT,
        status TEXT NOT NULL DEFAULT 'pending',
        opened_by_technician_id INT REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        opened_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS recharge_requests (
        id SERIAL PRIMARY KEY,
        technician_id INT NOT NULL REFERENCES users(id),
        amount INT NOT NULL,
        reference_number TEXT,
        receipt_path TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        rejection_reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS wallet_settings (
        id INT PRIMARY KEY CHECK(id = 1),
        provider TEXT NOT NULL,
        wallet_number TEXT NOT NULL,
        owner_name TEXT NOT NULL,
        instructions TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS balance_transactions (
        id SERIAL PRIMARY KEY,
        technician_id INT NOT NULL REFERENCES users(id),
        order_id INT REFERENCES orders(id),
        recharge_request_id INT REFERENCES recharge_requests(id),
        type TEXT NOT NULL CHECK(type IN ('recharge','order_deduction')),
        amount INT NOT NULL,
        balance_after INT NOT NULL,
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // إضافة الخدمات الافتراضية
    const servicesCount = await client.query('SELECT COUNT(*) FROM services');
    if (parseInt(servicesCount.rows[0].count) === 0) {
      await client.query(`
        INSERT INTO services (name, description) VALUES 
        ('تركيب وصيانة الدش والريسيفر', 'تركيب وضبط وإصلاح الدش والريسيفرات'),
        ('تركيب وصيانة كاميرات المراقبة', 'تركيب وبرمجة وصيانة أنظمة المراقبة'),
        ('صيانة إضاءة LED للتلفزيون', 'تغيير وإصلاح شرائط LED لشاشات التلفزيون');
      `);
    }

    // إعدادات المحفظة
    const wallet = await client.query('SELECT id FROM wallet_settings WHERE id=1');
    if (wallet.rows.length === 0) {
      await client.query(`
        INSERT INTO wallet_settings (id, provider, wallet_number, owner_name, instructions)
        VALUES (1, 'Vodafone Cash', '01152822263', 'حمزاوي سات', 'حوّل المبلغ ثم ارفع صورة الإيصال من التطبيق.');
      `);
    }

    // إنشاء حساب الأدمن الافتراضي
    const admin = await client.query("SELECT id FROM users WHERE role='admin'");
    if (admin.rows.length === 0) {
      const hash = bcrypt.hashSync('admin123', 10);
      await client.query(`
        INSERT INTO users (name, phone, password_hash, role, approved)
        VALUES ('الأدمن', '01152822263', $1, 'admin', 1);
      `, [hash]);
    }
  } finally {
    client.release();
  }
}

initDb().catch(console.error);

module.exports = {
  query: (text, params) => pool.query(text, params)
};
