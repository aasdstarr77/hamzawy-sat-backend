const bcrypt=require('bcryptjs');
const db=require('./src/db');
const phone=process.env.ADMIN_PHONE||'01000000000';
const password=process.env.ADMIN_PASSWORD||'ChangeMe123!';
const name=process.env.ADMIN_NAME||'حمزاوي سات - الأدمن';
const exists=db.prepare('SELECT id FROM users WHERE phone=?').get(phone);
if(exists){db.prepare("UPDATE users SET role='admin',approved=1 WHERE id=?").run(exists.id);console.log('Admin account already existed and was set to admin:',phone)}
else{const hash=bcrypt.hashSync(password,12);db.prepare("INSERT INTO users(name,phone,password_hash,role,approved) VALUES(?,?,?,?,1)").run(name,phone,hash,'admin');console.log('Admin created:',phone)}
