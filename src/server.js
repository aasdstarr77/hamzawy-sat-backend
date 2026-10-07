const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET_BEFORE_PRODUCTION';

app.use(cors({origin:true}));
app.use(express.json({limit:'2mb'}));
app.use('/uploads', express.static(path.join(__dirname,'..','uploads')));

const uploadDir = path.join(__dirname,'..','uploads');
fs.mkdirSync(uploadDir, {recursive:true});
const upload = multer({
  dest: uploadDir,
  limits: {fileSize: 5 * 1024 * 1024},
  fileFilter: (req,file,cb) => {
    if (/^image\/(jpeg|png|webp)$/.test(file.mimetype)) cb(null,true);
    else cb(new Error('يسمح بصور JPG/PNG/WEBP فقط'));
  }
});

function userById(id){ return db.prepare('SELECT * FROM users WHERE id=?').get(id); }

function auth(req,res,next){
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return res.status(401).json({error:'تسجيل الدخول مطلوب'});
  try {
    const payload = jwt.verify(header.slice(7), JWT_SECRET);
    const user = userById(payload.userId);
    if (!user) return res.status(401).json({error:'الحساب غير موجود'});
    req.user = user;
    next();
  } catch { res.status(401).json({error:'جلسة الدخول غير صالحة أو منتهية'}); }
}

function role(roleName){
  return (req,res,next) => {
    if (!req.user || req.user.role !== roleName) return res.status(403).json({error:'غير مصرح'});
    next();
  };
}

function publicUser(u){
  return {id:u.id,name:u.name,phone:u.phone,role:u.role,approved:!!u.approved,balance:u.role==='technician'?u.balance:undefined};
}

app.get('/api/health',(req,res)=>res.json({ok:true,service:'Hamzawy Sat Backend',version:'0.2.0'}));

app.post('/api/auth/register', async (req,res)=>{
  const {name,phone,password,role='customer'}=req.body;
  if (!name || !phone || !password) return res.status(400).json({error:'الاسم ورقم الهاتف وكلمة المرور مطلوبة'});
  if (!['customer','technician'].includes(role)) return res.status(400).json({error:'الدور غير صالح'});
  if (String(password).length < 6) return res.status(400).json({error:'كلمة المرور يجب ألا تقل عن 6 أحرف'});
  const exists=db.prepare('SELECT id FROM users WHERE phone=?').get(phone);
  if (exists) return res.status(409).json({error:'رقم الهاتف مستخدم بالفعل'});
  const hash=await bcrypt.hash(password,12);
  const result=db.prepare('INSERT INTO users(name,phone,password_hash,role,approved) VALUES(?,?,?,?,?)')
    .run(name,phone,hash,role,role==='customer'?1:0);
  const user=userById(result.lastInsertRowid);
  res.status(201).json({user:publicUser(user),message:role==='technician'?'تم إنشاء الحساب، وفي انتظار موافقة الأدمن.':'تم إنشاء الحساب'});
});

app.post('/api/auth/login', async (req,res)=>{
  const {phone,password}=req.body;
  const user=db.prepare('SELECT * FROM users WHERE phone=?').get(phone);
  if (!user || !(await bcrypt.compare(password||'',user.password_hash)))
    return res.status(401).json({error:'رقم الهاتف أو كلمة المرور غير صحيحة'});
  const token=jwt.sign({userId:user.id,role:user.role},JWT_SECRET,{expiresIn:'7d'});
  res.json({token,user:publicUser(user)});
});

app.get('/api/me',auth,(req,res)=>res.json({user:publicUser(req.user)}));

app.get('/api/services',(req,res)=>{
  res.json(db.prepare('SELECT id,name,description FROM services WHERE active=1 ORDER BY id').all());
});

app.post('/api/orders',(req,res)=>{
  const {service_id,name,phone,area,address,problem}=req.body;
  const service=db.prepare('SELECT id FROM services WHERE id=? AND active=1').get(service_id);
  if(!service) return res.status(404).json({error:'الخدمة غير موجودة'});
  if(!name || !phone) return res.status(400).json({error:'الاسم ورقم الهاتف مطلوبان'});

  // العميل لا يحتاج لتسجيل حساب. ننشئ/نستخدم سجل عميل داخلي فقط لربط الطلب بالأدمن والفني.
  let customer = db.prepare("SELECT id FROM users WHERE phone=? AND role='customer' LIMIT 1").get(phone);
  if(!customer){
    const crypto = require('crypto');
    const bcrypt = require('bcryptjs');
    const tempPassword = crypto.randomBytes(24).toString('hex');
    const hash = bcrypt.hashSync(tempPassword, 10);
    const created = db.prepare("INSERT INTO users(name,phone,password_hash,role,approved) VALUES(?,?,?,?,1)")
      .run(name,phone,hash,'customer');
    customer = {id: created.lastInsertRowid};
  } else {
    db.prepare("UPDATE users SET name=? WHERE id=?").run(name,customer.id);
  }

  const result=db.prepare('INSERT INTO orders(customer_id,service_id,area,address,problem) VALUES(?,?,?,?,?)')
    .run(customer.id,service_id,area||'',address||'',problem||'');
  res.status(201).json({order_id:result.lastInsertRowid,status:'pending'});
});

app.get('/api/my/orders',auth,role('customer'),(req,res)=>{
  const rows=db.prepare(`
    SELECT o.id,s.name service,o.area,o.address,o.problem,o.customer_price,o.status,o.created_at
    FROM orders o JOIN services s ON s.id=o.service_id
    WHERE o.customer_id=? ORDER BY o.id DESC
  `).all(req.user.id);
  res.json(rows);
});

// Admin dashboard
app.get('/api/admin/dashboard',auth,role('admin'),(req,res)=>{
  const counts = {
    customers: db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c,
    technicians: db.prepare("SELECT COUNT(*) c FROM users WHERE role='technician'").get().c,
    pending_technicians: db.prepare("SELECT COUNT(*) c FROM users WHERE role='technician' AND approved=0").get().c,
    orders: db.prepare("SELECT COUNT(*) c FROM orders").get().c,
    available_orders: db.prepare("SELECT COUNT(*) c FROM orders WHERE status='available'").get().c,
    pending_recharges: db.prepare("SELECT COUNT(*) c FROM recharge_requests WHERE status='pending'").get().c
  };
  res.json(counts);
});

app.get('/api/admin/technicians',auth,role('admin'),(req,res)=>{
  res.json(db.prepare(`
    SELECT id,name,phone,approved,balance,created_at
    FROM users WHERE role='technician' ORDER BY id DESC
  `).all());
});

app.post('/api/admin/technicians/:id/approve',auth,role('admin'),(req,res)=>{
  const id=Number(req.params.id);
  const result=db.prepare("UPDATE users SET approved=1 WHERE id=? AND role='technician'").run(id);
  if(!result.changes) return res.status(404).json({error:'الفني غير موجود'});
  res.json({ok:true});
});

app.get('/api/admin/orders',auth,role('admin'),(req,res)=>{
  res.json(db.prepare(`
    SELECT o.*, s.name service, c.name customer_name, c.phone customer_phone
    FROM orders o
    JOIN services s ON s.id=o.service_id
    JOIN users c ON c.id=o.customer_id
    ORDER BY o.id DESC
  `).all());
});

app.post('/api/admin/orders/:id/pricing',auth,role('admin'),(req,res)=>{
  const id=Number(req.params.id);
  const customerPrice=Number(req.body.customer_price);
  const technicianFee=Number(req.body.technician_fee);
  if(!Number.isInteger(customerPrice)||!Number.isInteger(technicianFee)||customerPrice<0||technicianFee<0)
    return res.status(400).json({error:'السعر والخصم يجب أن يكونا أرقامًا صحيحة غير سالبة'});
  const result=db.prepare("UPDATE orders SET customer_price=?,technician_fee=?,status='available' WHERE id=? AND status IN ('pending','available')")
    .run(customerPrice,technicianFee,id);
  if(!result.changes) return res.status(404).json({error:'الطلب غير موجود أو تم فتحه بالفعل'});
  res.json({ok:true});
});

app.get('/api/technician/orders',auth,role('technician'),(req,res)=>{
  if(!req.user.approved) return res.status(403).json({error:'الحساب في انتظار موافقة الأدمن'});
  res.json(db.prepare(`
    SELECT o.id,s.name service,o.area,o.customer_price,o.technician_fee,o.status
    FROM orders o JOIN services s ON s.id=o.service_id
    WHERE o.status='available' ORDER BY o.id DESC
  `).all());
});

app.get('/api/technician/balance',auth,role('technician'),(req,res)=>{
  res.json({balance:userById(req.user.id).balance});
});

app.post('/api/technician/orders/:id/open',auth,role('technician'),(req,res)=>{
  if(!req.user.approved) return res.status(403).json({error:'الحساب غير معتمد'});
  const orderId=Number(req.params.id);
  const order=db.prepare(`
    SELECT o.*,c.name customer_name,c.phone customer_phone,s.name service_name
    FROM orders o JOIN users c ON c.id=o.customer_id JOIN services s ON s.id=o.service_id
    WHERE o.id=? AND o.status='available'
  `).get(orderId);
  if(!order) return res.status(404).json({error:'الطلب غير متاح'});
  const fee=order.technician_fee;

  try {
    const result=db.transaction(()=>{
      const current=db.prepare('SELECT balance FROM users WHERE id=?').get(req.user.id);
      if(current.balance<fee) throw new Error('INSUFFICIENT');
      const newBalance=current.balance-fee;
      const updated=db.prepare("UPDATE users SET balance=? WHERE id=? AND balance>=?").run(newBalance,req.user.id,fee);
      if(!updated.changes) throw new Error
