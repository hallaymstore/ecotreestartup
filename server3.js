'use strict';

/**
 * EcoTreeSense — SIMPLE & DEPLOYABLE (Render-ready)
 * - No "setx"/"INMEMORY" hints
 * - Uses MongoDB Atlas ONLY (via env MONGODB_URI) or fallback URI if you really want
 * - Adds /api/health so you can test backend is alive
 * - Avoids Express v5 wildcard path errors (no app.get('*'))
 *
 * REQUIRED on Render:
 *   Environment Variable: MONGODB_URI = mongodb+srv://USER:PASSWORD@CLUSTER/ecotree?retryWrites=true&w=majority&appName=abumafia
 * OPTIONAL:
 *   DB_NAME=ecotreesense
 *   ADMIN_EMAIL=admin@example.com   (register with this email to become admin)
 *
 * Run locally:
 *   npm i express mongodb
 *   node server.js
 */

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');

// Load .env if present, but DO NOT require it (Render uses env vars)
try { require('dotenv').config(); } catch {}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.PORT || 3000);

// IMPORTANT: Use Atlas URI (Render env var). This fallback is only for local dev if you forget env var.
const MONGODB_URI = String(
  process.env.MONGODB_URI ||
  'mongodb+srv://abumafia0:abumafia0@abumafia.h1trttg.mongodb.net/ecotree?retryWrites=true&w=majority&appName=abumafia'
).trim();

const DB_NAME = String(process.env.DB_NAME || 'ecotreesense').trim();
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').toLowerCase().trim();

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

/** ---------- small utils ---------- **/
const nowISO = () => new Date().toISOString();
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
const safeLower = (s) => String(s || '').trim().toLowerCase();

function jsonErr(res, code, msg) {
  return res.status(code).json({ ok: false, error: msg });
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').map(v => v.trim()).filter(Boolean).forEach(pair => {
    const i = pair.indexOf('=');
    const k = i >= 0 ? pair.slice(0, i).trim() : pair.trim();
    const v = i >= 0 ? pair.slice(i + 1).trim() : '';
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || '/'}`);
  parts.push('HttpOnly');
  parts.push(`SameSite=${opts.sameSite || 'Lax'}`);
  // On Render it's HTTPS, so Secure is OK if behind proxy.
  // If you later enable proxy (app.set('trust proxy', 1)), you can set secure:true.
  if (opts.secure) parts.push('Secure');
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
}

function pbkdf2Hash(password, saltB64) {
  const salt = saltB64 ? Buffer.from(saltB64, 'base64') : crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256');
  return { salt: salt.toString('base64'), hash: key.toString('base64') };
}

function timingSafeEqB64(a, b) {
  try {
    const ba = Buffer.from(String(a || ''), 'base64');
    const bb = Buffer.from(String(b || ''), 'base64');
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

function makeId() {
  return crypto.randomBytes(24).toString('hex');
}

/** ---------- Mongo connection ---------- **/
let mongo = { ok: false, client: null, db: null };

async function ensureIndexes(db) {
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  await db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await db.collection('farms').createIndex({ ownerId: 1, createdAt: -1 });
  await db.collection('devices').createIndex({ ownerId: 1, createdAt: -1 });
  await db.collection('telemetry').createIndex({ ownerId: 1, deviceId: 1, createdAt: -1 });
  await db.collection('alerts').createIndex({ ownerId: 1, createdAt: -1 });
  await db.collection('audit').createIndex({ createdAt: -1 });
}

async function connectMongo() {
  // If you see ECONNREFUSED 127.0.0.1:27017, it means your MONGODB_URI is STILL local.
  // On Render: set env var MONGODB_URI properly.
  const client = new MongoClient(MONGODB_URI, {
    maxPoolSize: 20,
    serverSelectionTimeoutMS: 15000,
  });
  await client.connect();
  const db = client.db(DB_NAME);
  await ensureIndexes(db);
  mongo = { ok: true, client, db };
  console.log('✅ MongoDB connected. db:', DB_NAME);
}

/** ---------- Auth helpers ---------- **/
async function loadSession(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;

  const sess = await mongo.db.collection('sessions').findOne({ _id: sid });
  if (!sess || !sess.userId) return null;
  if (sess.expiresAt && new Date(sess.expiresAt) < new Date()) return null;

  const user = await mongo.db.collection('users').findOne({ _id: new ObjectId(sess.userId) });
  if (!user || user.disabled) return null;
  return { sid, user };
}

function requireAuth() {
  return async (req, res, next) => {
    try {
      const auth = await loadSession(req);
      if (!auth) return jsonErr(res, 401, 'Login required');
      req.auth = auth;
      next();
    } catch (e) { jsonErr(res, 500, e.message); }
  };
}

function requireAdmin() {
  return async (req, res, next) => {
    try {
      const auth = await loadSession(req);
      if (!auth) return jsonErr(res, 401, 'Login required');
      if (auth.user.role !== 'admin') return jsonErr(res, 403, 'Admin required');
      req.auth = auth;
      next();
    } catch (e) { jsonErr(res, 500, e.message); }
  };
}

async function audit(req, action, meta = {}) {
  try {
    const actorId = req.auth?.user?._id ? String(req.auth.user._id) : null;
    await mongo.db.collection('audit').insertOne({
      actorId, action, meta,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '',
      ua: req.headers['user-agent'] || '',
      createdAt: nowISO()
    });
  } catch {}
}

/** ---------- Health check (for Render + browser tests) ---------- **/
app.get('/api/health', async (req, res) => {
  res.json({
    ok: true,
    db: mongo.ok ? 'connected' : 'not_connected',
    time: nowISO()
  });
});

/** ---------- AUTH API ---------- **/
app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, password, phone } = req.body || {};
  const em = safeLower(email);

  if (!fullName || !em || !password) return jsonErr(res, 400, 'fullName, email, password required');
  if (String(password).length < 6) return jsonErr(res, 400, 'Password min 6');

  try {
    const existing = await mongo.db.collection('users').findOne({ email: em });
    if (existing) return jsonErr(res, 409, 'Email already exists');

    const { salt, hash } = pbkdf2Hash(password);
    const role = (ADMIN_EMAIL && em === ADMIN_EMAIL) ? 'admin' : 'user';

    const userDoc = {
      fullName: String(fullName).trim(),
      email: em,
      phone: String(phone || '').trim(),
      role,
      disabled: false,
      createdAt: nowISO(),
      passSalt: salt,
      passHash: hash
    };
    const r = await mongo.db.collection('users').insertOne(userDoc);

    const sid = makeId();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 14).toISOString();
    await mongo.db.collection('sessions').insertOne({ _id: sid, userId: String(r.insertedId), createdAt: nowISO(), expiresAt });

    setCookie(res, 'sid', sid, { sameSite: 'Lax', path: '/' });
    res.json({ ok: true, user: { id: String(r.insertedId), fullName: userDoc.fullName, email: userDoc.email, role: userDoc.role } });
  } catch (e) {
    if (String(e.message || '').includes('E11000')) return jsonErr(res, 409, 'Email already exists');
    jsonErr(res, 500, e.message);
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const em = safeLower(email);
  if (!em || !password) return jsonErr(res, 400, 'email, password required');

  try {
    const user = await mongo.db.collection('users').findOne({ email: em });
    if (!user || user.disabled) return jsonErr(res, 401, 'Invalid credentials');

    const { hash } = pbkdf2Hash(password, user.passSalt);
    if (!timingSafeEqB64(hash, user.passHash)) return jsonErr(res, 401, 'Invalid credentials');

    const sid = makeId();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 14).toISOString();
    await mongo.db.collection('sessions').insertOne({ _id: sid, userId: String(user._id), createdAt: nowISO(), expiresAt });

    setCookie(res, 'sid', sid, { sameSite: 'Lax', path: '/' });
    res.json({ ok: true, user: { id: String(user._id), fullName: user.fullName, email: user.email, role: user.role } });
  } catch (e) { jsonErr(res, 500, e.message); }
});

app.post('/api/auth/logout', requireAuth(), async (req, res) => {
  try {
    await mongo.db.collection('sessions').deleteOne({ _id: req.auth.sid });
    clearCookie(res, 'sid');
    res.json({ ok: true });
  } catch (e) { jsonErr(res, 500, e.message); }
});

app.get('/api/auth/me', async (req, res) => {
  try {
    const auth = await loadSession(req);
    if (!auth) return res.json({ ok: true, user: null });
    const u = auth.user;
    res.json({ ok: true, user: { id: String(u._id), fullName: u.fullName, email: u.email, phone: u.phone || '', role: u.role } });
  } catch (e) { jsonErr(res, 500, e.message); }
});

/** ---------- USER: Farms & Devices ---------- **/
app.get('/api/my/farms', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const farms = await mongo.db.collection('farms').find({ ownerId }).sort({ createdAt: -1 }).toArray();
  res.json({ ok: true, farms });
});

app.get('/api/my/devices', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const devices = await mongo.db.collection('devices').find({ ownerId }).sort({ createdAt: -1 }).toArray();
  res.json({ ok: true, devices });
});

app.post('/api/my/farms', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const { name, location, areaM2, crop, notes } = req.body || {};
  if (!name) return jsonErr(res, 400, 'name required');

  const doc = {
    ownerId,
    name: String(name).trim(),
    location: String(location || '').trim(),
    areaM2: clamp(Number(areaM2 || 0), 0, 1e9),
    crop: String(crop || '').trim(),
    notes: String(notes || '').trim(),
    createdAt: nowISO()
  };
  const r = await mongo.db.collection('farms').insertOne(doc);
  await audit(req, 'farm.create', { farmId: String(r.insertedId) });
  res.json({ ok: true, farm: { _id: String(r.insertedId), ...doc } });
});

app.post('/api/my/devices', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const { name, farmId, motorFlowLpm, motorPowerW, sensors = [], controller = 'ESP32', notes = '' } = req.body || {};
  if (!name) return jsonErr(res, 400, 'name required');

  let farmObjId = null;
  if (farmId) {
    try { farmObjId = new ObjectId(String(farmId)); } catch { return jsonErr(res, 400, 'invalid farmId'); }
    const farm = await mongo.db.collection('farms').findOne({ _id: farmObjId, ownerId });
    if (!farm) return jsonErr(res, 404, 'farm not found');
  }

  const doc = {
    ownerId,
    farmId: farmObjId ? String(farmObjId) : null,
    name: String(name).trim(),
    controller: String(controller || 'ESP32').trim(),
    sensors: Array.isArray(sensors) ? sensors.map(s => String(s).trim()).filter(Boolean).slice(0, 20) : [],
    motorFlowLpm: clamp(Number(motorFlowLpm || 0), 0, 1e6),
    motorPowerW: clamp(Number(motorPowerW || 0), 0, 1e6),
    pump: 'off',
    disabled: false,
    deviceKey: crypto.randomBytes(24).toString('hex'),
    notes: String(notes || '').trim(),
    createdAt: nowISO(),
    lastSeenAt: null
  };

  const r = await mongo.db.collection('devices').insertOne(doc);
  await audit(req, 'device.create', { deviceId: String(r.insertedId) });
  res.json({ ok: true, device: { _id: String(r.insertedId), ...doc } });
});

app.delete('/api/my/farms/:id', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const id = String(req.params.id);
  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }

  await mongo.db.collection('devices').updateMany({ ownerId, farmId: id }, { $set: { farmId: null } });
  const r = await mongo.db.collection('farms').deleteOne({ _id, ownerId });
  await audit(req, 'farm.delete', { farmId: id });
  res.json({ ok: true, deleted: r.deletedCount });
});

app.delete('/api/my/devices/:id', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const id = String(req.params.id);
  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }

  await mongo.db.collection('telemetry').deleteMany({ deviceId: id, ownerId });
  const r = await mongo.db.collection('devices').deleteOne({ _id, ownerId });
  await audit(req, 'device.delete', { deviceId: id });
  res.json({ ok: true, deleted: r.deletedCount });
});

app.post('/api/my/devices/:id/pump', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const id = String(req.params.id);
  const { state } = req.body || {};
  if (!['on', 'off'].includes(String(state))) return jsonErr(res, 400, 'state must be on|off');

  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }
  const device = await mongo.db.collection('devices').findOne({ _id, ownerId });
  if (!device) return jsonErr(res, 404, 'device not found');
  if (device.disabled) return jsonErr(res, 403, 'device disabled');

  await mongo.db.collection('devices').updateOne({ _id }, { $set: { pump: state, lastSeenAt: nowISO() } });
  await mongo.db.collection('alerts').insertOne({ ownerId, deviceId: id, type: 'pump', message: `Pump ${String(state).toUpperCase()} (manual)`, createdAt: nowISO() });
  await audit(req, 'pump.user', { deviceId: id, state });

  res.json({ ok: true });
});

/** ---------- Device telemetry ---------- **/
app.post('/api/device/telemetry', async (req, res) => {
  const { deviceId, soilMoisture, battery, flowLpm, pressureKpa, tempC, humidityPct } = req.body || {};
  const dk = String(req.header('x-device-key') || '');
  if (!deviceId || !dk) return jsonErr(res, 400, 'deviceId and x-device-key required');

  let _id; try { _id = new ObjectId(String(deviceId)); } catch { return jsonErr(res, 400, 'invalid deviceId'); }
  const dev = await mongo.db.collection('devices').findOne({ _id });
  if (!dev) return jsonErr(res, 404, 'device not found');
  if (dev.disabled) return jsonErr(res, 403, 'device disabled');
  if (dk !== dev.deviceKey) return jsonErr(res, 401, 'invalid device key');

  const ownerId = String(dev.ownerId);
  const doc = {
    ownerId,
    deviceId: String(_id),
    soilMoisture: clamp(Number(soilMoisture ?? 0), 0, 100),
    battery: clamp(Number(battery ?? 100), 0, 100),
    flowLpm: clamp(Number(flowLpm ?? 0), 0, 1e6),
    pressureKpa: clamp(Number(pressureKpa ?? 0), 0, 1e6),
    tempC: clamp(Number(tempC ?? 0), -50, 80),
    humidityPct: clamp(Number(humidityPct ?? 0), 0, 100),
    pump: dev.pump || 'off',
    createdAt: nowISO()
  };

  await mongo.db.collection('telemetry').insertOne(doc);
  await mongo.db.collection('devices').updateOne({ _id }, { $set: { lastSeenAt: nowISO() } });
  res.json({ ok: true });
});

app.get('/api/my/telemetry', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const deviceId = String(req.query.deviceId || '');
  const limit = clamp(Number(req.query.limit || 50), 1, 500);
  if (!deviceId) return jsonErr(res, 400, 'deviceId required');

  const dev = await mongo.db.collection('devices').findOne({ _id: new ObjectId(deviceId), ownerId });
  if (!dev) return jsonErr(res, 404, 'device not found');

  const items = await mongo.db.collection('telemetry')
    .find({ ownerId, deviceId })
    .sort({ createdAt: -1 })
    .limit(limit)
    .toArray();

  res.json({ ok: true, telemetry: items });
});

/** ---------- ADMIN (minimal) ---------- **/
app.get('/api/admin/users', requireAdmin(), async (req, res) => {
  const users = await mongo.db.collection('users')
    .find({})
    .project({ passSalt: 0, passHash: 0 })
    .sort({ createdAt: -1 })
    .toArray();

  res.json({ ok: true, users });
});

app.get('/api/admin/user/:id', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }

  const user = await mongo.db.collection('users').findOne({ _id }, { projection: { passSalt: 0, passHash: 0 } });
  if (!user) return jsonErr(res, 404, 'user not found');

  const ownerId = String(_id);
  const farms = await mongo.db.collection('farms').find({ ownerId }).sort({ createdAt: -1 }).toArray();
  const devices = await mongo.db.collection('devices').find({ ownerId }).sort({ createdAt: -1 }).toArray();

  res.json({ ok: true, user, farms, devices });
});

app.post('/api/admin/device/:id/disable', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  const { disabled } = req.body || {};
  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }

  const r = await mongo.db.collection('devices').updateOne({ _id }, { $set: { disabled: !!disabled } });
  await audit(req, 'admin.device.disable', { deviceId: id, disabled: !!disabled });
  res.json({ ok: true, modified: r.modifiedCount });
});

/** ---------- API 404 guard (helps debugging) ---------- **/
app.use('/api', (req, res) => {
  return jsonErr(res, 404, `No API route: ${req.method} ${req.originalUrl}`);
});

/** ---------- Start ---------- **/
(async () => {
  try {
    await connectMongo();
    app.listen(PORT, () => console.log(`🚀 EcoTreeSense running on :${PORT}`));
  } catch (e) {
    console.error('❌ Startup error:', e.message);
    console.error('➡️ Renderda hal qilish: Settings -> Environment -> MONGODB_URI ni Atlas URI qilib qo‘ying (localhost emas).');
    process.exit(1);
  }
})();
