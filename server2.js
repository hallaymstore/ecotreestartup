'use strict';
/**
 * EcoTreeSense — Online Real MVP (roles + farms + devices + admin)
 *
 * ✅ FIX for your error:
 *   ECONNREFUSED 127.0.0.1:27017 means MongoDB is NOT running locally,
 *   or you are pointing to localhost without a running mongod service.
 *
 * Two correct options:
 *   A) Use local MongoDB:
 *      - Install MongoDB Community Server
 *      - Start service (Windows: Services -> "MongoDB Server" -> Start)
 *      - Keep MONGODB_URI=mongodb://127.0.0.1:27017
 *
 *   B) Use MongoDB Atlas (recommended if you don't want local Mongo):
 *      setx MONGODB_URI "mongodb+srv://<USER>:<PASS>@<CLUSTER>/<DB>?retryWrites=true&w=majority"
 *
 * Optional (so it NEVER crashes on startup):
 *   - Set INMEMORY=1 to run without MongoDB (data resets on restart)
 *     setx INMEMORY "1"
 *
 * Install:
 *   npm i express mongodb
 */

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = String(process.env.MONGODB_URI || 'mongodb+srv://abumafia0:abumafia0@abumafia.h1trttg.mongodb.net/ecotree?appName=abumafia').trim();
const EXPLICIT_DB_NAME = (process.env.DB_NAME != null && String(process.env.DB_NAME).trim() !== '') ? String(process.env.DB_NAME).trim() : '';
function inferDbNameFromUri(uri) {
  // Works for mongodb:// and mongodb+srv://
  // Examples:
  //  mongodb+srv://u:p@cluster.mongodb.net/ecotree?retryWrites=true&w=majority
  //  mongodb://127.0.0.1:27017/ecotree
  try {
    const m = String(uri || '').match(/\/([^\/\?\#]+)(?:[\?\#]|$)/);
    if (!m) return '';
    const name = m[1];
    // If someone passes just "/" (rare), ignore:
    if (!name || name.includes('@') || name.includes(':')) return '';
    return name;
  } catch { return ''; }
}
const INFERRED_DB_NAME = inferDbNameFromUri(MONGODB_URI);
const DB_NAME = (EXPLICIT_DB_NAME || INFERRED_DB_NAME || 'ecotreesense').trim();
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').toLowerCase().trim();
const INMEMORY = String(process.env.INMEMORY || '').trim() === '1';

const PUBLIC_DIR = path.join(__dirname, 'public');
app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

const nowISO = () => new Date().toISOString();
const clamp = (n, a, b) => Math.max(a, Math.min(b, n));
const safeLower = (s) => String(s || '').trim().toLowerCase();
function jsonErr(res, code, msg) { return res.status(code).json({ error: msg }); }

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
function makeId() { return crypto.randomBytes(24).toString('hex'); }

/** In-memory DB adapter (minimal Mongo-like) */
function makeMemDB() {
  const cols = new Map();
  const getCol = (name) => {
    if (!cols.has(name)) cols.set(name, []);
    return cols.get(name);
  };
  const match = (doc, query) => {
    if (!query || Object.keys(query).length === 0) return true;
    for (const [k, v] of Object.entries(query)) {
      if (k === '_id' && v && typeof v === 'object' && v._bsontype === 'ObjectID') {
        if (String(doc._id) !== String(v)) return false;
      } else {
        if (doc[k] !== v) return false;
      }
    }
    return true;
  };
  const projectDoc = (doc, projection) => {
    if (!projection) return doc;
    const out = { ...doc };
    for (const [k, val] of Object.entries(projection)) {
      if (val === 0) delete out[k];
    }
    return out;
  };

  const collection = (name) => ({
    async createIndex(){ /* noop */ },
    async insertOne(doc){
      const d = { ...doc };
      if (!d._id) d._id = new ObjectId();
      getCol(name).push(d);
      return { insertedId: d._id };
    },
    async findOne(query, opts={}){
      const found = getCol(name).find(d => match(d, query));
      return found ? projectDoc(found, opts.projection) : null;
    },
    find(query){
      let arr = getCol(name).filter(d => match(d, query));
      const chain = {
        sort(sortObj){
          const [[k, dir]] = Object.entries(sortObj || { createdAt: -1 });
          arr = arr.slice().sort((a,b) => {
            const av = a[k]; const bv = b[k];
            if (av === bv) return 0;
            return (av > bv ? 1 : -1) * (dir < 0 ? -1 : 1);
          });
          return chain;
        },
        limit(n){ arr = arr.slice(0, n); return chain; },
        project(proj){ arr = arr.map(d => projectDoc(d, proj)); return chain; },
        async toArray(){ return arr; }
      };
      return chain;
    },
    async updateOne(query, update){
      const arr = getCol(name);
      const i = arr.findIndex(d => match(d, query));
      if (i < 0) return { matchedCount: 0, modifiedCount: 0 };
      if (update && update.$set) arr[i] = { ...arr[i], ...update.$set };
      return { matchedCount: 1, modifiedCount: 1 };
    },
    async updateMany(query, update){
      const arr = getCol(name);
      let mod = 0;
      for (let i=0;i<arr.length;i++){
        if (match(arr[i], query)){
          if (update && update.$set) arr[i] = { ...arr[i], ...update.$set };
          mod++;
        }
      }
      return { matchedCount: mod, modifiedCount: mod };
    },
    async deleteOne(query){
      const arr = getCol(name);
      const i = arr.findIndex(d => match(d, query));
      if (i < 0) return { deletedCount: 0 };
      arr.splice(i,1);
      return { deletedCount: 1 };
    },
    async deleteMany(query){
      const arr = getCol(name);
      const before = arr.length;
      const kept = arr.filter(d => !match(d, query));
      cols.set(name, kept);
      return { deletedCount: before - kept.length };
    }
  });

  return {
    collection,
    db: { collection },
    close(){},
  };
}

/** Mongo */
let mongo = { ok: false, client: null, db: null };

async function ensureIndexes(db) {
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  await db.collection('sessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await db.collection('farms').createIndex({ ownerId: 1, createdAt: -1 });
  await db.collection('devices').createIndex({ ownerId: 1, createdAt: -1 });
  await db.collection('telemetry').createIndex({ deviceId: 1, createdAt: -1 });
  await db.collection('audit').createIndex({ createdAt: -1 });
  await db.collection('alerts').createIndex({ ownerId: 1, createdAt: -1 });
}

async function connectMongoWithRetry() {
  if (INMEMORY) {
    const mem = makeMemDB();
    mongo = { ok: true, client: mem, db: mem.db };
    await ensureIndexes(mongo.db);
    console.log('🟡 INMEMORY=1: running without MongoDB (data resets on restart).');
    return;
  }

  const maxAttempts = 3;
  let lastErr = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const client = new MongoClient(MONGODB_URI, { maxPoolSize: 20, serverSelectionTimeoutMS: 5000 });
      await client.connect();
      const db = client.db(DB_NAME);
      mongo = { ok: true, client, db };
      await ensureIndexes(db);
      console.log('✅ MongoDB connected:', MONGODB_URI, 'db:', DB_NAME);
      return;
    } catch (e) {
      lastErr = e;
      console.log(`⚠️ Mongo attempt ${attempt}/${maxAttempts} failed: ${e.message}`);
      await new Promise(r => setTimeout(r, 1200));
    }
  }

  // Better error help:
  const hint = (MONGODB_URI.includes('127.0.0.1') || MONGODB_URI.includes('localhost'))
    ? `MongoDB local ishlamayapti. Windows'da Services -> "MongoDB Server" ni Start qiling yoki Atlas URI qo'ying.`
    : `MongoDB Atlas bo'lsa: Database Access (user/pass), Network Access (IP whitelist 0.0.0.0/0 yoki sizning IP), va URI'dagi DB nomi to'g'ri ekanini tekshiring.`;
  const msg = `${lastErr?.message || 'Mongo connect failed'} | ${hint} | Agar hozircha Mongo'siz ishlasin desangiz: setx INMEMORY "1"`;
  throw new Error(msg);
}

/** Auth */
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
      req.auth = await loadSession(req);
      if (!req.auth) return jsonErr(res, 401, 'Login required');
      next();
    } catch (e) { jsonErr(res, 500, e.message); }
  };
}
function requireAdmin() {
  return async (req, res, next) => {
    try {
      req.auth = req.auth || await loadSession(req);
      if (!req.auth) return jsonErr(res, 401, 'Login required');
      if (req.auth.user.role !== 'admin') return jsonErr(res, 403, 'Admin required');
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

/** SSE */
const sseClients = new Map(); // ownerId -> Set(res)
function sseAdd(ownerId, res) {
  const k = String(ownerId);
  if (!sseClients.has(k)) sseClients.set(k, new Set());
  sseClients.get(k).add(res);
}
function sseRemove(ownerId, res) {
  const k = String(ownerId);
  const set = sseClients.get(k);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) sseClients.delete(k);
}
function sseSendUser(ownerId, evt, data) {
  const set = sseClients.get(String(ownerId));
  if (!set) return;
  const payload = `event: ${evt}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of set) { try { res.write(payload); } catch {} }
}

/** Helpers */
function calcIrrigation(areaM2, mmTarget, motorFlowLpm) {
  const litersNeeded = Math.max(0, Number(areaM2 || 0)) * Math.max(0, Number(mmTarget || 0));
  const flow = Math.max(1, Number(motorFlowLpm || 1));
  const minutes = litersNeeded / flow;
  return { litersNeeded: Math.round(litersNeeded), minutes: Math.round(minutes), hours: +(minutes / 60).toFixed(2) };
}

/** AUTH API */
app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, password, phone } = req.body || {};
  const em = safeLower(email);
  if (!fullName || !em || !password) return jsonErr(res, 400, 'fullName, email, password required');
  if (String(password).length < 6) return jsonErr(res, 400, 'Password min 6');

  try {
    // Unique email check for INMEMORY too:
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
    if (!auth) return res.json({ user: null });
    const u = auth.user;
    res.json({ user: { id: String(u._id), fullName: u.fullName, email: u.email, phone: u.phone || '', role: u.role } });
  } catch (e) { jsonErr(res, 500, e.message); }
});

/** USER: Farms & Devices */
app.get('/api/my/farms', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const farms = await mongo.db.collection('farms').find({ ownerId }).sort({ createdAt: -1 }).toArray();
  res.json({ farms });
});

app.get('/api/my/devices', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const devices = await mongo.db.collection('devices').find({ ownerId }).sort({ createdAt: -1 }).toArray();
  res.json({ devices });
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

  await mongo.db.collection('telemetry').deleteMany({ deviceId: id });
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

  sseSendUser(ownerId, 'pump', { deviceId: id, state, at: nowISO() });
  res.json({ ok: true });
});

/** Device telemetry */
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
  sseSendUser(ownerId, 'telemetry', doc);
  res.json({ ok: true });
});

app.get('/api/my/telemetry', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const deviceId = String(req.query.deviceId || '');
  const limit = clamp(Number(req.query.limit || 50), 1, 500);
  if (!deviceId) return jsonErr(res, 400, 'deviceId required');

  const dev = await mongo.db.collection('devices').findOne({ _id: new ObjectId(deviceId), ownerId });
  if (!dev) return jsonErr(res, 404, 'device not found');

  const items = await mongo.db.collection('telemetry').find({ ownerId, deviceId }).sort({ createdAt: -1 }).limit(limit).toArray();
  res.json({ telemetry: items });
});

app.post('/api/my/devices/:id/simulate', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  const id = String(req.params.id);
  const dev = await mongo.db.collection('devices').findOne({ _id: new ObjectId(id), ownerId });
  if (!dev) return jsonErr(res, 404, 'device not found');
  if (dev.disabled) return jsonErr(res, 403, 'device disabled');

  const last = await mongo.db.collection('telemetry').find({ ownerId, deviceId: id }).sort({ createdAt: -1 }).limit(1).toArray();
  const baseSm = last[0]?.soilMoisture ?? 45;
  const drift = (dev.pump === 'on') ? (Math.random() * 4 + 2) : -(Math.random() * 4 + 1);
  const sm = clamp(Math.round(baseSm + drift), 0, 100);

  const doc = {
    ownerId, deviceId: id,
    soilMoisture: sm,
    battery: clamp(Math.round((last[0]?.battery ?? 90) + (Math.random() * 2 - 1)), 0, 100),
    flowLpm: clamp(Math.round((dev.pump === 'on' ? (dev.motorFlowLpm || 100) : 0)), 0, 1e6),
    pressureKpa: clamp(Math.round(dev.pump === 'on' ? 180 + Math.random() * 30 : 0), 0, 1e6),
    tempC: clamp(Math.round(18 + Math.random() * 10), -50, 80),
    humidityPct: clamp(Math.round(40 + Math.random() * 40), 0, 100),
    pump: dev.pump || 'off',
    createdAt: nowISO()
  };

  await mongo.db.collection('telemetry').insertOne(doc);
  await mongo.db.collection('devices').updateOne({ _id: new ObjectId(id) }, { $set: { lastSeenAt: nowISO() } });
  sseSendUser(ownerId, 'telemetry', doc);
  res.json({ ok: true, telemetry: doc });
});

app.post('/api/my/calc/irrigation', requireAuth(), async (req, res) => {
  const { areaM2, mmTarget, motorFlowLpm } = req.body || {};
  res.json({ ok: true, ...calcIrrigation(areaM2, mmTarget, motorFlowLpm) });
});

/** SSE stream */
app.get('/api/my/stream', requireAuth(), async (req, res) => {
  const ownerId = String(req.auth.user._id);
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  res.write(`event: hello\ndata: ${JSON.stringify({ time: nowISO(), userId: ownerId })}\n\n`);
  sseAdd(ownerId, res);
  req.on('close', () => sseRemove(ownerId, res));
});

/** ADMIN API */
app.get('/api/admin/users', requireAdmin(), async (req, res) => {
  const users = await mongo.db.collection('users').find({}).project({ passHash: 0, passSalt: 0 }).sort({ createdAt: -1 }).toArray();
  res.json({ users });
});

app.get('/api/admin/user/:id', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }

  const user = await mongo.db.collection('users').findOne({ _id }, { projection: { passHash: 0, passSalt: 0 } });
  if (!user) return jsonErr(res, 404, 'not found');

  const ownerId = id;
  const farms = await mongo.db.collection('farms').find({ ownerId }).sort({ createdAt: -1 }).toArray();
  const devices = await mongo.db.collection('devices').find({ ownerId }).sort({ createdAt: -1 }).toArray();
  res.json({ user, farms, devices });
});

app.post('/api/admin/user/:id/toggle', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  const { disabled } = req.body || {};
  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }

  await mongo.db.collection('users').updateOne({ _id }, { $set: { disabled: !!disabled } });
  if (disabled) {
    await mongo.db.collection('sessions').deleteMany({ userId: id });
    await mongo.db.collection('devices').updateMany({ ownerId: id }, { $set: { disabled: true } });
  }
  await audit(req, 'admin.user.toggle', { userId: id, disabled: !!disabled });
  res.json({ ok: true });
});

app.delete('/api/admin/user/:id', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }

  await mongo.db.collection('sessions').deleteMany({ userId: id });
  await mongo.db.collection('farms').deleteMany({ ownerId: id });
  await mongo.db.collection('devices').deleteMany({ ownerId: id });
  await mongo.db.collection('telemetry').deleteMany({ ownerId: id });
  const r = await mongo.db.collection('users').deleteOne({ _id });
  await audit(req, 'admin.user.delete', { userId: id });
  res.json({ ok: true, deleted: r.deletedCount });
});

app.post('/api/admin/device/:id/toggle', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  const { disabled } = req.body || {};
  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }

  await mongo.db.collection('devices').updateOne({ _id }, { $set: { disabled: !!disabled } });
  await audit(req, 'admin.device.toggle', { deviceId: id, disabled: !!disabled });
  res.json({ ok: true });
});

app.delete('/api/admin/device/:id', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  let _id; try { _id = new ObjectId(id); } catch { return jsonErr(res, 400, 'invalid id'); }

  await mongo.db.collection('telemetry').deleteMany({ deviceId: id });
  const r = await mongo.db.collection('devices').deleteOne({ _id });
  await audit(req, 'admin.device.delete', { deviceId: id });
  res.json({ ok: true, deleted: r.deletedCount });
});

app.get('/api/admin/audit', requireAdmin(), async (req, res) => {
  const limit = clamp(Number(req.query.limit || 100), 1, 500);
  const items = await mongo.db.collection('audit').find({}).sort({ createdAt: -1 }).limit(limit).toArray();
  res.json({ audit: items });
});

/** Pages */
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));
/** Express 5 compatible fallback (no '*' route) */
app.use((req, res) => res.status(404).sendFile(path.join(PUBLIC_DIR, 'index.html')));

/** Start */
(async () => {
  try {
    await connectMongoWithRetry();
    app.listen(PORT, () => console.log(`🚀 EcoTreeSense running: http://localhost:${PORT}`));
  } catch (e) {
    console.error('❌ Startup error:', e.message);
    process.exit(1);
  }
})();
