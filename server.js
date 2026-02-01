'use strict';
/**
 * EcoTreeSense (mongoose version) — same features, SIMPLE Atlas connect
 *
 * Install:
 *   npm i express mongoose dotenv
 *
 * Run (PowerShell, same terminal):
 *   $env:MONGODB_URI="mongodb+srv://USER:PASS@abumafia.h1trttg.mongodb.net/ecotree?retryWrites=true&w=majority&appName=abumafia"
 *   $env:ADMIN_EMAIL="admin@example.com"
 *   node server.js
 *
 * NOTE:
 * - Do NOT hardcode your real password in code. Put it in MONGODB_URI env.
 * - If Atlas refuses connection: Atlas -> Network Access -> add 0.0.0.0/0 (temporary) OR your IP.
 */

require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.PORT || 3000);
const MONGODB_URI = String(process.env.MONGODB_URI || 'mongodb+srv://abumafia0:abumafia0@abumafia.h1trttg.mongodb.net/ecotree?appName=abumafia').trim();
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').toLowerCase().trim();

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

/** ====== Schemas ====== */
const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, default: '', trim: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  disabled: { type: Boolean, default: false },
  passSalt: { type: String, required: true },
  passHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const SessionSchema = new mongoose.Schema({
  _id: { type: String },              // sid
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true, index: true }
}, { versionKey: false });

const FarmSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  name: { type: String, required: true, trim: true },
  location: { type: String, default: '', trim: true },
  areaM2: { type: Number, default: 0 },
  crop: { type: String, default: '', trim: true },
  notes: { type: String, default: '', trim: true },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const DeviceSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  farmId: { type: mongoose.Schema.Types.ObjectId, default: null, index: true },
  name: { type: String, required: true, trim: true },
  controller: { type: String, default: 'ESP32', trim: true },
  sensors: { type: [String], default: [] },
  motorFlowLpm: { type: Number, default: 0 },
  motorPowerW: { type: Number, default: 0 },
  pump: { type: String, enum: ['on', 'off'], default: 'off' },
  disabled: { type: Boolean, default: false },
  deviceKey: { type: String, required: true, index: true },
  notes: { type: String, default: '', trim: true },
  lastSeenAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
}, { versionKey: false });

const TelemetrySchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  deviceId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  soilMoisture: { type: Number, default: 0 },
  battery: { type: Number, default: 100 },
  flowLpm: { type: Number, default: 0 },
  pressureKpa: { type: Number, default: 0 },
  tempC: { type: Number, default: 0 },
  humidityPct: { type: Number, default: 0 },
  pump: { type: String, enum: ['on', 'off'], default: 'off' },
  createdAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });

const AuditSchema = new mongoose.Schema({
  actorId: { type: mongoose.Schema.Types.ObjectId, default: null, index: true },
  action: { type: String, required: true },
  meta: { type: Object, default: {} },
  ip: { type: String, default: '' },
  ua: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });

const AlertSchema = new mongoose.Schema({
  ownerId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  deviceId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  type: { type: String, default: '' },
  message: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now, index: true }
}, { versionKey: false });

/** TTL: sessions auto delete after expiresAt */
SessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', UserSchema);
const Session = mongoose.model('Session', SessionSchema);
const Farm = mongoose.model('Farm', FarmSchema);
const Device = mongoose.model('Device', DeviceSchema);
const Telemetry = mongoose.model('Telemetry', TelemetrySchema);
const Audit = mongoose.model('Audit', AuditSchema);
const Alert = mongoose.model('Alert', AlertSchema);

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

/** Auth */
async function loadSession(req) {
  const sid = parseCookies(req).sid;
  if (!sid) return null;

  const sess = await Session.findById(sid).lean();
  if (!sess || !sess.userId) return null;
  if (sess.expiresAt && new Date(sess.expiresAt) < new Date()) return null;

  const user = await User.findById(sess.userId).lean();
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
    const actorId = req.auth?.user?._id || null;
    await Audit.create({
      actorId,
      action,
      meta,
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '',
      ua: req.headers['user-agent'] || '',
      createdAt: new Date()
    });
  } catch {}
}

/** ====== AUTH API ====== */
app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, password, phone } = req.body || {};
  const em = safeLower(email);
  if (!fullName || !em || !password) return jsonErr(res, 400, 'fullName, email, password required');
  if (String(password).length < 6) return jsonErr(res, 400, 'Password min 6');

  try {
    const existing = await User.findOne({ email: em }).lean();
    if (existing) return jsonErr(res, 409, 'Email already exists');

    const { salt, hash } = pbkdf2Hash(password);
    const role = (ADMIN_EMAIL && em === ADMIN_EMAIL) ? 'admin' : 'user';

    const user = await User.create({
      fullName: String(fullName).trim(),
      email: em,
      phone: String(phone || '').trim(),
      role,
      disabled: false,
      passSalt: salt,
      passHash: hash,
      createdAt: new Date()
    });

    const sid = makeId();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 14);
    await Session.create({ _id: sid, userId: user._id, createdAt: new Date(), expiresAt });

    setCookie(res, 'sid', sid, { sameSite: 'Lax', path: '/' });
    res.json({ ok: true, user: { id: String(user._id), fullName: user.fullName, email: user.email, role: user.role } });
  } catch (e) {
    // mongoose unique index error
    if (String(e.code) === '11000') return jsonErr(res, 409, 'Email already exists');
    jsonErr(res, 500, e.message);
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const em = safeLower(email);
  if (!em || !password) return jsonErr(res, 400, 'email, password required');

  try {
    const user = await User.findOne({ email: em }).lean();
    if (!user || user.disabled) return jsonErr(res, 401, 'Invalid credentials');

    const { hash } = pbkdf2Hash(password, user.passSalt);
    if (!timingSafeEqB64(hash, user.passHash)) return jsonErr(res, 401, 'Invalid credentials');

    const sid = makeId();
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 14);
    await Session.create({ _id: sid, userId: user._id, createdAt: new Date(), expiresAt });

    setCookie(res, 'sid', sid, { sameSite: 'Lax', path: '/' });
    res.json({ ok: true, user: { id: String(user._id), fullName: user.fullName, email: user.email, role: user.role } });
  } catch (e) { jsonErr(res, 500, e.message); }
});

app.post('/api/auth/logout', requireAuth(), async (req, res) => {
  try {
    await Session.deleteOne({ _id: req.auth.sid });
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

/** ====== USER: Farms & Devices ====== */
app.get('/api/my/farms', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  const farms = await Farm.find({ ownerId }).sort({ createdAt: -1 }).lean();
  res.json({ farms });
});

app.get('/api/my/devices', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  const devices = await Device.find({ ownerId }).sort({ createdAt: -1 }).lean();
  res.json({ devices });
});

app.post('/api/my/farms', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  const { name, location, areaM2, crop, notes } = req.body || {};
  if (!name) return jsonErr(res, 400, 'name required');

  const farm = await Farm.create({
    ownerId,
    name: String(name).trim(),
    location: String(location || '').trim(),
    areaM2: clamp(Number(areaM2 || 0), 0, 1e9),
    crop: String(crop || '').trim(),
    notes: String(notes || '').trim(),
    createdAt: new Date()
  });

  await audit(req, 'farm.create', { farmId: String(farm._id) });
  res.json({ ok: true, farm });
});

app.post('/api/my/devices', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  const { name, farmId, motorFlowLpm, motorPowerW, sensors = [], controller = 'ESP32', notes = '' } = req.body || {};
  if (!name) return jsonErr(res, 400, 'name required');

  let farmObjId = null;
  if (farmId) {
    if (!mongoose.isValidObjectId(farmId)) return jsonErr(res, 400, 'invalid farmId');
    farmObjId = new mongoose.Types.ObjectId(farmId);
    const farm = await Farm.findOne({ _id: farmObjId, ownerId }).lean();
    if (!farm) return jsonErr(res, 404, 'farm not found');
  }

  const device = await Device.create({
    ownerId,
    farmId: farmObjId,
    name: String(name).trim(),
    controller: String(controller || 'ESP32').trim(),
    sensors: Array.isArray(sensors) ? sensors.map(s => String(s).trim()).filter(Boolean).slice(0, 20) : [],
    motorFlowLpm: clamp(Number(motorFlowLpm || 0), 0, 1e6),
    motorPowerW: clamp(Number(motorPowerW || 0), 0, 1e6),
    pump: 'off',
    disabled: false,
    deviceKey: crypto.randomBytes(24).toString('hex'),
    notes: String(notes || '').trim(),
    createdAt: new Date(),
    lastSeenAt: null
  });

  await audit(req, 'device.create', { deviceId: String(device._id) });
  res.json({ ok: true, device });
});

app.delete('/api/my/farms/:id', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  const id = String(req.params.id);
  if (!mongoose.isValidObjectId(id)) return jsonErr(res, 400, 'invalid id');

  await Device.updateMany({ ownerId, farmId: id }, { $set: { farmId: null } });
  const r = await Farm.deleteOne({ _id: id, ownerId });
  await audit(req, 'farm.delete', { farmId: id });
  res.json({ ok: true, deleted: r.deletedCount || 0 });
});

app.delete('/api/my/devices/:id', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  const id = String(req.params.id);
  if (!mongoose.isValidObjectId(id)) return jsonErr(res, 400, 'invalid id');

  await Telemetry.deleteMany({ deviceId: id, ownerId });
  const r = await Device.deleteOne({ _id: id, ownerId });
  await audit(req, 'device.delete', { deviceId: id });
  res.json({ ok: true, deleted: r.deletedCount || 0 });
});

app.post('/api/my/devices/:id/pump', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  const id = String(req.params.id);
  const { state } = req.body || {};
  if (!['on', 'off'].includes(String(state))) return jsonErr(res, 400, 'state must be on|off');
  if (!mongoose.isValidObjectId(id)) return jsonErr(res, 400, 'invalid id');

  const device = await Device.findOne({ _id: id, ownerId }).lean();
  if (!device) return jsonErr(res, 404, 'device not found');
  if (device.disabled) return jsonErr(res, 403, 'device disabled');

  await Device.updateOne({ _id: id }, { $set: { pump: state, lastSeenAt: new Date() } });
  await Alert.create({ ownerId, deviceId: id, type: 'pump', message: `Pump ${String(state).toUpperCase()} (manual)`, createdAt: new Date() });
  await audit(req, 'pump.user', { deviceId: id, state });

  sseSendUser(ownerId, 'pump', { deviceId: id, state, at: nowISO() });
  res.json({ ok: true });
});

/** Device telemetry (device pushes data) */
app.post('/api/device/telemetry', async (req, res) => {
  const { deviceId, soilMoisture, battery, flowLpm, pressureKpa, tempC, humidityPct } = req.body || {};
  const dk = String(req.header('x-device-key') || '');
  if (!deviceId || !dk) return jsonErr(res, 400, 'deviceId and x-device-key required');
  if (!mongoose.isValidObjectId(deviceId)) return jsonErr(res, 400, 'invalid deviceId');

  const dev = await Device.findById(deviceId).lean();
  if (!dev) return jsonErr(res, 404, 'device not found');
  if (dev.disabled) return jsonErr(res, 403, 'device disabled');
  if (dk !== dev.deviceKey) return jsonErr(res, 401, 'invalid device key');

  const doc = await Telemetry.create({
    ownerId: dev.ownerId,
    deviceId: dev._id,
    soilMoisture: clamp(Number(soilMoisture ?? 0), 0, 100),
    battery: clamp(Number(battery ?? 100), 0, 100),
    flowLpm: clamp(Number(flowLpm ?? 0), 0, 1e6),
    pressureKpa: clamp(Number(pressureKpa ?? 0), 0, 1e6),
    tempC: clamp(Number(tempC ?? 0), -50, 80),
    humidityPct: clamp(Number(humidityPct ?? 0), 0, 100),
    pump: dev.pump || 'off',
    createdAt: new Date()
  });

  await Device.updateOne({ _id: dev._id }, { $set: { lastSeenAt: new Date() } });
  sseSendUser(dev.ownerId, 'telemetry', { ...doc.toObject(), createdAt: doc.createdAt.toISOString() });
  res.json({ ok: true });
});

app.get('/api/my/telemetry', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  const deviceId = String(req.query.deviceId || '');
  const limit = clamp(Number(req.query.limit || 50), 1, 500);
  if (!deviceId) return jsonErr(res, 400, 'deviceId required');
  if (!mongoose.isValidObjectId(deviceId)) return jsonErr(res, 400, 'invalid deviceId');

  const dev = await Device.findOne({ _id: deviceId, ownerId }).lean();
  if (!dev) return jsonErr(res, 404, 'device not found');

  const items = await Telemetry.find({ ownerId, deviceId }).sort({ createdAt: -1 }).limit(limit).lean();
  res.json({ telemetry: items });
});

app.post('/api/my/devices/:id/simulate', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  const id = String(req.params.id);
  if (!mongoose.isValidObjectId(id)) return jsonErr(res, 400, 'invalid id');

  const dev = await Device.findOne({ _id: id, ownerId }).lean();
  if (!dev) return jsonErr(res, 404, 'device not found');
  if (dev.disabled) return jsonErr(res, 403, 'device disabled');

  const last = await Telemetry.find({ ownerId, deviceId: id }).sort({ createdAt: -1 }).limit(1).lean();
  const baseSm = last[0]?.soilMoisture ?? 45;
  const drift = (dev.pump === 'on') ? (Math.random() * 4 + 2) : -(Math.random() * 4 + 1);
  const sm = clamp(Math.round(baseSm + drift), 0, 100);

  const doc = await Telemetry.create({
    ownerId, deviceId: id,
    soilMoisture: sm,
    battery: clamp(Math.round((last[0]?.battery ?? 90) + (Math.random() * 2 - 1)), 0, 100),
    flowLpm: clamp(Math.round((dev.pump === 'on' ? (dev.motorFlowLpm || 100) : 0)), 0, 1e6),
    pressureKpa: clamp(Math.round(dev.pump === 'on' ? 180 + Math.random() * 30 : 0), 0, 1e6),
    tempC: clamp(Math.round(18 + Math.random() * 10), -50, 80),
    humidityPct: clamp(Math.round(40 + Math.random() * 40), 0, 100),
    pump: dev.pump || 'off',
    createdAt: new Date()
  });

  await Device.updateOne({ _id: id }, { $set: { lastSeenAt: new Date() } });
  sseSendUser(ownerId, 'telemetry', { ...doc.toObject(), createdAt: doc.createdAt.toISOString() });
  res.json({ ok: true });
});

app.post('/api/my/calc/irrigation', requireAuth(), async (req, res) => {
  const { areaM2, mmTarget, motorFlowLpm } = req.body || {};
  res.json({ ok: true, ...calcIrrigation(areaM2, mmTarget, motorFlowLpm) });
});

/** SSE stream */
app.get('/api/my/stream', requireAuth(), async (req, res) => {
  const ownerId = req.auth.user._id;
  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  res.write(`event: hello\ndata: ${JSON.stringify({ time: nowISO(), userId: String(ownerId) })}\n\n`);
  sseAdd(ownerId, res);
  req.on('close', () => sseRemove(ownerId, res));
});

/** ====== ADMIN API ====== */
app.get('/api/admin/users', requireAdmin(), async (req, res) => {
  const users = await User.find({}).select('-passHash -passSalt').sort({ createdAt: -1 }).lean();
  res.json({ users });
});

app.get('/api/admin/user/:id', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  if (!mongoose.isValidObjectId(id)) return jsonErr(res, 400, 'invalid id');

  const user = await User.findById(id).select('-passHash -passSalt').lean();
  if (!user) return jsonErr(res, 404, 'not found');

  const ownerId = id;
  const farms = await Farm.find({ ownerId }).sort({ createdAt: -1 }).lean();
  const devices = await Device.find({ ownerId }).sort({ createdAt: -1 }).lean();
  res.json({ user, farms, devices });
});

app.post('/api/admin/user/:id/toggle', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  const { disabled } = req.body || {};
  if (!mongoose.isValidObjectId(id)) return jsonErr(res, 400, 'invalid id');

  await User.updateOne({ _id: id }, { $set: { disabled: !!disabled } });
  if (disabled) {
    await Session.deleteMany({ userId: id });
    await Device.updateMany({ ownerId: id }, { $set: { disabled: true } });
  }
  await audit(req, 'admin.user.toggle', { userId: id, disabled: !!disabled });
  res.json({ ok: true });
});

app.delete('/api/admin/user/:id', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  if (!mongoose.isValidObjectId(id)) return jsonErr(res, 400, 'invalid id');

  await Session.deleteMany({ userId: id });
  await Farm.deleteMany({ ownerId: id });
  await Device.deleteMany({ ownerId: id });
  await Telemetry.deleteMany({ ownerId: id });
  const r = await User.deleteOne({ _id: id });
  await audit(req, 'admin.user.delete', { userId: id });
  res.json({ ok: true, deleted: r.deletedCount || 0 });
});

app.post('/api/admin/device/:id/toggle', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  const { disabled } = req.body || {};
  if (!mongoose.isValidObjectId(id)) return jsonErr(res, 400, 'invalid id');

  await Device.updateOne({ _id: id }, { $set: { disabled: !!disabled } });
  await audit(req, 'admin.device.toggle', { deviceId: id, disabled: !!disabled });
  res.json({ ok: true });
});

app.delete('/api/admin/device/:id', requireAdmin(), async (req, res) => {
  const id = String(req.params.id);
  if (!mongoose.isValidObjectId(id)) return jsonErr(res, 400, 'invalid id');

  await Telemetry.deleteMany({ deviceId: id });
  const r = await Device.deleteOne({ _id: id });
  await audit(req, 'admin.device.delete', { deviceId: id });
  res.json({ ok: true, deleted: r.deletedCount || 0 });
});

app.get('/api/admin/audit', requireAdmin(), async (req, res) => {
  const limit = clamp(Number(req.query.limit || 100), 1, 500);
  const items = await Audit.find({}).sort({ createdAt: -1 }).limit(limit).lean();
  res.json({ audit: items });
});

/** Pages */
app.get('/', (req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));
app.use((req, res) => res.status(404).sendFile(path.join(PUBLIC_DIR, 'index.html')));

/** Start */
(async () => {
  try {
    if (!MONGODB_URI) {
      console.error('❌ MONGODB_URI is empty.');
      console.error('👉 PowerShell example:');
      console.error('$env:MONGODB_URI="mongodb+srv://USER:PASS@cluster.mongodb.net/ecotree?retryWrites=true&w=majority"');
      process.exit(1);
    }

    await mongoose.connect(MONGODB_URI);
    console.log('✅ MongoDB connected (mongoose)');

    app.listen(PORT, () => console.log(`🚀 EcoTreeSense running: http://localhost:${PORT}`));
  } catch (e) {
    console.error('❌ Startup error:', e.message);
    console.error('🔧 Atlas checklist: Network Access IP whitelist + Database Access user/pass.');
    process.exit(1);
  }
})();
