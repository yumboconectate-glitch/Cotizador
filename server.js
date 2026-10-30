import Fastify from 'fastify';
import fstatic from '@fastify/static';
import cookie from '@fastify/cookie';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import PDFDocument from 'pdfkit';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || '/data';
const PDF_DIR = join(DATA_DIR, 'pdfs');
const DOCS_DIR = join(DATA_DIR, 'docs');
const ADJ_DIR = join(DATA_DIR, 'adjuntos');
const STORE = join(DATA_DIR, 'store.json');
const SECRET = process.env.JWT_SECRET || 'cambia-este-secreto';
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;
const N8N_API_KEY = process.env.N8N_API_KEY || '';

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
if (!existsSync(PDF_DIR)) mkdirSync(PDF_DIR, { recursive: true });
if (!existsSync(DOCS_DIR)) mkdirSync(DOCS_DIR, { recursive: true });
if (!existsSync(ADJ_DIR)) mkdirSync(ADJ_DIR, { recursive: true });
let db = { users: [], kv: {}, firmas: [] };
if (existsSync(STORE)) { try { db = JSON.parse(readFileSync(STORE, 'utf8')); } catch (e) { console.error('No se pudo leer store.json:', e.message); } }
if (!db.firmas) db.firmas = [];
// migración a multiusuario
(db.users || []).forEach(u => { if (!u.role) u.role = 'admin'; if (u.active === undefined) u.active = true; });
function save() { const tmp = STORE + '.tmp'; writeFileSync(tmp, JSON.stringify(db)); renameSync(tmp, STORE); }
function findUser(u) { return db.users.find(x => x.username === u); }

const app = Fastify({ logger: false, bodyLimit: 15 * 1024 * 1024, trustProxy: true });
await app.register(cookie);

// --- rate limit simple para login (anti fuerza bruta) ---
const loginAttempts = new Map();
function tooManyAttempts(ip) {
  const a = loginAttempts.get(ip);
  if (!a) return false;
  if (Date.now() - a.ts > 15 * 60 * 1000) { loginAttempts.delete(ip); return false; }
  return a.n >= 8;
}
function registerFail(ip) {
  const a = loginAttempts.get(ip) || { n: 0, ts: Date.now() };
  a.n++; a.ts = Date.now(); loginAttempts.set(ip, a);
}
function clearFails(ip) { loginAttempts.delete(ip); }

function setSession(reply, username) {
  const token = jwt.sign({ u: username }, SECRET, { expiresIn: '30d' });
  reply.setCookie('cotz_session', token, { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 60 * 60 * 24 * 30, secure: PUBLIC_URL.startsWith('https') });
}
function getUser(req) {
  const t = req.cookies?.cotz_session; if (!t) return null;
  try { return jwt.verify(t, SECRET).u; } catch (e) { return null; }
}
function requireAuth(req, reply) {
  const u = getUser(req); if (!u) { reply.code(401).send({ error: 'no auth' }); return null; } return u;
}
function requireAuthOrKey(req, reply) {
  if (N8N_API_KEY && req.headers['x-api-key'] === N8N_API_KEY) return 'n8n';
  return requireAuth(req, reply);
}
function requireAdmin(req, reply) {
  const u = requireAuth(req, reply); if (!u) return null;
  const user = findUser(u);
  if (!user || user.role !== 'admin') { reply.code(403).send({ error: 'solo administrador' }); return null; }
  return u;
}

app.get('/api/auth/me', async (req) => {
  const u = getUser(req);
  const user = u ? findUser(u) : null;
  return { authenticated: !!user, username: user ? user.username : null, role: user ? user.role : null, needSetup: db.users.length === 0 };
});
app.post('/api/auth/setup', async (req, reply) => {
  if (db.users.length > 0) { reply.code(400); return { error: 'ya configurado' }; }
  const { username, password } = req.body || {};
  if (!username || !password || password.length < 4) { reply.code(400); return { error: 'datos inválidos' }; }
  db.users.push({ username: String(username).trim(), hash: bcrypt.hashSync(password, 10), role: 'admin', active: true }); save();
  setSession(reply, String(username).trim()); return { ok: true };
});
app.post('/api/auth/login', async (req, reply) => {
  const ip = req.ip;
  if (tooManyAttempts(ip)) { reply.code(429); return { error: 'Demasiados intentos. Espera 15 minutos.' }; }
  const { username, password } = req.body || {};
  const user = db.users.find(x => x.username === String(username || '').trim());
  if (!user || user.active === false || !bcrypt.compareSync(password || '', user.hash)) {
    registerFail(ip);
    reply.code(401); return { error: 'credenciales incorrectas' };
  }
  clearFails(ip);
  setSession(reply, user.username); return { ok: true };
});
app.post('/api/auth/logout', async (req, reply) => { reply.clearCookie('cotz_session', { path: '/' }); return { ok: true }; });
app.post('/api/auth/change', async (req, reply) => {
  const cur = requireAuth(req, reply); if (!cur) return;
  const { password } = req.body || {};
  if (!password || password.length < 4) { reply.code(400); return { error: 'contraseña inválida (mínimo 4)' }; }
  const user = findUser(cur);
  user.hash = bcrypt.hashSync(password, 10); save();
  return { ok: true };
});

/* ---- Gestión de usuarios (solo admin) ---- */
app.get('/api/users', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  return { users: db.users.map(u => ({ username: u.username, role: u.role, active: u.active !== false })) };
});
app.post('/api/users', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const { username, password, role } = req.body || {};
  const uname = String(username || '').trim();
  if (!uname || !password || password.length < 4) { reply.code(400); return { error: 'usuario y contraseña (mín 4) requeridos' }; }
  if (findUser(uname)) { reply.code(400); return { error: 'ese usuario ya existe' }; }
  db.users.push({ username: uname, hash: bcrypt.hashSync(password, 10), role: role === 'admin' ? 'admin' : 'vendedor', active: true }); save();
  return { ok: true };
});
app.post('/api/users/:username/reset', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const user = findUser(req.params.username);
  if (!user) { reply.code(404); return { error: 'no existe' }; }
  const { password } = req.body || {};
  if (!password || password.length < 4) { reply.code(400); return { error: 'contraseña inválida' }; }
  user.hash = bcrypt.hashSync(password, 10); save();
  return { ok: true };
});
app.post('/api/users/:username/toggle', async (req, reply) => {
  const cur = requireAdmin(req, reply); if (!cur) return;
  const user = findUser(req.params.username);
  if (!user) { reply.code(404); return { error: 'no existe' }; }
  if (user.username === cur) { reply.code(400); return { error: 'no puedes desactivarte a ti mismo' }; }
  user.active = user.active === false ? true : false; save();
  return { ok: true, active: user.active };
});
const ADMIN_KEYS = ['cfg', 'smtp', 'factcfg'];
app.get('/api/kv/:key', async (req, reply) => {
  if (req.params.key === 'smtp' || req.params.key === 'factcfg') { if (!requireAdmin(req, reply)) return; }
  else if (!requireAuth(req, reply)) return;
  const v = db.kv[req.params.key];
  return { value: v === undefined ? null : v };
});
app.put('/api/kv/:key', async (req, reply) => {
  if (ADMIN_KEYS.includes(req.params.key)) { if (!requireAdmin(req, reply)) return; }
  else if (!requireAuth(req, reply)) return;
  db.kv[req.params.key] = req.body?.value; save();
  return { ok: true };
});

/* ---- PDFs con enlace publico ---- */
app.post('/api/pdf', async (req, reply) => {
  if (!requireAuth(req, reply)) return;
  const { filename, data } = req.body || {};
  if (!data) { reply.code(400); return { error: 'sin data' }; }
  const token = crypto.randomBytes(10).toString('hex');
  const safe = String(filename || 'documento').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 60);
  const name = token + '_' + safe + '.pdf';
  writeFileSync(join(PDF_DIR, name), Buffer.from(data, 'base64'));
  const base = PUBLIC_URL || '';
  return { ok: true, file: name, url: base + '/p/' + name };
});
app.get('/p/:file', async (req, reply) => {
  try {
    const f0 = String(req.params.file || '');
    db.kv.vistas = db.kv.vistas || {};
    const vv = db.kv.vistas[f0] = db.kv.vistas[f0] || { n: 0 };
    vv.n++; vv.ultima = new Date().toISOString(); save();
  } catch (e) {}
  const f = String(req.params.file || '').replace(/[^a-zA-Z0-9._-]/g, '');
  const full = join(PDF_DIR, f);
  if (!existsSync(full)) { reply.code(404); return { error: 'no existe' }; }
  reply.header('Content-Type', 'application/pdf');
  reply.header('Content-Disposition', 'inline; filename="' + f.split('_').slice(1).join('_') + '"');
  return reply.send(readFileSync(full));
});

/* ---- Correo SMTP (config desde la interfaz con fallback a variables de entorno) ---- */
function smtpCfg() {
  const s = db.kv.smtp || {};
  return {
    host: s.host || SMTP_HOST, port: Number(s.port || SMTP_PORT || 465),
    user: s.user || SMTP_USER, pass: s.pass || SMTP_PASS,
    from: s.from || s.user || SMTP_FROM
  };
}
function mailer() {
  const c = smtpCfg();
  if (!c.host || !c.user || !c.pass) return null;
  return nodemailer.createTransport({ host: c.host, port: c.port, secure: c.port === 465, auth: { user: c.user, pass: c.pass } });
}
app.get('/api/correo/estado', async (req, reply) => {
  if (!requireAuth(req, reply)) return;
  const c = smtpCfg();
  return { configurado: !!mailer(), from: c.from || null };
});
app.post('/api/correo/test', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const t = mailer();
  if (!t) { reply.code(400); return { error: 'SMTP incompleto: falta servidor, usuario o contraseña' }; }
  const { to } = req.body || {};
  if (!to) { reply.code(400); return { error: 'indica el correo de destino de la prueba' }; }
  try {
    await t.sendMail({ from: '"Prueba Cotizador" <' + smtpCfg().from + '>', to, subject: 'Prueba SMTP - Cotizador', text: 'Si recibes este mensaje, el servidor de correo quedó bien configurado. ✓' });
    return { ok: true };
  } catch (e) { reply.code(500); return { error: 'fallo SMTP: ' + e.message }; }
});
app.post('/api/correo', async (req, reply) => {
  if (!requireAuthOrKey(req, reply)) return;
  const t = mailer();
  if (!t) { reply.code(400); return { error: 'SMTP no configurado. Define SMTP_HOST, SMTP_USER y SMTP_PASS en el .env' }; }
  const { to, subject, text, pdfFile } = req.body || {};
  if (!to || !subject) { reply.code(400); return { error: 'faltan destinatario o asunto' }; }
  const attachments = [];
  if (pdfFile) {
    const f = String(pdfFile).replace(/[^a-zA-Z0-9._-]/g, '');
    const full = join(PDF_DIR, f);
    if (existsSync(full)) attachments.push({ filename: f.split('_').slice(1).join('_') || 'documento.pdf', path: full });
  }
  try {
    await t.sendMail({ from: '"' + ((db.kv.cfg||{}).marca||'Cotizador') + '" <' + smtpCfg().from + '>', to, subject, text: text || '', attachments });
    return { ok: true };
  } catch (e) { reply.code(500); return { error: 'fallo SMTP: ' + e.message }; }
});

/* ---- Firma electronica propia ---- */
app.post('/api/firmas', async (req, reply) => {
  const user = requireAuth(req, reply); if (!user) return;
  const { orden, docName, empresa } = req.body || {};
  if (!orden || !orden.cliente) { reply.code(400); return { error: 'orden incompleta' }; }
  const token = crypto.randomBytes(14).toString('hex');
  const hash = crypto.createHash('sha256').update(JSON.stringify(orden)).digest('hex');
  db.firmas.push({
    token, docName: String(docName || 'Orden de servicio').slice(0, 120),
    orden, empresa: empresa || {}, hash,
    creada: new Date().toISOString(), creadaPor: user, estado: 'pendiente'
  });
  save();
  const base = PUBLIC_URL || '';
  return { ok: true, token, url: base + '/firmar.html?t=' + token, hash };
});
app.get('/api/firmas', async (req, reply) => {
  if (!requireAuth(req, reply)) return;
  return { firmas: db.firmas.map(f => ({ token: f.token, docName: f.docName, cliente: f.orden?.cliente?.nombre || '', estado: f.estado, creada: f.creada, creadaPor: f.creadaPor, fechaFirma: f.fechaFirma || null, ivaOn: !!f.orden?.tot?.ivaOn, facturaEnvio: f.facturaEnvio || null })) };
});
app.get('/api/firmas/:token', async (req, reply) => {
  if (!requireAuth(req, reply)) return;
  const f = db.firmas.find(x => x.token === req.params.token);
  if (!f) { reply.code(404); return { error: 'no existe' }; }
  return { firma: f };
});
app.delete('/api/firmas/:token', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const i = db.firmas.findIndex(x => x.token === req.params.token);
  if (i < 0) { reply.code(404); return { error: 'no existe' }; }
  db.firmas.splice(i, 1); save();
  return { ok: true };
});
/* pagina publica de firma: datos y envio */
function maskMail(m) {
  if (!m || !m.includes('@')) return null;
  const [u, d] = m.split('@');
  return (u.slice(0, 2) + '***') + '@' + d;
}
app.get('/api/firma-publica/:token', async (req, reply) => {
  const f = db.firmas.find(x => x.token === req.params.token);
  if (!f) { reply.code(404); return { error: 'Enlace de firma no valido' }; }
  const ordenPub = JSON.parse(JSON.stringify(f.orden));
  if (ordenPub.cliente) delete ordenPub.cliente.correo; // no exponer el correo completo
  const cfgC = db.kv.cfg || {};
  return { docName: f.docName, estado: f.estado, creada: f.creada, hash: f.hash,
    empresa: { ...(f.empresa || {}), web: cfgC.web || '', tel1: cfgC.tel1 || '', tel2: cfgC.tel2 || '', marca: cfgC.marca || '', mail: cfgC.mail || '' }, orden: ordenPub,
    correoMasked: maskMail(f.orden?.cliente?.correo),
    fechaFirma: f.fechaFirma || null, firmante: f.estado === 'firmada' ? { nombre: f.firmanteNombre, documento: f.firmanteDoc } : null };
});
/* enviar codigo de verificacion al correo del cliente */
app.post('/api/firma-publica/:token/codigo', async (req, reply) => {
  const f = db.firmas.find(x => x.token === req.params.token);
  if (!f) { reply.code(404); return { error: 'Enlace no valido' }; }
  if (f.estado === 'firmada') { reply.code(400); return { error: 'Documento ya firmado' }; }
  const correo = f.orden?.cliente?.correo;
  if (!correo) { reply.code(400); return { error: 'No hay un correo registrado para este cliente. Contacta a la empresa para actualizarlo.' }; }
  if (f.otpTs && Date.now() - f.otpTs < 60 * 1000) { reply.code(429); return { error: 'Espera un minuto antes de pedir otro codigo' }; }
  const code = String(crypto.randomInt(100000, 999999));
  f.otp = code; f.otpTs = Date.now(); f.otpExp = Date.now() + 10 * 60 * 1000; f.otpIntentos = 0; save();
  const t = mailer();
  if (!t) { reply.code(400); return { error: 'El servidor de correo no esta configurado. Contacta a la empresa.' }; }
  try {
    await t.sendMail({ from: '"Verificacion de firma" <' + smtpCfg().from + '>', to: correo,
      subject: 'Tu codigo de verificacion: ' + code,
      text: 'Codigo de verificacion para firmar "' + f.docName + '": ' + code + '\n\nVence en 10 minutos. Si no solicitaste esta firma, ignora este mensaje.' });
    return { ok: true, correo: maskMail(correo) };
  } catch (e) { reply.code(500); return { error: 'No se pudo enviar el codigo: ' + e.message }; }
});
app.post('/api/firma-publica/:token', async (req, reply) => {
  const f = db.firmas.find(x => x.token === req.params.token);
  if (!f) { reply.code(404); return { error: 'Enlace de firma no valido' }; }
  if (f.estado === 'firmada') { reply.code(400); return { error: 'Este documento ya fue firmado' }; }
  const { nombre, documento, firma, acepta, codigo } = req.body || {};
  if (!acepta) { reply.code(400); return { error: 'Debes aceptar los terminos de firma electronica' }; }
  if (!nombre || !documento) { reply.code(400); return { error: 'Nombre y documento son requeridos' }; }
  // verificacion de identidad por codigo enviado al correo
  if (!f.otp || Date.now() > (f.otpExp || 0)) { reply.code(400); return { error: 'Solicita el codigo de verificacion a tu correo (o venció, pide uno nuevo)' }; }
  if ((f.otpIntentos || 0) >= 5) { reply.code(429); return { error: 'Demasiados intentos con el codigo. Solicita uno nuevo.' }; }
  if (String(codigo || '').trim() !== f.otp) { f.otpIntentos = (f.otpIntentos || 0) + 1; save(); reply.code(400); return { error: 'Codigo incorrecto (' + (5 - f.otpIntentos) + ' intentos restantes)' }; }
  if (!firma || !String(firma).startsWith('data:image/png;base64,') || firma.length > 800000) {
    reply.code(400); return { error: 'Firma invalida' };
  }
  f.estado = 'firmada';
  f.firmanteNombre = String(nombre).slice(0, 120);
  f.firmanteDoc = String(documento).slice(0, 40);
  f.firmaImg = firma;
  f.fechaFirma = new Date().toISOString();
  f.ipFirma = req.ip;
  f.uaFirma = String(req.headers['user-agent'] || '').slice(0, 200);
  f.correoVerificado = f.orden?.cliente?.correo || '';
  delete f.otp; delete f.otpExp; delete f.otpIntentos; delete f.otpTs;
  save();
  // notificar por correo (si SMTP esta configurado) sin bloquear la respuesta
  try {
    const t = mailer();
    const destino = (db.kv.cfg || {}).mail;
    if (t && destino) {
      t.sendMail({ from: '"Firmas Cotizador" <' + smtpCfg().from + '>', to: destino,
        subject: '✍ Firmado - requiere tu APROBACION: ' + f.docName,
        text: 'El cliente firmo el documento y esta PENDIENTE DE TU APROBACION.\n\nDocumento: ' + f.docName + '\nFirmante: ' + f.firmanteNombre + ' (' + f.firmanteDoc + ')\nFecha: ' + f.fechaFirma + '\nIP: ' + f.ipFirma + '\nVerificacion (SHA-256): ' + f.hash + '\n\nEntra al cotizador > Historial > Firmas electronicas y pulsa Aprobar para enviarle automaticamente los documentos de la empresa (RUT, camara, cuenta, etc.).' }).catch(() => {});
    }
  } catch (e) {}
  return { ok: true };
});

/* ---- Adjuntos (ej: RUT de clientes) ---- */
app.post('/api/archivo', async (req, reply) => {
  if (!requireAuth(req, reply)) return;
  const { nombre, data } = req.body || {};
  if (!data) { reply.code(400); return { error: 'sin archivo' }; }
  const buf = Buffer.from(data, 'base64');
  if (buf.length > 10 * 1024 * 1024) { reply.code(400); return { error: 'maximo 10 MB' }; }
  const safe = String(nombre || 'adjunto.pdf').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 60);
  const file = crypto.randomBytes(8).toString('hex') + '_' + safe;
  writeFileSync(join(ADJ_DIR, file), buf);
  return { ok: true, file };
});
app.get('/api/archivo/:file', async (req, reply) => {
  if (!requireAuth(req, reply)) return;
  const f = String(req.params.file || '').replace(/[^a-zA-Z0-9._-]/g, '');
  const full = join(ADJ_DIR, f);
  if (!existsSync(full)) { reply.code(404); return { error: 'no existe' }; }
  reply.header('Content-Type', 'application/pdf');
  reply.header('Content-Disposition', 'inline; filename="' + f.split('_').slice(1).join('_') + '"');
  return reply.send(readFileSync(full));
});

/* ---- Pagos / abonos por cotizacion ---- */
function resumenPagos(cot) {
  const pagos = cot.pagos || [];
  const abonado = pagos.reduce((a, p) => a + (+p.valor || 0), 0);
  const total = +cot.total || 0;
  return { total, abonado, saldo: Math.max(0, total - abonado), pagos };
}
app.get('/api/pagos/:cotId', async (req, reply) => {
  if (!requireAuth(req, reply)) return;
  const cot = (db.kv.historial || []).find(h => h.id === req.params.cotId);
  if (!cot) { reply.code(404); return { error: 'cotizacion no existe' }; }
  return { ok: true, numero: cot.numero, cliente: cot.cliente?.nombre || '', ...resumenPagos(cot) };
});
function htmlAbono(cot, r, v, cfg) {
  const azul = '#007DB7', navy = '#14395c', gris = '#64748b', suave = '#f5f9fc';
  const alDia = r.saldo === 0;
  const filas = (cot.pagos || []).slice().reverse().map(p =>
    '<tr><td style="padding:8px 10px;border-bottom:1px solid #e3ebf2;font-size:13px;color:#1f2d3a">' + new Date(p.fecha).toLocaleDateString('es-CO') + '</td>' +
    '<td style="padding:8px 10px;border-bottom:1px solid #e3ebf2;font-size:13px;font-weight:bold;color:' + navy + ';text-align:right">' + fmtCOP(p.valor) + '</td>' +
    '<td style="padding:8px 10px;border-bottom:1px solid #e3ebf2;font-size:13px;color:' + gris + '">' + (p.metodo || '') + '</td></tr>').join('');
  const stat = (label, valor, color, bg) =>
    '<td width="33%" style="padding:6px"><table width="100%" cellpadding="0" cellspacing="0" style="background:' + (bg || suave) + ';border-radius:10px"><tr><td style="padding:14px 8px;text-align:center">' +
    '<div style="font-size:10px;letter-spacing:1px;color:' + gris + ';text-transform:uppercase;font-family:Arial">' + label + '</div>' +
    '<div style="font-size:17px;font-weight:bold;color:' + (color || navy) + ';font-family:Arial;margin-top:4px">' + valor + '</div></td></tr></table></td>';
  return '<!DOCTYPE html><html><body style="margin:0;padding:0;background:#eef4f8">' +
  '<table width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:24px 12px">' +
  '<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border-radius:14px;overflow:hidden;font-family:Arial,sans-serif">' +
  // encabezado
  '<tr><td style="background:' + azul + ';padding:22px 26px">' +
  '<div style="color:#ffffff;font-size:20px;font-weight:bold">' + (cfg.marca || cfg.empresa || '') + '</div>' +
  '<div style="color:#cfe9f7;font-size:12px;margin-top:2px">' + (cfg.eslogan || '') + '</div></td></tr>' +
  // titulo
  '<tr><td style="padding:24px 26px 8px">' +
  '<div style="font-size:18px;font-weight:bold;color:' + navy + '">✓ Abono registrado: ' + fmtCOP(v) + '</div>' +
  '<div style="font-size:13px;color:' + gris + ';margin-top:4px">Cotización <b>' + cot.numero + '</b> · ' + (cot.cliente.nombre || '') + '</div></td></tr>' +
  // tarjetas
  '<tr><td style="padding:10px 20px"><table width="100%" cellpadding="0" cellspacing="0"><tr>' +
  stat('Valor total', fmtCOP(r.total)) +
  stat('Total abonado', fmtCOP(r.abonado), '#0f9d58') +
  (alDia ? stat('Estado', 'Cuenta al día ✓', '#ffffff', '#0f9d58') : stat('Saldo pendiente', fmtCOP(r.saldo), '#b7791f', '#fff7e6')) +
  '</tr></table></td></tr>' +
  (alDia ? '<tr><td style="padding:4px 26px 0"><div style="background:#e8f7ef;border-radius:10px;padding:12px 16px;font-size:13.5px;color:#0b7a43;font-weight:bold;text-align:center">🎉 ¡Su cuenta quedó al día! Gracias por su pago.</div></td></tr>' : '') +
  // tabla abonos
  '<tr><td style="padding:18px 26px 6px"><div style="font-size:13px;font-weight:bold;color:' + navy + ';text-transform:uppercase;letter-spacing:.5px">Detalle de abonos</div></td></tr>' +
  '<tr><td style="padding:0 26px 10px"><table width="100%" cellpadding="0" cellspacing="0">' +
  '<tr><td style="padding:8px 10px;background:' + suave + ';font-size:11px;color:' + gris + ';text-transform:uppercase">Fecha</td>' +
  '<td style="padding:8px 10px;background:' + suave + ';font-size:11px;color:' + gris + ';text-transform:uppercase;text-align:right">Valor</td>' +
  '<td style="padding:8px 10px;background:' + suave + ';font-size:11px;color:' + gris + ';text-transform:uppercase">Método</td></tr>' +
  filas + '</table></td></tr>' +
  // pie
  '<tr><td style="padding:16px 26px 24px">' +
  '<div style="border-top:2px solid ' + azul + ';padding-top:14px;font-size:12px;color:' + gris + ';line-height:1.7">' +
  (cfg.rep || '') + '<br><b style="color:' + navy + '">' + (cfg.empresa || '') + '</b><br>' +
  (cfg.tel1 || '') + (cfg.tel2 ? ' / ' + cfg.tel2 : '') + (cfg.web ? ' · ' + cfg.web : '') + '</div></td></tr>' +
  '</table></td></tr></table></body></html>';
}
app.post('/api/pagos', async (req, reply) => {
  const user = requireAuth(req, reply); if (!user) return;
  const { cotId, valor, metodo, nota, comprobante, comprobanteNombre, notificar } = req.body || {};
  const cot = (db.kv.historial || []).find(h => h.id === cotId);
  if (!cot) { reply.code(404); return { error: 'cotizacion no existe' }; }
  const v = Math.round(+valor || 0);
  if (v <= 0) { reply.code(400); return { error: 'el valor del abono debe ser mayor a 0' }; }
  let compFile = null;
  if (comprobante) {
    const buf = Buffer.from(comprobante, 'base64');
    if (buf.length > 10 * 1024 * 1024) { reply.code(400); return { error: 'comprobante maximo 10 MB' }; }
    const safe = String(comprobanteNombre || 'comprobante').replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 60);
    compFile = crypto.randomBytes(8).toString('hex') + '_' + safe;
    writeFileSync(join(ADJ_DIR, compFile), buf);
  }
  cot.pagos = cot.pagos || [];
  const pago = { id: crypto.randomBytes(6).toString('hex'), fecha: new Date().toISOString(),
    valor: v, metodo: String(metodo || '').slice(0, 40), nota: String(nota || '').slice(0, 200),
    comprobanteFile: compFile, comprobanteNombre: comprobanteNombre || null, registradoPor: user };
  cot.pagos.push(pago);
  save();
  const r = resumenPagos(cot);
  let correoEnviado = false, aviso = null;
  if (notificar !== false) {
    const t = mailer();
    const correo = cot.cliente?.correo;
    if (t && correo) {
      const cfg = db.kv.cfg || {};
      const detalle = cot.pagos.map(p => '  - ' + new Date(p.fecha).toLocaleDateString('es-CO') + ': ' + fmtCOP(p.valor) + (p.metodo ? ' (' + p.metodo + ')' : '')).join('\n');
      const cuerpo = 'Cordial saludo ' + (cot.cliente.nombre || '') + ',\n\n' +
        'Confirmamos el registro de su abono por ' + fmtCOP(v) + ' a la cotización ' + cot.numero + '.\n\n' +
        'ESTADO DE SU CUENTA:\n' +
        '  Valor total:      ' + fmtCOP(r.total) + '\n' +
        '  Total abonado:    ' + fmtCOP(r.abonado) + '\n' +
        '  Saldo pendiente:  ' + fmtCOP(r.saldo) + '\n\n' +
        (r.saldo === 0 ? '✓ ¡Su cuenta quedó al día! Gracias por su pago.\n\n' : '') +
        'Detalle de abonos:\n' + detalle + '\n\n' +
        (cfg.rep || '') + '\n' + (cfg.empresa || '') + '\n' + (cfg.tel1 || '') + (cfg.tel2 ? ' / ' + cfg.tel2 : '');
      try {
        await t.sendMail({ from: '"' + (cfg.marca || 'Cotizador') + '" <' + smtpCfg().from + '>', to: correo,
          subject: 'Abono registrado ' + fmtCOP(v) + ' - ' + cot.numero + (r.saldo === 0 ? ' · Cuenta al día ✓' : ' · Saldo: ' + fmtCOP(r.saldo)),
          text: cuerpo, html: htmlAbono(cot, r, v, cfg) });
        correoEnviado = true;
      } catch (e) { aviso = 'correo fallo: ' + e.message; }
    } else aviso = !t ? 'SMTP no configurado' : 'cliente sin correo';
  }
  return { ok: true, pago, ...r, correoEnviado, aviso };
});
app.delete('/api/pagos/:cotId/:pagoId', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const cot = (db.kv.historial || []).find(h => h.id === req.params.cotId);
  if (!cot || !cot.pagos) { reply.code(404); return { error: 'no existe' }; }
  const i = cot.pagos.findIndex(p => p.id === req.params.pagoId);
  if (i < 0) { reply.code(404); return { error: 'pago no existe' }; }
  cot.pagos.splice(i, 1); save();
  return { ok: true, ...resumenPagos(cot) };
});

/* ---- Documentos corporativos (RUT, camara, cuenta, etc.) ---- */
const DOC_TIPOS = ['rut', 'existencia', 'camara', 'rup', 'cuenta'];
const DOC_LABELS = { rut: 'RUT', existencia: 'Certificado de existencia', camara: 'Camara de comercio', rup: 'RUP', cuenta: 'Certificado de cuenta bancaria' };
function docsToken() {
  if (!db.kv.docsToken) { db.kv.docsToken = crypto.randomBytes(12).toString('hex'); save(); }
  return db.kv.docsToken;
}
function docsList() {
  const meta = db.kv.docs || {};
  return DOC_TIPOS.map(t => ({ tipo: t, label: DOC_LABELS[t], cargado: !!meta[t], nombre: meta[t]?.nombre || null, fecha: meta[t]?.fecha || null }));
}
app.get('/api/docs', async (req, reply) => {
  if (!requireAuth(req, reply)) return;
  const base = PUBLIC_URL || '';
  return { docs: docsList(), url: base + '/docs.html?t=' + docsToken() };
});
app.post('/api/docs/:tipo', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const tipo = req.params.tipo;
  if (!DOC_TIPOS.includes(tipo)) { reply.code(400); return { error: 'tipo invalido' }; }
  const { nombre, data } = req.body || {};
  if (!data) { reply.code(400); return { error: 'sin archivo' }; }
  const buf = Buffer.from(data, 'base64');
  if (buf.length > 10 * 1024 * 1024) { reply.code(400); return { error: 'maximo 10 MB' }; }
  writeFileSync(join(DOCS_DIR, tipo + '.pdf'), buf);
  db.kv.docs = db.kv.docs || {};
  db.kv.docs[tipo] = { nombre: String(nombre || tipo + '.pdf').slice(0, 100), fecha: new Date().toISOString() };
  save();
  return { ok: true };
});
app.delete('/api/docs/:tipo', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const tipo = req.params.tipo;
  if (db.kv.docs && db.kv.docs[tipo]) { delete db.kv.docs[tipo]; save(); }
  try { const p = join(DOCS_DIR, tipo + '.pdf'); if (existsSync(p)) writeFileSync(p, ''); } catch (e) {}
  return { ok: true };
});
/* enlace publico de documentos (para WhatsApp) */
app.get('/api/docs-publicos/:tk', async (req, reply) => {
  if (req.params.tk !== db.kv.docsToken) { reply.code(404); return { error: 'enlace no valido' }; }
  const cfg = db.kv.cfg || {};
  return { empresa: { nombre: cfg.empresa || '', nit: cfg.nit || '', logo: cfg.logo || null, eslogan: cfg.eslogan || '' }, docs: docsList().filter(d => d.cargado) };
});
app.get('/api/docs-publicos/:tk/:tipo', async (req, reply) => {
  if (req.params.tk !== db.kv.docsToken) { reply.code(404); return { error: 'no valido' }; }
  const tipo = req.params.tipo;
  if (!DOC_TIPOS.includes(tipo) || !(db.kv.docs || {})[tipo]) { reply.code(404); return { error: 'no existe' }; }
  reply.header('Content-Type', 'application/pdf');
  reply.header('Content-Disposition', 'inline; filename="' + (DOC_LABELS[tipo] || tipo).replace(/[^a-zA-Z0-9 _-]/g, '') + '.pdf"');
  return reply.send(readFileSync(join(DOCS_DIR, tipo + '.pdf')));
});
/* ---- Aceptacion en linea de la propuesta (boton del PDF) ---- */
app.post('/api/aceptar/:token', async (req, reply) => {
  const tk = String(req.params.token || '');
  if (tk.length < 10) { reply.code(404); return { error: 'no valido' }; }
  const cot = (db.kv.historial || []).find(h => h.aceptaToken === tk);
  if (!cot) { reply.code(404); return { error: 'no valido' }; }
  const cfg = db.kv.cfg || {};
  // idempotente: si ya tiene firma creada y sigue existiendo, devolver la misma
  if (cot.firmaToken) {
    const fx = db.firmas.find(x => x.token === cot.firmaToken);
    if (fx) return { ok: true, firmaUrl: (PUBLIC_URL || '') + '/firmar.html?t=' + fx.token,
      numero: cot.numero, cliente: cot.cliente?.nombre || '', total: fmtCOP(cot.total),
      empresa: { logo: cfg.logo || null } };
  }
  // construir la orden desde la cotizacion (mismo criterio que la conversion manual)
  const rows = (cot.lineas || []).map(l => ({ serv: l.item + (l.cant > 1 ? ' (x' + l.cant + ')' : ''), bw: '', ciudad: cfg.ciudad || '', dir: '', inst: fmtCOP(l.cant * l.precio), mes: '' }));
  const items = (cot.lineas || []).map(l => ({ item: l.item, desc: l.desc || '', cant: +l.cant || 1, precio: +l.precio || 0 }));
  const esInternet = (cot.lineas || []).some(l => /internet|mb\b|mbps|plan/i.test(l.item || ''));
  const orden = { cliente: cot.cliente, fecha: new Date().toLocaleDateString('es-CO'), tipoDoc: 'NIT', numDoc: cot.cliente?.cedula || '',
    tipo: esInternet ? 'internet' : 'venta', items, dirGen: '', ciudadGen: cfg.ciudad || '',
    rows, cond: (db.kv.condOrden || '1. Los valores presentados INCLUYEN el IVA del 19%.'), tot: { ...(cot.tot || {}), mes: 0, mesIva: 0 } };
  const token = crypto.randomBytes(14).toString('hex');
  const hash = crypto.createHash('sha256').update(JSON.stringify(orden)).digest('hex');
  db.firmas.push({ token, docName: 'Orden de servicio - ' + (cot.cliente?.nombre || '') + ' (' + cot.numero + ')', orden,
    empresa: { nombre: cfg.empresa, nit: cfg.nit, eslogan: cfg.eslogan, logo: cfg.logo }, hash,
    creada: new Date().toISOString(), creadaPor: 'aceptacion-cliente', estado: 'pendiente' });
  cot.firmaToken = token;
  if (!cot.estado || cot.estado === 'enviada' || cot.estado === 'negociacion') cot.estado = 'aceptada';
  save();
  // avisar a la empresa
  const t = mailer();
  if (t && (cfg.mail)) {
    t.sendMail({ from: '"' + (cfg.marca || 'Cotizador') + '" <' + smtpCfg().from + '>', to: cfg.mail,
      subject: '🎉 Propuesta ACEPTADA: ' + cot.numero + ' - ' + (cot.cliente?.nombre || ''),
      text: 'El cliente acepto la propuesta desde el PDF.\n\nCotizacion: ' + cot.numero + '\nCliente: ' + (cot.cliente?.nombre || '') + '\nTotal: ' + fmtCOP(cot.total) + '\n\nSe genero la orden de servicio y el cliente esta en proceso de firma electronica.\nEnlace de firma: ' + (PUBLIC_URL || '') + '/firmar.html?t=' + token }).catch(() => {});
  }
  return { ok: true, firmaUrl: (PUBLIC_URL || '') + '/firmar.html?t=' + token,
    numero: cot.numero, cliente: cot.cliente?.nombre || '', total: fmtCOP(cot.total),
    empresa: { logo: cfg.logo || null } };
});

/* ---- Facturacion electronica: webhook al CRM ---- */
async function enviarAFacturacion(f, motivo) {
  const fc = db.kv.factcfg || {};
  if (!fc.url) return { ok: false, error: 'sin URL de facturacion configurada' };
  const o = f.orden || {};
  const t = o.tot || {};
  const payload = {
    evento: motivo || 'orden_aprobada',
    orden: {
      documento: f.docName, firmaToken: f.token, tipo: o.tipo || 'internet',
      fecha: o.fecha, fechaAprobacion: f.fechaAprob || null,
      dirInstalacion: o.dirGen || '', ciudad: o.ciudadGen || ''
    },
    cliente: {
      nombre: o.cliente?.nombre || '', tipoDoc: o.tipoDoc || 'NIT',
      numDoc: o.numDoc || o.cliente?.cedula || '', correo: o.cliente?.correo || '', tel: o.cliente?.tel || ''
    },
    items: (o.tipo === 'venta' && o.items?.length)
      ? o.items.map(l => ({ item: l.item, desc: l.desc || '', cant: +l.cant || 1, vlrUnitario: +l.precio || 0, vlrTotal: (+l.cant || 0) * (+l.precio || 0) }))
      : (o.rows || []).map(r => ({ item: r.serv, desc: r.dir || '', cant: 1, vlrUnitario: null, vlrTotal: null, cargoInstalacion: r.inst, recurrenteMensual: r.mes })),
    totales: { subtotal: t.sub || 0, descuentoPct: t.dPct || 0, descuento: t.desc || 0, base: t.base || 0, ivaOn: !!t.ivaOn, ivaPct: t.ivaPct || 0, iva: Math.round(t.iva || 0), total: Math.round(t.total || 0), recurrenteMensual: t.mes || 0 }
  };
  try {
    const ctl = new AbortController(); const tm = setTimeout(() => ctl.abort(), 10000);
    const r = await fetch(fc.url, { method: 'POST', signal: ctl.signal,
      headers: { 'Content-Type': 'application/json', ...(fc.token ? { 'X-Fact-Token': fc.token, 'Authorization': 'Bearer ' + fc.token } : {}) },
      body: JSON.stringify(payload) });
    clearTimeout(tm);
    f.facturaEnvio = { ok: r.ok, status: r.status, fecha: new Date().toISOString(), evento: payload.evento };
    save();
    return { ok: r.ok, status: r.status };
  } catch (e) {
    f.facturaEnvio = { ok: false, error: e.message, fecha: new Date().toISOString() }; save();
    return { ok: false, error: e.message };
  }
}
app.post('/api/facturacion/probar', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const fc = db.kv.factcfg || {};
  if (!fc.url) { reply.code(400); return { error: 'configura la URL primero' }; }
  try {
    const ctl = new AbortController(); const tm = setTimeout(() => ctl.abort(), 8000);
    const r = await fetch(fc.url, { method: 'POST', signal: ctl.signal,
      headers: { 'Content-Type': 'application/json', ...(fc.token ? { 'X-Fact-Token': fc.token, 'Authorization': 'Bearer ' + fc.token } : {}) },
      body: JSON.stringify({ evento: 'prueba', mensaje: 'Conexion de facturacion del cotizador OK', ts: Date.now() }) });
    clearTimeout(tm);
    return { ok: r.ok, status: r.status };
  } catch (e) { return { ok: false, error: e.message }; }
});
app.post('/api/firmas/:token/facturar', async (req, reply) => {
  if (!requireAdmin(req, reply)) return;
  const f = db.firmas.find(x => x.token === req.params.token);
  if (!f) { reply.code(404); return { error: 'no existe' }; }
  if (f.estado !== 'aprobada') { reply.code(400); return { error: 'solo se facturan ordenes aprobadas' }; }
  return await enviarAFacturacion(f, 'envio_manual');
});
/* aprobar firma: marca aprobada y envia documentos al cliente */
app.post('/api/firmas/:token/aprobar', async (req, reply) => {
  const user = requireAuth(req, reply); if (!user) return;
  const f = db.firmas.find(x => x.token === req.params.token);
  if (!f) { reply.code(404); return { error: 'no existe' }; }
  if (f.estado !== 'firmada') { reply.code(400); return { error: 'solo se aprueban ordenes firmadas' }; }
  f.estado = 'aprobada'; f.fechaAprob = new Date().toISOString(); f.aprobadaPor = user; save();
  let facturacion = null;
  if (f.orden?.tot?.ivaOn && (db.kv.factcfg || {}).activo) facturacion = await enviarAFacturacion(f, 'orden_aprobada');
  const correo = f.correoVerificado || f.orden?.cliente?.correo;
  const t = mailer();
  if (!t || !correo) return { ok: true, correoEnviado: false, aviso: !t ? 'SMTP no configurado' : 'cliente sin correo', facturacion };
  const meta = db.kv.docs || {};
  const attachments = DOC_TIPOS.filter(x => meta[x]).map(x => ({ filename: (DOC_LABELS[x] || x) + '.pdf', path: join(DOCS_DIR, x + '.pdf') }));
  const cfg = db.kv.cfg || {};
  const linkDocs = (PUBLIC_URL || '') + '/docs.html?t=' + docsToken();
  try {
    await t.sendMail({ from: '"' + (cfg.marca || 'Cotizador') + '" <' + smtpCfg().from + '>', to: correo,
      subject: 'Orden aprobada ✓ - Documentos de ' + (cfg.marca || 'la empresa'),
      text: 'Cordial saludo ' + (f.firmanteNombre || '') + ',\n\nTu orden de servicio "' + f.docName + '" fue APROBADA. ¡Bienvenido!\n\nAdjuntamos los documentos de la empresa para agilizar tus tramites (RUT, camara de comercio, certificado bancario, etc.).\nTambien puedes verlos y descargarlos aqui: ' + linkDocs + '\n\n' + (cfg.rep || '') + '\n' + (cfg.empresa || '') + '\n' + (cfg.tel1 || '') + (cfg.tel2 ? ' / ' + cfg.tel2 : ''),
      attachments });
    return { ok: true, correoEnviado: true, correo, facturacion };
  } catch (e) { return { ok: true, correoEnviado: false, aviso: 'fallo correo: ' + e.message, facturacion }; }
});

/* ================= API DE AUTOMATIZACION (n8n) ================= */
function fmtCOP(n) { return '$ ' + Math.round(n || 0).toLocaleString('es-CO'); }
function catalogo() { return [...(db.kv.productos || []), ...(db.kv.servicios || [])]; }
function buscarItem(nombre) {
  const q = String(nombre || '').trim().toLowerCase();
  if (!q) return null;
  const cat = catalogo();
  return cat.find(x => (x.nombre || '').toLowerCase() === q) ||
         cat.find(x => (x.nombre || '').toLowerCase().includes(q)) ||
         cat.find(x => q.includes((x.nombre || '').toLowerCase()));
}
function pdfCotizacion(cot, cfg) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margins: { top: 40, left: 45, right: 45, bottom: 40 } });
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    const azul = '#007DB7', navy = '#14395c', gris = '#64748b';
    const W = doc.page.width, M = 45;
    try {
      if (cfg.logo && cfg.logo.startsWith('data:image')) {
        const buf = Buffer.from(cfg.logo.split(',')[1], 'base64');
        doc.image(buf, M, 32, { fit: [150, 60] });
      }
    } catch (e) {}
    doc.font('Helvetica-Bold').fontSize(13).fillColor(navy).text('COTIZACIÓN ' + cot.numero, 300, 40, { width: W - 300 - M, align: 'right' });
    doc.font('Helvetica').fontSize(8.5).fillColor(gris)
      .text((cfg.empresa || '') + '\nNIT ' + (cfg.nit || '') + '\n' + (cot.fecha || ''), 300, 58, { width: W - 300 - M, align: 'right' });
    let y = 105;
    doc.moveTo(M, y).lineTo(W - M, y).lineWidth(1.2).strokeColor(azul).stroke();
    y += 12;
    doc.font('Helvetica-Bold').fontSize(9).fillColor(navy).text('CLIENTE', M, y);
    doc.font('Helvetica').fontSize(9.5).fillColor('#1f2d3a')
      .text(cot.cliente.nombre + (cot.cliente.cedula ? ('  ·  CC/NIT ' + cot.cliente.cedula) : ''), M, y + 12)
      .text((cot.cliente.correo || '') + (cot.cliente.tel ? ('  ·  Tel ' + cot.cliente.tel) : ''), M, y + 25);
    y += 48;
    // tabla
    const cols = [ { t: 'ÍTEM', w: 215 }, { t: 'CANT', w: 50, r: 1 }, { t: 'VLR UNITARIO', w: 115, r: 1 }, { t: 'VLR TOTAL', w: 125, r: 1 } ];
    let x = M;
    doc.rect(M, y, W - 2 * M, 18).fillColor(azul).fill();
    doc.fillColor('#fff').font('Helvetica-Bold').fontSize(8);
    cols.forEach(c => { doc.text(c.t, x + 5, y + 5, { width: c.w - 10, align: c.r ? 'right' : 'left' }); x += c.w; });
    y += 18;
    doc.font('Helvetica').fontSize(9).fillColor('#1f2d3a');
    (cot.lineas || []).forEach((l, i) => {
      const h = 18;
      if (y + h > doc.page.height - 150) { doc.addPage(); y = 50; }
      if (i % 2) { doc.rect(M, y, W - 2 * M, h).fillColor('#f5f9fc').fill(); doc.fillColor('#1f2d3a'); }
      x = M;
      const vals = [ l.item, String(l.cant), fmtCOP(l.precio), fmtCOP(l.cant * l.precio) ];
      cols.forEach((c, j) => { doc.text(vals[j], x + 5, y + 5, { width: c.w - 10, align: c.r ? 'right' : 'left', ellipsis: true, height: 12 }); x += c.w; });
      y += h;
    });
    y += 10;
    // totales
    const t = cot.tot, bx = W - M - 190, bw = 190;
    const line = (lbl, val, big) => {
      if (big) { doc.rect(bx, y - 3, bw, 18).fillColor(azul).fill(); doc.fillColor('#fff').font('Helvetica-Bold').fontSize(10); }
      else { doc.fillColor(gris).font('Helvetica').fontSize(9); }
      doc.text(lbl, bx + 6, y, { width: bw - 12 }); doc.text(val, bx + 6, y, { width: bw - 12, align: 'right' });
      y += big ? 20 : 14;
    };
    line('Subtotal', fmtCOP(t.sub));
    if (t.dPct > 0) { line('Descuento (' + t.dPct + '%)', '- ' + fmtCOP(t.desc)); line('Base gravable', fmtCOP(t.base)); }
    if (t.ivaOn) line('IVA (' + t.ivaPct + '%)', fmtCOP(t.iva));
    line('TOTAL', fmtCOP(t.total), true);
    y += 8;
    doc.font('Helvetica-Oblique').fontSize(8).fillColor(gris)
      .text((cfg.vigencia || '') + '\nGenerada automáticamente por el asistente de ' + (cfg.marca || 'la empresa') + '.', M, y, { width: W - 2 * M });
    if (cot.aceptaToken && PUBLIC_URL) {
      y = doc.y + 16;
      const uAc = PUBLIC_URL + '/aceptar.html?t=' + cot.aceptaToken;
      const bw2 = 250, bh2 = 34, bx2 = (W - bw2) / 2;
      doc.roundedRect(bx2, y, bw2, bh2, 7).fillColor(azul).fill();
      doc.font('Helvetica-Bold').fontSize(13).fillColor('#ffffff').text('ACEPTO ESTA PROPUESTA', bx2, y + 10, { width: bw2, align: 'center' });
      doc.link(bx2, y, bw2, bh2, uAc);
      doc.font('Helvetica').fontSize(7.5).fillColor(gris).text('Para aceptar, haz clic en el botón o abre: ' + uAc, M, y + bh2 + 8, { width: W - 2 * M, align: 'center', link: uAc });
    }
    // pie
    doc.rect(0, doc.page.height - 42, W, 42).fillColor(azul).fill();
    doc.fillColor('#fff').font('Helvetica').fontSize(8)
      .text((cfg.empresa || '') + '  ·  ' + (cfg.dir || '') + '  ·  ' + (cfg.tel1 || '') + (cfg.tel2 ? ' / ' + cfg.tel2 : '') + '  ·  ' + (cfg.web || ''), M, doc.page.height - 28, { width: W - 2 * M, align: 'center' });
    doc.end();
  });
}
/* crear cotizacion completa desde n8n */
app.post('/api/n8n/cotizacion', async (req, reply) => {
  if (!requireAuthOrKey(req, reply)) return;
  const { cliente, items, descuento, iva } = req.body || {};
  if (!cliente?.nombre || !Array.isArray(items) || !items.length) { reply.code(400); return { error: 'faltan cliente.nombre o items' }; }
  const cfg = db.kv.cfg || {};
  db.kv.clientes = db.kv.clientes || [];
  let cli = db.kv.clientes.find(c => (c.cedula && cliente.cedula && c.cedula === cliente.cedula) || c.nombre.toLowerCase() === cliente.nombre.toLowerCase());
  if (!cli) {
    cli = { id: crypto.randomBytes(6).toString('hex'), nombre: cliente.nombre, cedula: cliente.cedula || '', correo: cliente.correo || '', tel: cliente.tel || '' };
    db.kv.clientes.push(cli);
  } else { if (cliente.correo) cli.correo = cliente.correo; if (cliente.tel) cli.tel = cliente.tel; }
  const lineas = []; const noEncontrados = [];
  for (const it of items) {
    const cat = buscarItem(it.nombre);
    const precio = it.precio != null ? +it.precio : (cat ? +cat.precio : 0);
    const nombre = cat ? cat.nombre : String(it.nombre);
    if (!cat && it.precio == null) noEncontrados.push(String(it.nombre));
    lineas.push({ item: nombre, desc: cat?.desc || '', cant: +it.cant || 1, precio });
  }
  const sub = lineas.reduce((a, l) => a + l.cant * l.precio, 0);
  const dPct = +descuento || 0, desc = sub * dPct / 100, base = sub - desc;
  const ivaOn = iva !== false, ivaPct = +cfg.iva || 19, ivaV = ivaOn ? base * ivaPct / 100 : 0, total = base + ivaV;
  const numero = (cfg.prefijo || 'COT') + '-' + String(cfg.consecutivo || 1).padStart(4, '0');
  const cot = { id: crypto.randomBytes(6).toString('hex'), numero, autor: 'asistente-n8n', aceptaToken: crypto.randomBytes(14).toString('hex'),
    fecha: new Date().toLocaleDateString('es-CO', { day: '2-digit', month: '2-digit', year: 'numeric' }),
    cliente: cli, lineas, tot: { sub, dPct, desc, base, ivaOn, ivaPct, iva: ivaV, total }, total };
  const pdfBuf = await pdfCotizacion(cot, cfg);
  const file = crypto.randomBytes(10).toString('hex') + '_Cotizacion_' + numero + '.pdf';
  writeFileSync(join(PDF_DIR, file), pdfBuf);
  cot.pdfUrl = (PUBLIC_URL || '') + '/p/' + file;
  db.kv.historial = db.kv.historial || [];
  db.kv.historial.push(cot);
  cfg.consecutivo = (cfg.consecutivo || 1) + 1; db.kv.cfg = cfg;
  save();
  const resumen = lineas.map(l => '• ' + l.cant + ' x ' + l.item + ' = ' + fmtCOP(l.cant * l.precio)).join('\n');
  return { ok: true, numero, total: fmtCOP(total), pdfUrl: cot.pdfUrl, cliente: { nombre: cli.nombre, correo: cli.correo, tel: cli.tel },
    resumen, avisos: noEncontrados.length ? ('Items sin precio en catálogo (quedaron en $0): ' + noEncontrados.join(', ')) : null };
});
/* consultar cotizacion */
app.get('/api/n8n/cotizacion/:numero', async (req, reply) => {
  if (!requireAuthOrKey(req, reply)) return;
  const cot = (db.kv.historial || []).find(h => h.numero.toLowerCase() === String(req.params.numero).toLowerCase());
  if (!cot) { reply.code(404); return { error: 'no existe ' + req.params.numero }; }
  return { ok: true, numero: cot.numero, total: fmtCOP(cot.total), pdfUrl: cot.pdfUrl || null,
    pdfFile: cot.pdfUrl ? cot.pdfUrl.split('/p/')[1] : null,
    cliente: { nombre: cot.cliente.nombre, correo: cot.cliente.correo || '', tel: cot.cliente.tel || '' } };
});
/* convertir cotizacion en orden + enlace de firma */
app.post('/api/n8n/orden', async (req, reply) => {
  if (!requireAuthOrKey(req, reply)) return;
  const { numero } = req.body || {};
  const cot = (db.kv.historial || []).find(h => h.numero.toLowerCase() === String(numero || '').toLowerCase());
  if (!cot) { reply.code(404); return { error: 'no existe ' + numero }; }
  const cfg = db.kv.cfg || {};
  const rows = (cot.lineas || []).map(l => ({ serv: l.item + (l.cant > 1 ? ' (x' + l.cant + ')' : ''), bw: '', ciudad: cfg.ciudad || '', dir: '', inst: fmtCOP(l.cant * l.precio), mes: '' }));
  const items = (cot.lineas || []).map(l => ({ item: l.item, desc: l.desc || '', cant: +l.cant || 1, precio: +l.precio || 0 }));
  const esInternet = (cot.lineas || []).some(l => /internet|mb\b|mbps|plan/i.test(l.item || ''));
  const orden = { cliente: cot.cliente, fecha: new Date().toLocaleDateString('es-CO'), tipoDoc: 'NIT', numDoc: cot.cliente.cedula || '',
    tipo: esInternet ? 'internet' : 'venta', items, dirGen: '', ciudadGen: cfg.ciudad || '',
    rows, cond: (db.kv.condOrden || '1. Los valores presentados INCLUYEN el IVA del 19%.'), tot: { ...cot.tot, mes: 0, mesIva: 0 } };
  const token = crypto.randomBytes(14).toString('hex');
  const hash = crypto.createHash('sha256').update(JSON.stringify(orden)).digest('hex');
  db.firmas.push({ token, docName: 'Orden de servicio - ' + cot.cliente.nombre + ' (' + cot.numero + ')', orden,
    empresa: { nombre: cfg.empresa, nit: cfg.nit, eslogan: cfg.eslogan, logo: cfg.logo }, hash,
    creada: new Date().toISOString(), creadaPor: 'asistente-n8n', estado: 'pendiente' });
  save();
  return { ok: true, numero: cot.numero, firmaUrl: (PUBLIC_URL || '') + '/firmar.html?t=' + token, token,
    cliente: { nombre: cot.cliente.nombre, correo: cot.cliente.correo || '', tel: cot.cliente.tel || '' }, total: fmtCOP(cot.total) };
});

app.get('/salud', async () => ({ ok: true, app: 'cotizador', ts: Date.now() }));
await app.register(fstatic, { root: join(__dirname, 'public'), prefix: '/' });

app.listen({ port: PORT, host: '0.0.0.0' }).then(() => console.log('Cotizador Mi Empresa escuchando en puerto', PORT));
