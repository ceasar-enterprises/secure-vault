#!/usr/bin/env node

/*
 * SecureVault GUI — local-only hardened server
 * Binds to 127.0.0.1 only. Not accessible from network.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = 3010;
const HOST = '127.0.0.1';
const VAULT_PATH = __dirname;
const MAX_BODY = 1024 * 1024; // 1MB max request body
const SESSION_TTL = 3600000; // 1 hour

// rate limiter: max 5 login attempts per 15 minutes per IP
const loginAttempts = new Map();
const RATE_WINDOW = 900000;
const RATE_MAX = 5;

function checkRate(ip) {
  const now = Date.now();
  const attempts = (loginAttempts.get(ip) || []).filter(t => now - t < RATE_WINDOW);
  loginAttempts.set(ip, attempts);
  return attempts.length < RATE_MAX;
}

function recordAttempt(ip) {
  const attempts = loginAttempts.get(ip) || [];
  attempts.push(Date.now());
  loginAttempts.set(ip, attempts);
}

// auth system
const AUTH_FILE = path.join(VAULT_PATH, 'data', 'auth.json');

function loadAuth() {
  try {
    if (fs.existsSync(AUTH_FILE)) return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
  } catch (e) {}
  return null;
}

function saveAuth(data) {
  fs.mkdirSync(path.dirname(AUTH_FILE), { recursive: true });
  fs.writeFileSync(AUTH_FILE, JSON.stringify(data, null, 2));
}

function setupPassword(pw) {
  const salt = crypto.randomBytes(32);
  const hash = crypto.scryptSync(pw, salt, 64, { N: 32768, r: 8, p: 1 });
  saveAuth({ hash: hash.toString('hex'), salt: salt.toString('hex'), created: new Date().toISOString() });
}

function verifyPw(pw) {
  const auth = loadAuth();
  if (!auth) return false;
  const salt = Buffer.from(auth.salt, 'hex');
  const hash = crypto.scryptSync(pw, salt, 64, { N: 32768, r: 8, p: 1 });
  const stored = Buffer.from(auth.hash, 'hex');
  return hash.length === stored.length && crypto.timingSafeEqual(hash, stored);
}

// sessions
const sessions = new Map();

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { created: Date.now() });
  return token;
}

function validSession(token) {
  if (!token) return false;
  const s = sessions.get(token);
  if (!s) return false;
  if (Date.now() - s.created > SESSION_TTL) { sessions.delete(token); return false; }
  return true;
}

// body parser with size limit
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY) { req.destroy(); reject(new Error('Body too large')); return; }
      body += chunk;
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch (e) { resolve(body); }
    });
    req.on('error', reject);
  });
}

function json(res, data, status) {
  status = status || 200;
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(data));
}

function serveStatic(res, filePath) {
  if (!fs.existsSync(filePath)) { res.writeHead(404); res.end('Not found'); return; }
  const ext = path.extname(filePath);
  const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.png': 'image/png', '.svg': 'image/svg+xml' };
  res.writeHead(200, { 'Content-Type': types[ext] || 'text/plain', 'X-Content-Type-Options': 'nosniff' });
  fs.createReadStream(filePath).pipe(res);
}

function getClientIP(req) {
  return req.socket.remoteAddress || '127.0.0.1';
}

// API handler
async function handleAPI(req, res, pathname, method, ip) {
  try {
    // --- auth routes (no token required) ---
    if (pathname === '/api/auth/status') {
      const auth = loadAuth();
      return json(res, { configured: !!auth });
    }

    if (pathname === '/api/auth/setup' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.password || body.password.length < 4) return json(res, { error: 'Password too short' }, 400);
      if (loadAuth()) return json(res, { error: 'Already configured' }, 409);
      setupPassword(body.password);
      const token = createSession();
      return json(res, { success: true, token });
    }

    if (pathname === '/api/auth/login' && method === 'POST') {
      if (!checkRate(ip)) return json(res, { error: 'Too many attempts. Try again later.' }, 429);
      const body = await parseBody(req);
      if (!body.password) return json(res, { error: 'Password required' }, 400);
      if (!verifyPw(body.password)) { recordAttempt(ip); return json(res, { error: 'Wrong password' }, 401); }
      const token = createSession();
      return json(res, { success: true, token });
    }

    // --- all routes below require auth ---
    const token = (req.headers.authorization || '').replace('Bearer ', '');
    if (!validSession(token)) return json(res, { error: 'Unauthorized' }, 401);

    // lazy load modules
    const FileEncryptor = require('./lib/files');
    const VolumeManager = require('./lib/volume');
    const PasswordManager = require('./lib/passwords');
    const SecureShredder = require('./lib/shredder');
    const DriveManager = require('./lib/drives');

    const fileEnc = new FileEncryptor(VAULT_PATH);
    const volMgr = new VolumeManager(VAULT_PATH);
    const passMgr = new PasswordManager(VAULT_PATH);
    const shredder = new SecureShredder();
    const driveMgr = new DriveManager();

    // --- stats ---
    if (pathname === '/api/stats') {
      return json(res, {
        files: fileEnc.getStats(),
        passwords: passMgr.getStats(),
        mounted: volMgr.getMounted().length,
        volumes: volMgr.listVolumes().length
      });
    }

    // --- files ---
    if (pathname === '/api/files' && method === 'GET') {
      return json(res, { files: fileEnc.getEncryptedFiles() });
    }
    if (pathname === '/api/files/encrypt' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.filePath || !body.password) return json(res, { error: 'filePath and password required' }, 400);
      const r = await fileEnc.encryptFile(body.filePath, body.password);
      return json(res, { success: true, ...r });
    }
    if (pathname === '/api/files/decrypt' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.filePath || !body.password) return json(res, { error: 'filePath and password required' }, 400);
      const r = await fileEnc.decryptFile(body.filePath, body.password);
      return json(res, { success: true, ...r });
    }

    // --- volumes ---
    if (pathname === '/api/volumes' && method === 'GET') {
      return json(res, { volumes: volMgr.listVolumes() });
    }
    if (pathname === '/api/volumes/mounted' && method === 'GET') {
      return json(res, { mounted: volMgr.getMounted() });
    }
    if (pathname === '/api/volumes/create' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.filePath || !body.password || !body.sizeMB) return json(res, { error: 'filePath, password, sizeMB required' }, 400);
      const r = await volMgr.createVolume(body.filePath, body.password, parseInt(body.sizeMB, 10), {
        algorithm: body.algorithm !== undefined ? parseInt(body.algorithm, 10) : 0,
        pim: body.pim ? parseInt(body.pim, 10) : 1
      });
      return json(res, { success: true, ...r });
    }
    if (pathname === '/api/volumes/mount' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.volumePath || !body.password) return json(res, { error: 'volumePath and password required' }, 400);
      const r = await volMgr.mountVolume(body.volumePath, body.password);
      return json(res, { success: true, ...r });
    }
    if (pathname === '/api/volumes/unmount' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.driveLetter) return json(res, { error: 'driveLetter required' }, 400);
      const r = volMgr.unmountVolume(body.driveLetter);
      return json(res, { success: true, ...r });
    }
    if (pathname === '/api/volumes/unmount-all' && method === 'POST') {
      const r = volMgr.unmountAll();
      return json(res, { success: true, count: r.length });
    }
    if (pathname === '/api/volumes/info' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.volumePath) return json(res, { error: 'volumePath required' }, 400);
      return json(res, { info: volMgr.getVolumeInfo(body.volumePath) });
    }
    if (pathname === '/api/volumes/delete' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.volumePath) return json(res, { error: 'volumePath required' }, 400);
      const r = volMgr.deleteVolume(body.volumePath);
      return json(res, { success: true, ...r });
    }

    // --- drives ---
    if (pathname === '/api/drives' && method === 'GET') {
      return json(res, { drives: driveMgr.detectDrives() });
    }
    if (pathname === '/api/drives/removable' && method === 'GET') {
      return json(res, { drives: driveMgr.getRemovableDrives() });
    }
    if (pathname === '/api/drives/encrypt' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.drive || !body.password || !body.sizeMB) return json(res, { error: 'drive, password, sizeMB required' }, 400);
      const r = await driveMgr.encryptFlashDrive(body.drive, body.password, parseInt(body.sizeMB, 10));
      return json(res, { success: true, ...r });
    }
    if (pathname === '/api/drives/decrypt' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.drive || !body.password) return json(res, { error: 'drive and password required' }, 400);
      const r = await driveMgr.decryptFlashDrive(body.drive, body.password);
      return json(res, { success: true, ...r });
    }
    if (pathname === '/api/drives/wipe' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.drive) return json(res, { error: 'drive required' }, 400);
      const r = driveMgr.secureWipeDrive(body.drive);
      return json(res, { success: true, ...r });
    }

    // --- passwords ---
    if (pathname === '/api/passwords' && method === 'GET') {
      return json(res, { passwords: passMgr.data.passwords.map(p => ({ id: p.id })) });
    }
    if (pathname === '/api/passwords/add' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.title || !body.password || !body.masterPassword) return json(res, { error: 'title, password, masterPassword required' }, 400);
      const r = passMgr.addEntry(body, body.masterPassword);
      return json(res, { success: true, ...r });
    }
    if (pathname === '/api/passwords/get' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.id || !body.masterPassword) return json(res, { error: 'id and masterPassword required' }, 400);
      const r = passMgr.getEntry(body.id, body.masterPassword);
      return json(res, { entry: r });
    }
    if (pathname === '/api/passwords/list' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.masterPassword) return json(res, { error: 'masterPassword required' }, 400);
      const r = passMgr.getAllEntries(body.masterPassword);
      return json(res, { passwords: r });
    }
    if (pathname === '/api/passwords/delete' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.id) return json(res, { error: 'id required' }, 400);
      const r = passMgr.deleteEntry(body.id);
      return json(res, { success: true, ...r });
    }
    if (pathname === '/api/passwords/generate' && method === 'GET') {
      const u = new URL(req.url, 'http://localhost');
      const len = parseInt(u.searchParams.get('length') || '20', 10);
      return json(res, { password: passMgr.generatePassword(len) });
    }

    // --- shredder ---
    if (pathname === '/api/shred' && method === 'POST') {
      const body = await parseBody(req);
      if (!body.filePath) return json(res, { error: 'filePath required' }, 400);
      const r = shredder.shredFile(body.filePath, body.passes || 3);
      return json(res, { success: true, ...r });
    }

    json(res, { error: 'Not found' }, 404);
  } catch (e) {
    json(res, { error: e.message }, 500);
  }
}

// server
const server = http.createServer(async (req, res) => {
  const ip = getClientIP(req);
  const parsed = new URL(req.url, 'http://' + HOST);
  const pathname = parsed.pathname;

  if (pathname.startsWith('/api/')) {
    return handleAPI(req, res, pathname, req.method, ip);
  }

  // static files — only serve from public/
  let filePath;
  if (pathname === '/' || pathname === '/index.html') {
    filePath = path.join(__dirname, 'public', 'index.html');
  } else {
    filePath = path.join(__dirname, 'public', pathname);
  }
  serveStatic(res, filePath);
});

server.listen(PORT, HOST, () => {
  console.log('SecureVault GUI running at http://127.0.0.1:' + PORT);
  console.log('Press Ctrl+C to stop.');
});
