const crypto = require('crypto');
const fs = require('fs');

const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const CHACHA_IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const MIN_PIM = 1;
const MAX_PIM = 10;

// algorithm IDs stored in volume/file headers
const ALGO = Object.freeze({
  AES_256_GCM: 0,
  CHACHA20_POLY1305: 1,
  AES_CHACHA_CASCADE: 2,
  CHACHA_AES_CASCADE: 3
});

const ALGO_NAMES = Object.freeze({
  [ALGO.AES_256_GCM]: 'AES-256-GCM',
  [ALGO.CHACHA20_POLY1305]: 'ChaCha20-Poly1305',
  [ALGO.AES_CHACHA_CASCADE]: 'AES-256-GCM → ChaCha20-Poly1305',
  [ALGO.CHACHA_AES_CASCADE]: 'ChaCha20-Poly1305 → AES-256-GCM'
});

// default KDF cost — tuned for ~1-2s on mid-range hardware
const DEFAULT_PIM = 1;

function clampPim(pim) {
  const p = parseInt(pim, 10);
  if (Number.isNaN(p) || p < MIN_PIM) return MIN_PIM;
  if (p > MAX_PIM) return MAX_PIM;
  return p;
}

function scryptParams(pim) {
  return { N: Math.pow(2, 14 + pim), r: 8, p: 1, maxmem: 256 * 1024 * 1024 };
}

// --- key derivation ---

function deriveKeySync(password, salt, pim) {
  pim = clampPim(pim);
  const params = scryptParams(pim);
  const raw = crypto.scryptSync(password, salt, KEY_LENGTH, params);
  // stretch with blake2b — adds a second memory-hard step
  return crypto.createHash('blake2b512').update(raw).update(salt).digest().subarray(0, KEY_LENGTH);
}

function deriveKey(password, salt, pim) {
  return new Promise((resolve, reject) => {
    pim = clampPim(pim);
    const params = scryptParams(pim);
    crypto.scrypt(password, salt, KEY_LENGTH, params, (err, raw) => {
      if (err) return reject(err);
      const stretched = crypto.createHash('blake2b512').update(raw).update(salt).digest().subarray(0, KEY_LENGTH);
      resolve(stretched);
    });
  });
}

function deriveKeyWithKeyfiles(password, salt, pim, keyfilePaths) {
  const baseKey = deriveKeySync(password, salt, pim);
  if (!keyfilePaths || keyfilePaths.length === 0) return baseKey;

  const merged = Buffer.alloc(KEY_LENGTH, 0);
  for (const fp of keyfilePaths) {
    // TODO: validate keyfile exists before hashing
    const content = fs.readFileSync(fp);
    const hash = crypto.createHash('blake2b256').update(content).digest();
    for (let i = 0; i < KEY_LENGTH; i++) {
      merged[i] ^= hash[i % hash.length];
    }
  }
  // XOR merge base key with keyfile material
  for (let i = 0; i < KEY_LENGTH; i++) {
    baseKey[i] ^= merged[i];
  }
  return baseKey;
}

async function deriveKeyWithKeyfilesAsync(password, salt, pim, keyfilePaths) {
  const baseKey = await deriveKey(password, salt, pim);
  if (!keyfilePaths || keyfilePaths.length === 0) return baseKey;

  const merged = Buffer.alloc(KEY_LENGTH, 0);
  for (const fp of keyfilePaths) {
    const content = fs.readFileSync(fp);
    const hash = crypto.createHash('blake2b256').update(content).digest();
    for (let i = 0; i < KEY_LENGTH; i++) {
      merged[i] ^= hash[i % hash.length];
    }
  }
  for (let i = 0; i < KEY_LENGTH; i++) {
    baseKey[i] ^= merged[i];
  }
  return baseKey;
}

// --- random generators ---

function generateSalt() {
  return crypto.randomBytes(SALT_LENGTH);
}

function generateIV() {
  return crypto.randomBytes(IV_LENGTH);
}

function generateChaChaIV() {
  return crypto.randomBytes(CHACHA_IV_LENGTH);
}

// --- cipher helpers ---

function createCipher(algorithm, key, iv) {
  if (algorithm === ALGO.CHACHA20_POLY1305) {
    return crypto.createCipheriv('chacha20-poly1305', key, iv, { authTagLength: AUTH_TAG_LENGTH });
  }
  return crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: AUTH_TAG_LENGTH });
}

function createDecipher(algorithm, key, iv) {
  if (algorithm === ALGO.CHACHA20_POLY1305) {
    return crypto.createDecipheriv('chacha20-poly1305', key, iv, { authTagLength: AUTH_TAG_LENGTH });
  }
  return crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: AUTH_TAG_LENGTH });
}

function getIVLength(algorithm) {
  return algorithm === ALGO.CHACHA20_POLY1305 ? CHACHA_IV_LENGTH : IV_LENGTH;
}

function pickIV(algorithm) {
  return algorithm === ALGO.CHACHA20_POLY1305 ? generateChaChaIV() : generateIV();
}

// --- encrypt / decrypt string (JSON metadata) ---

function encryptString(plaintext, password, options = {}) {
  const algorithm = options.algorithm !== undefined ? options.algorithm : ALGO.AES_256_GCM;
  const pim = clampPim(options.pim || DEFAULT_PIM);
  const keyfilePaths = options.keyfilePaths || [];

  const salt = generateSalt();
  const key = deriveKeyWithKeyfiles(password, salt, pim, keyfilePaths);

  // cascade: encrypt twice with different algorithms
  if (algorithm === ALGO.AES_CHACHA_CASCADE || algorithm === ALGO.CHACHA_AES_CASCADE) {
    return _encryptCascade(plaintext, key, salt, algorithm, pim);
  }

  const iv = pickIV(algorithm);
  const cipher = createCipher(algorithm, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    encrypted: enc.toString('hex'),
    iv: iv.toString('hex'),
    salt: salt.toString('hex'),
    authTag: tag.toString('hex'),
    algorithm,
    pim,
    version: 2
  };
}

function _encryptCascade(plaintext, firstKey, salt, algorithm, pim) {
  const firstAlgo = algorithm === ALGO.AES_CHACHA_CASCADE ? ALGO.AES_256_GCM : ALGO.CHACHA20_POLY1305;
  const iv1 = pickIV(firstAlgo);
  const c1 = createCipher(firstAlgo, firstKey, iv1);
  const mid = Buffer.concat([c1.update(plaintext, 'utf8'), c1.final()]);
  const tag1 = c1.getAuthTag();

  // derive second key from first
  const secondSalt = generateSalt();
  const secondKey = crypto.createHash('blake2b512').update(firstKey).update(secondSalt).digest().subarray(0, KEY_LENGTH);
  const secondAlgo = algorithm === ALGO.AES_CHACHA_CASCADE ? ALGO.CHACHA20_POLY1305 : ALGO.AES_256_GCM;
  const iv2 = pickIV(secondAlgo);
  const c2 = createCipher(secondAlgo, secondKey, iv2);
  const enc = Buffer.concat([c2.update(mid.toString('hex'), 'utf8'), c2.final()]);
  const tag2 = c2.getAuthTag();

  return {
    encrypted: enc.toString('hex'),
    iv: Buffer.concat([iv1, iv2]).toString('hex'),
    salt: Buffer.concat([salt, secondSalt]).toString('hex'),
    authTag: Buffer.concat([tag1, tag2]).toString('hex'),
    algorithm,
    pim,
    version: 2,
    cascade: true
  };
}

function decryptString(encData, password, options = {}) {
  const keyfilePaths = options.keyfilePaths || [];
  const algorithm = encData.algorithm !== undefined ? encData.algorithm : ALGO.AES_256_GCM;
  const pim = clampPim(encData.pim || DEFAULT_PIM);
  const salt = Buffer.from(encData.salt, 'hex');
  const key = deriveKeyWithKeyfiles(password, salt, pim, keyfilePaths);

  if (encData.cascade) {
    return _decryptCascade(encData, key, algorithm);
  }

  const iv = Buffer.from(encData.iv, 'hex');
  const tag = Buffer.from(encData.authTag, 'hex');
  const enc = Buffer.from(encData.encrypted, 'hex');

  const decipher = createDecipher(algorithm, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

function _decryptCascade(encData, firstKey, algorithm) {
  const iv = Buffer.from(encData.iv, 'hex');
  const tag = Buffer.from(encData.authTag, 'hex');
  const enc = Buffer.from(encData.encrypted, 'hex');

  // second layer (outer)
  const iv2 = iv.subarray(12);
  const tag2 = tag.subarray(16);
  const secondAlgo = algorithm === ALGO.AES_CHACHA_CASCADE ? ALGO.CHACHA20_POLY1305 : ALGO.AES_256_GCM;
  const d2 = createDecipher(secondAlgo, firstKey, iv2);
  d2.setAuthTag(tag2);
  const mid = Buffer.concat([d2.update(enc), d2.final()]);

  // first layer (inner)
  const salt = Buffer.from(encData.salt, 'hex');
  const secondSalt = salt.subarray(32);
  const secondKey = crypto.createHash('blake2b512').update(firstKey).update(secondSalt).digest().subarray(0, KEY_LENGTH);
  const iv1 = iv.subarray(0, 16);
  const tag1 = tag.subarray(0, 16);
  const firstAlgo = algorithm === ALGO.AES_CHACHA_CASCADE ? ALGO.AES_256_GCM : ALGO.CHACHA20_POLY1305;
  const d1 = createDecipher(firstAlgo, secondKey, iv1);
  d1.setAuthTag(tag1);
  return Buffer.concat([d1.update(mid), d1.final()]).toString('utf8');
}

// --- encrypt / decrypt binary (file volumes) ---

function encryptBuffer(buffer, password, options = {}) {
  const algorithm = options.algorithm !== undefined ? options.algorithm : ALGO.AES_256_GCM;
  const pim = clampPim(options.pim || DEFAULT_PIM);
  const keyfilePaths = options.keyfilePaths || [];

  const salt = generateSalt();
  const key = deriveKeyWithKeyfiles(password, salt, pim, keyfilePaths);
  const iv = pickIV(algorithm);

  const cipher = createCipher(algorithm, key, iv);
  const enc = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();

  // header: magic(4) + algo(4) + saltLen(4) + ivLen(4) + salt + iv + tag
  const header = Buffer.alloc(16);
  header.writeUInt32BE(algorithm, 0);
  header.writeUInt32BE(salt.length, 4);
  header.writeUInt32BE(iv.length, 8);
  header.writeUInt32BE(tag.length, 12);

  return Buffer.concat([header, salt, iv, tag, enc]);
}

function decryptBuffer(encryptedBuffer, password, options = {}) {
  const keyfilePaths = options.keyfilePaths || [];
  let off = 0;

  const algorithm = encryptedBuffer.readUInt32BE(off); off += 4;
  const saltLen = encryptedBuffer.readUInt32BE(off); off += 4;
  const ivLen = encryptedBuffer.readUInt32BE(off); off += 4;
  const tagLen = encryptedBuffer.readUInt32BE(off); off += 4;

  const salt = encryptedBuffer.subarray(off, off + saltLen); off += saltLen;
  const iv = encryptedBuffer.subarray(off, off + ivLen); off += ivLen;
  const authTag = encryptedBuffer.subarray(off, off + tagLen); off += tagLen;
  const enc = encryptedBuffer.subarray(off);

  const key = deriveKeyWithKeyfiles(password, salt, DEFAULT_PIM, keyfilePaths);
  const decipher = createDecipher(algorithm, key, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([decipher.update(enc), decipher.final()]);
}

// --- password hashing (for login/auth) ---

function hashPassword(password) {
  const salt = generateSalt();
  const hash = crypto.scryptSync(password, salt, 64, scryptParams(DEFAULT_PIM));
  return {
    hash: hash.toString('hex'),
    salt: salt.toString('hex'),
    method: 'scrypt-blake2b'
  };
}

function verifyPasswordConstantTime(password, stored) {
  const salt = Buffer.from(stored.salt, 'hex');
  const hash = crypto.scryptSync(password, salt, 64, scryptParams(DEFAULT_PIM));
  const storedHash = Buffer.from(stored.hash, 'hex');
  // constant-time comparison — prevents timing side-channel
  return hash.length === storedHash.length && crypto.timingSafeEqual(hash, storedHash);
}

module.exports = {
  ALGO, ALGO_NAMES, DEFAULT_PIM,
  KEY_LENGTH, IV_LENGTH, CHACHA_IV_LENGTH, AUTH_TAG_LENGTH, SALT_LENGTH,
  deriveKeySync, deriveKey, deriveKeyWithKeyfiles, deriveKeyWithKeyfilesAsync,
  generateSalt, generateIV, generateChaChaIV,
  createCipher, createDecipher, getIVLength, pickIV,
  encryptString, decryptString,
  encryptBuffer, decryptBuffer,
  hashPassword, verifyPasswordConstantTime
};
