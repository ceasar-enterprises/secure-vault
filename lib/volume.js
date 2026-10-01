const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  ALGO, ALGO_NAMES, AUTH_TAG_LENGTH,
  generateSalt, generateIV, generateChaChaIV, pickIV,
  createCipher, createDecipher,
  deriveKeyWithKeyfilesAsync, deriveKeyWithKeyfiles
} = require('./crypto');
const MountManager = require('./mount');

const MAGIC = Buffer.from('SECVLT2');
const VERIFY_PLAINTEXT = Buffer.from('SECVLT_VERIFY_OK');
const CHUNK_SIZE = 64 * 1024;

// binary header layout — all integers are big-endian
const HEADER_FIELDS = [
  ['magic', 7], ['version', 4], ['algorithm', 4], ['salt', 32],
  ['iv', 16], ['pim', 4], ['volumeSize', 8], ['keyfileHash', 32],
  ['verifyIv', 16], ['verifyCipher', 16], ['verifyTag', 16]
];
const HEADER_SIZE = HEADER_FIELDS.reduce((sum, [, len]) => sum + len, 0);
const DATA_START = HEADER_SIZE;

function buildHeader(version, algorithm, salt, iv, pim, volumeSize, keyfileHash, verifyIv, verifyCipher, verifyTag) {
  const buf = Buffer.alloc(HEADER_SIZE);
  let off = 0;
  MAGIC.copy(buf, off); off += 7;
  buf.writeUInt32BE(version, off); off += 4;
  buf.writeUInt32BE(algorithm, off); off += 4;
  salt.copy(buf, off); off += 32;
  iv.copy(buf, off); off += 16;
  buf.writeUInt32BE(pim, off); off += 4;
  buf.writeBigUInt64BE(BigInt(volumeSize), off); off += 8;
  keyfileHash.copy(buf, off); off += 32;
  verifyIv.copy(buf, off); off += 16;
  verifyCipher.copy(buf, off); off += 16;
  verifyTag.copy(buf, off); off += 16;
  return buf;
}

function parseHeader(volumePath) {
  if (!fs.existsSync(volumePath)) throw new Error('Volume not found');
  const fd = fs.openSync(volumePath, 'r');
  try {
    const buf = Buffer.alloc(HEADER_SIZE);
    const bytesRead = fs.readSync(fd, buf, 0, HEADER_SIZE, 0);
    if (bytesRead < HEADER_SIZE) throw new Error('File too small to be a volume');

    let off = 0;
    const magic = buf.subarray(off, off + 7); off += 7;
    if (!magic.equals(MAGIC)) throw new Error('Not a SecureVault volume');

    const version = buf.readUInt32BE(off); off += 4;
    const algorithm = buf.readUInt32BE(off); off += 4;
    const salt = Buffer.from(buf.subarray(off, off + 32)); off += 32;
    const iv = Buffer.from(buf.subarray(off, off + 16)); off += 16;
    const pim = buf.readUInt32BE(off); off += 4;
    const volumeSize = buf.readBigUInt64BE(off); off += 8;
    const keyfileHash = Buffer.from(buf.subarray(off, off + 32)); off += 32;
    const verifyIv = Buffer.from(buf.subarray(off, off + 16)); off += 16;
    const verifyCipher = Buffer.from(buf.subarray(off, off + 16)); off += 16;
    const verifyTag = Buffer.from(buf.subarray(off, off + 16)); off += 16;

    if (version !== 2) throw new Error('Unsupported version: ' + version);
    if (!Object.values(ALGO).includes(algorithm)) throw new Error('Unknown algorithm');

    // ChaCha20 uses 12-byte nonce but stored as 16
    const actualIv = algorithm === ALGO.CHACHA20_POLY1305 ? iv.subarray(0, 12) : iv;

    return { version, algorithm, salt, iv: actualIv, pim, volumeSize, keyfileHash, verifyIv, verifyCipher, verifyTag };
  } finally {
    fs.closeSync(fd);
  }
}

function createVerifyBlock(key) {
  const iv = generateIV();
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  const enc = Buffer.concat([cipher.update(VERIFY_PLAINTEXT), cipher.final()]);
  return { iv, encrypted: enc, tag: cipher.getAuthTag() };
}

function verifyPassword(key, header) {
  let decipher;
  try {
    decipher = crypto.createDecipheriv('aes-256-gcm', key, header.verifyIv, { authTagLength: 16 });
  } catch (e) {
    throw new Error('Wrong password');
  }
  decipher.setAuthTag(header.verifyTag);
  try {
    const result = Buffer.concat([decipher.update(header.verifyCipher), decipher.final()]);
    if (!result.equals(VERIFY_PLAINTEXT)) throw new Error('no match');
  } catch (e) {
    throw new Error('Wrong password');
  }
}

class VolumeManager {
  constructor(vaultPath) {
    this.vaultPath = vaultPath;
    this.volumesFile = path.join(vaultPath, 'data', 'volumes.json');
    this.mountMgr = new MountManager();
    this.volumes = this._load();
  }

  _load() {
    try {
      if (fs.existsSync(this.volumesFile)) {
        return JSON.parse(fs.readFileSync(this.volumesFile, 'utf8'));
      }
    } catch (e) {}
    return [];
  }

  _save() {
    fs.mkdirSync(path.dirname(this.volumesFile), { recursive: true });
    fs.writeFileSync(this.volumesFile, JSON.stringify(this.volumes, null, 2));
  }

  async createVolume(filePath, password, sizeMB, options = {}) {
    const algorithm = options.algorithm !== undefined ? options.algorithm : ALGO.AES_256_GCM;
    const pim = options.pim || 1;
    const keyfilePaths = options.keyfilePaths || [];
    const totalSize = sizeMB * 1024 * 1024;

    const salt = generateSalt();
    const iv = pickIV(algorithm);
    const key = await deriveKeyWithKeyfilesAsync(password, salt, pim, keyfilePaths);

    const keyfileHash = keyfilePaths.length > 0
      ? crypto.createHash('blake2b256').update(Buffer.concat(keyfilePaths.map(fp => fs.readFileSync(fp)))).digest()
      : Buffer.alloc(32, 0);

    const verify = createVerifyBlock(key);
    const header = buildHeader(2, algorithm, salt, iv, pim, totalSize, keyfileHash, verify.iv, verify.encrypted, verify.tag);

    const fd = fs.openSync(filePath, 'w');
    try {
      fs.writeSync(fd, header);

      const cipher = createCipher(algorithm, key, iv);
      const bufSize = Math.min(CHUNK_SIZE, totalSize);
      const buf = crypto.randomBytes(bufSize);
      let written = 0;

      while (written < totalSize) {
        const toWrite = Math.min(bufSize, totalSize - written);
        const chunk = toWrite === bufSize ? buf : crypto.randomBytes(toWrite);
        fs.writeSync(fd, cipher.update(chunk));
        written += toWrite;
      }

      const final = cipher.final();
      if (final.length > 0) fs.writeSync(fd, final);
      fs.writeSync(fd, cipher.getAuthTag());
    } finally {
      fs.closeSync(fd);
    }

    const record = {
      id: crypto.randomUUID(),
      path: filePath,
      size: totalSize,
      algorithm,
      algorithmName: ALGO_NAMES[algorithm],
      pim,
      hasKeyfiles: keyfilePaths.length > 0,
      hidden: false,
      outerVolumePath: null,
      createdAt: new Date().toISOString()
    };

    this.volumes.push(record);
    this._save();
    return record;
  }

  async mountVolume(volumePath, password, options = {}) {
    const keyfilePaths = options.keyfilePaths || [];
    const header = parseHeader(volumePath);

    if (keyfilePaths.length > 0 && header.keyfileHash.equals(Buffer.alloc(32, 0))) {
      throw new Error('Volume was not created with keyfiles');
    }

    const key = await deriveKeyWithKeyfilesAsync(password, header.salt, header.pim, keyfilePaths);
    verifyPassword(key, header);

    const driveLetter = this.mountMgr.getAvailableDriveLetter();
    const mountId = path.basename(volumePath, path.extname(volumePath));
    this.mountMgr.mount(volumePath, driveLetter, mountId);

    return {
      driveLetter: driveLetter + ':',
      volumePath,
      algorithm: ALGO_NAMES[header.algorithm],
      size: Number(header.volumeSize),
      mountedAt: new Date().toISOString()
    };
  }

  unmountVolume(driveLetter) {
    const letter = driveLetter.replace(':', '');
    return this.mountMgr.unmount(letter);
  }

  unmountAll() { return this.mountMgr.unmountAll(); }
  getMounted() { return this.mountMgr.getMounted(); }

  async changePassword(volumePath, oldPassword, newPassword, options = {}) {
    const keyfilePaths = options.keyfilePaths || [];
    const newKeyfilePaths = options.newKeyfilePaths || [];
    const header = parseHeader(volumePath);

    const oldKey = await deriveKeyWithKeyfilesAsync(oldPassword, header.salt, header.pim, keyfilePaths);
    verifyPassword(oldKey, header);

    // decrypt all data into memory
    const fd = fs.openSync(volumePath, 'r');
    const stat = fs.statSync(volumePath);
    const dataSize = stat.size - DATA_START - 16;
    const buf = Buffer.alloc(CHUNK_SIZE);
    const chunks = [];

    let totalRead = 0;
    while (totalRead < dataSize) {
      const toRead = Math.min(CHUNK_SIZE, dataSize - totalRead);
      const bytesRead = fs.readSync(fd, buf, 0, toRead, DATA_START + totalRead);
      if (bytesRead === 0) break;
      chunks.push(Buffer.from(buf.subarray(0, bytesRead)));
      totalRead += bytesRead;
    }

    const authTag = Buffer.alloc(16);
    fs.readSync(fd, authTag, 0, 16, stat.size - 16);
    fs.closeSync(fd);

    const decipher = createDecipher(header.algorithm, oldKey, header.iv);
    decipher.setAuthTag(authTag);
    let decrypted = Buffer.alloc(0);
    for (const chunk of chunks) {
      decrypted = Buffer.concat([decrypted, decipher.update(chunk)]);
    }
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    // re-encrypt with new password
    const newSalt = generateSalt();
    const newPim = options.pim || header.pim;
    const newKey = await deriveKeyWithKeyfilesAsync(newPassword, newSalt, newPim, newKeyfilePaths);
    const newIv = pickIV(header.algorithm);
    const cipher = createCipher(header.algorithm, newKey, newIv);
    const reEncrypted = Buffer.concat([cipher.update(decrypted), cipher.final()]);
    const newAuthTag = cipher.getAuthTag();

    const newKeyfileHash = newKeyfilePaths.length > 0
      ? crypto.createHash('blake2b256').update(Buffer.concat(newKeyfilePaths.map(fp => fs.readFileSync(fp)))).digest()
      : Buffer.alloc(32, 0);

    const verify = createVerifyBlock(newKey);
    const newHeader = buildHeader(2, header.algorithm, newSalt, newIv, newPim, header.volumeSize, newKeyfileHash, verify.iv, verify.encrypted, verify.tag);

    const outFd = fs.openSync(volumePath, 'w');
    try {
      fs.writeSync(outFd, newHeader);
      fs.writeSync(outFd, reEncrypted);
      fs.writeSync(outFd, newAuthTag);
    } finally {
      fs.closeSync(outFd);
    }

    return { changed: true, volumePath };
  }

  getVolumeInfo(volumePath) {
    const header = parseHeader(volumePath);
    const stat = fs.statSync(volumePath);
    const volume = this.volumes.find(v => v.path === volumePath);
    return {
      path: volumePath,
      size: Number(header.volumeSize),
      fileSize: stat.size,
      algorithm: ALGO_NAMES[header.algorithm],
      algorithmId: header.algorithm,
      pim: header.pim,
      hasKeyfiles: !header.keyfileHash.equals(Buffer.alloc(32, 0)),
      version: header.version,
      createdAt: volume ? volume.createdAt : null
    };
  }

  backupHeader(volumePath, backupPath) {
    const fd = fs.openSync(volumePath, 'r');
    try {
      const buf = Buffer.alloc(DATA_START);
      fs.readSync(fd, buf, 0, DATA_START, 0);
      fs.mkdirSync(path.dirname(backupPath), { recursive: true });
      fs.writeFileSync(backupPath, buf);
      return { backedUp: true, backupPath, size: buf.length };
    } finally {
      fs.closeSync(fd);
    }
  }

  restoreHeader(volumePath, backupPath) {
    if (!fs.existsSync(backupPath)) throw new Error('Backup not found');
    const backup = fs.readFileSync(backupPath);
    if (backup.length < DATA_START) throw new Error('Invalid backup');
    if (!backup.subarray(0, 7).equals(MAGIC)) throw new Error('Invalid backup magic');

    const fd = fs.openSync(volumePath, 'r+');
    try {
      fs.writeSync(fd, backup, 0, DATA_START, 0);
      return { restored: true, volumePath };
    } finally {
      fs.closeSync(fd);
    }
  }

  deleteVolume(volumePath) {
    // shred before deleting — this is a security tool
    if (fs.existsSync(volumePath)) {
      const stat = fs.statSync(volumePath);
      const fd = fs.openSync(volumePath, 'r+');
      // 3-pass overwrite: random, zeros, random
      for (let pass = 0; pass < 3; pass++) {
        const buf = pass === 1
          ? Buffer.alloc(Math.min(64 * 1024, stat.size), 0)
          : crypto.randomBytes(Math.min(64 * 1024, stat.size));
        let written = 0;
        while (written < stat.size) {
          const toWrite = Math.min(buf.length, stat.size - written);
          fs.writeSync(fd, buf, 0, toWrite, written);
          written += toWrite;
        }
        fs.fsyncSync(fd);
      }
      fs.closeSync(fd);
      fs.unlinkSync(volumePath);
    }
    this.volumes = this.volumes.filter(v => v.path !== volumePath);
    this._save();
    return { deleted: true, volumePath };
  }

  async createHiddenVolume(outerVolumePath, outerPassword, hiddenPassword, hiddenSizeMB, options = {}) {
    const algorithm = options.algorithm !== undefined ? options.algorithm : ALGO.AES_256_GCM;
    const pim = options.pim || 1;
    const keyfilePaths = options.keyfilePaths || [];
    const hiddenKeyfilePaths = options.hiddenKeyfilePaths || [];

    const outerStat = fs.statSync(outerVolumePath);
    const outerHeader = parseHeader(outerVolumePath);
    const hiddenSize = hiddenSizeMB * 1024 * 1024;

    if (hiddenSize >= outerStat.size - DATA_START - 16) {
      throw new Error('Hidden volume too large for outer volume');
    }

    const outerKey = await deriveKeyWithKeyfilesAsync(outerPassword, outerHeader.salt, outerHeader.pim, keyfilePaths);
    verifyPassword(outerKey, outerHeader);

    const hiddenSalt = generateSalt();
    const hiddenIv = pickIV(algorithm);
    const hiddenKey = await deriveKeyWithKeyfilesAsync(hiddenPassword, hiddenSalt, pim, hiddenKeyfilePaths);

    const hiddenKeyfileHash = hiddenKeyfilePaths.length > 0
      ? crypto.createHash('blake2b256').update(Buffer.concat(hiddenKeyfilePaths.map(fp => fs.readFileSync(fp)))).digest()
      : Buffer.alloc(32, 0);

    const verify = createVerifyBlock(hiddenKey);
    const hiddenHeader = buildHeader(2, algorithm, hiddenSalt, hiddenIv, pim, hiddenSize, hiddenKeyfileHash, verify.iv, verify.encrypted, verify.tag);

    const fd = fs.openSync(outerVolumePath, 'r+');
    try {
      // overwrite the outer header with hidden header
      fs.writeSync(fd, hiddenHeader, 0, DATA_START, 0);

      const cipher = createCipher(algorithm, hiddenKey, hiddenIv);
      const buf = crypto.randomBytes(Math.min(CHUNK_SIZE, hiddenSize));
      let written = 0;
      while (written < hiddenSize) {
        const toWrite = Math.min(buf.length, hiddenSize - written);
        const chunk = toWrite === buf.length ? buf : crypto.randomBytes(toWrite);
        fs.writeSync(fd, cipher.update(chunk), 0, cipher.update(chunk).length, DATA_START + written);
        written += toWrite;
      }
      const final = cipher.final();
      if (final.length > 0) fs.writeSync(fd, final, 0, final.length, DATA_START + written);
      fs.writeSync(fd, cipher.getAuthTag(), 0, 16, DATA_START + hiddenSize);
    } finally {
      fs.closeSync(fd);
    }

    const record = {
      id: crypto.randomUUID(),
      path: outerVolumePath,
      size: hiddenSize,
      algorithm,
      algorithmName: ALGO_NAMES[algorithm],
      pim,
      hasKeyfiles: hiddenKeyfilePaths.length > 0,
      hidden: true,
      outerVolumePath,
      createdAt: new Date().toISOString()
    };
    this.volumes.push(record);
    this._save();
    return record;
  }

  async mountHiddenVolume(outerVolumePath, hiddenPassword, options = {}) {
    const hiddenKeyfilePaths = options.hiddenKeyfilePaths || [];
    const header = parseHeader(outerVolumePath);
    const key = await deriveKeyWithKeyfilesAsync(hiddenPassword, header.salt, header.pim, hiddenKeyfilePaths);
    verifyPassword(key, header);

    const driveLetter = this.mountMgr.getAvailableDriveLetter();
    const mountId = 'hidden-' + path.basename(outerVolumePath, path.extname(outerVolumePath));
    this.mountMgr.mount(outerVolumePath, driveLetter, mountId);

    return {
      driveLetter: driveLetter + ':',
      volumePath: outerVolumePath,
      algorithm: ALGO_NAMES[header.algorithm],
      size: Number(header.volumeSize),
      hidden: true,
      mountedAt: new Date().toISOString()
    };
  }

  listVolumes() {
    return this.volumes.map(v => ({
      ...v,
      algorithmName: ALGO_NAMES[v.algorithm],
      exists: fs.existsSync(v.path)
    }));
  }
}

module.exports = VolumeManager;
