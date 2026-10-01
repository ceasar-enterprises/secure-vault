const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { deriveKey, encryptBuffer, decryptBuffer, ALGO, generateSalt, generateIV, AUTH_TAG_LENGTH } = require('./crypto');

const CHUNK_SIZE = 64 * 1024;
const MAGIC = Buffer.from('SECVLT1');
const HEADER_SIZE = MAGIC.length + 4 + 32 + 16 + 4; // magic + version + salt + iv + origSize

function sanitizePath(p) {
  // resolve to absolute, reject traversal
  const resolved = path.resolve(p);
  return resolved;
}

class FileEncryptor {
  constructor(vaultPath) {
    this.vaultPath = vaultPath;
    this.metaFile = path.join(vaultPath, 'data', 'files.json');
    this.meta = this._load();
  }

  _load() {
    try {
      if (fs.existsSync(this.metaFile)) {
        return JSON.parse(fs.readFileSync(this.metaFile, 'utf8'));
      }
    } catch (e) {
      // corrupted metadata — start fresh
    }
    return { files: [], folders: [] };
  }

  _save() {
    fs.mkdirSync(path.dirname(this.metaFile), { recursive: true });
    fs.writeFileSync(this.metaFile, JSON.stringify(this.meta, null, 2));
  }

  async encryptFile(inputPath, password, outputPath) {
    inputPath = sanitizePath(inputPath);
    if (!fs.existsSync(inputPath)) throw new Error('File not found');

    const stat = fs.statSync(inputPath);
    if (!stat.isFile()) throw new Error('Not a file');

    const fileId = crypto.randomUUID();
    const salt = generateSalt();
    const iv = generateIV();
    const key = await deriveKey(password, salt);

    const output = outputPath || inputPath + '.svault';
    const fd = fs.openSync(output, 'w');

    try {
      // write header: magic + version + salt + iv + originalSize
      const header = Buffer.alloc(HEADER_SIZE);
      let off = 0;
      MAGIC.copy(header, off); off += MAGIC.length;
      header.writeUInt32BE(1, off); off += 4;
      salt.copy(header, off); off += 32;
      iv.copy(header, off); off += 16;
      header.writeUInt32BE(stat.size, off);
      fs.writeSync(fd, header);

      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
      const inputFd = fs.openSync(inputPath, 'r');
      const buf = Buffer.alloc(CHUNK_SIZE);
      let totalRead = 0;

      try {
        while (totalRead < stat.size) {
          const toRead = Math.min(CHUNK_SIZE, stat.size - totalRead);
          const bytesRead = fs.readSync(inputFd, buf, 0, toRead, totalRead);
          if (bytesRead === 0) break;
          // must copy subarray — Node v24 doesn't copy on slice
          const chunk = Buffer.from(buf.subarray(0, bytesRead));
          const encrypted = cipher.update(chunk);
          fs.writeSync(fd, encrypted);
          totalRead += bytesRead;
        }
      } finally {
        fs.closeSync(inputFd);
      }

      const final = cipher.final();
      if (final.length > 0) fs.writeSync(fd, final);
      fs.writeSync(fd, cipher.getAuthTag());
    } finally {
      fs.closeSync(fd);
    }

    const record = {
      id: fileId,
      name: path.basename(inputPath),
      originalPath: inputPath,
      encryptedPath: output,
      size: stat.size,
      encryptedSize: fs.statSync(output).size,
      encryptedAt: new Date().toISOString(),
      algorithm: 'aes-256-gcm'
    };

    this.meta.files.push(record);
    this._save();
    return record;
  }

  async decryptFile(encryptedPath, password, outputPath) {
    encryptedPath = sanitizePath(encryptedPath);
    if (!fs.existsSync(encryptedPath)) throw new Error('Encrypted file not found');

    const fd = fs.openSync(encryptedPath, 'r');

    try {
      // read and validate magic
      const magicBuf = Buffer.alloc(MAGIC.length);
      fs.readSync(fd, magicBuf, 0, MAGIC.length, 0);
      if (!magicBuf.equals(MAGIC)) {
        throw new Error('Not a SecureVault file');
      }

      let off = MAGIC.length;
      // version (skip for now)
      const vBuf = Buffer.alloc(4);
      fs.readSync(fd, vBuf, 0, 4, off); off += 4;

      const salt = Buffer.alloc(32);
      fs.readSync(fd, salt, 0, 32, off); off += 32;

      const iv = Buffer.alloc(16);
      fs.readSync(fd, iv, 0, 16, off); off += 16;

      const sizeBuf = Buffer.alloc(4);
      fs.readSync(fd, sizeBuf, 0, 4, off); off += 4;
      const originalSize = sizeBuf.readUInt32BE(0);

      const stat = fs.statSync(encryptedPath);
      const authTag = Buffer.alloc(16);
      fs.readSync(fd, authTag, 0, 16, stat.size - 16);

      const key = await deriveKey(password, salt);

      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
      decipher.setAuthTag(authTag);

      const dataSize = stat.size - off - 16;
      const output = outputPath || encryptedPath.replace('.svault', '');
      const outFd = fs.openSync(output, 'w');

      try {
        const buf = Buffer.alloc(CHUNK_SIZE);
        let totalRead = 0;

        while (totalRead < dataSize) {
          const toRead = Math.min(CHUNK_SIZE, dataSize - totalRead);
          const bytesRead = fs.readSync(fd, buf, 0, toRead, off + totalRead);
          if (bytesRead === 0) break;
          const chunk = Buffer.from(buf.subarray(0, bytesRead));
          const decrypted = decipher.update(chunk);
          fs.writeSync(outFd, decrypted);
          totalRead += bytesRead;
        }

        const final = decipher.final();
        if (final.length > 0) fs.writeSync(outFd, final);
      } finally {
        fs.closeSync(outFd);
      }
    } finally {
      fs.closeSync(fd);
    }

    return {
      path: outputPath || encryptedPath.replace('.svault', ''),
      size: (await fs.promises.stat(outputPath || encryptedPath.replace('.svault', ''))).size,
      decryptedAt: new Date().toISOString()
    };
  }

  async encryptFolder(folderPath, password) {
    folderPath = sanitizePath(folderPath);
    if (!fs.existsSync(folderPath)) throw new Error('Folder not found');

    const files = [];
    const walk = (dir) => {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else files.push(full);
      }
    };
    walk(folderPath);

    const results = [];
    for (const file of files) {
      try {
        results.push(await this.encryptFile(file, password));
      } catch (e) {
        results.push({ path: file, error: e.message });
      }
    }

    this.meta.folders.push({
      id: crypto.randomUUID(),
      path: folderPath,
      fileCount: files.length,
      encryptedAt: new Date().toISOString()
    });
    this._save();
    return { totalFiles: files.length, results };
  }

  getEncryptedFiles() { return this.meta.files; }

  getStats() {
    const files = this.meta.files;
    return {
      fileCount: files.length,
      folderCount: this.meta.folders.length,
      totalOriginalSize: files.reduce((s, f) => s + f.size, 0),
      totalEncryptedSize: files.reduce((s, f) => s + f.encryptedSize, 0)
    };
  }
}

module.exports = FileEncryptor;
