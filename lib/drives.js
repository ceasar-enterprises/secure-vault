const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const CryptoEngine = require('./crypto');

const CHUNK_SIZE = 1024 * 1024;

// only allow single uppercase letters as drive identifiers
function validateDriveLetter(letter) {
  if (!letter || typeof letter !== 'string') return false;
  return /^[A-Z]$/.test(letter);
}

class DriveManager {
  constructor() {
    this.vaultConfig = null;
  }

  detectDrives() {
    try {
      // use execFileSync to avoid shell injection
      const output = execFileSync('wmic', [
        'logicaldisk', 'get',
        'DeviceID,VolumeName,Size,FreeSpace,FileSystem,DriveType',
        '/format:csv'
      ], { encoding: 'utf8', timeout: 10000 });

      const lines = output.trim().split('\n').filter(l => l.trim());
      const drives = [];

      // CSV header: Node,DeviceID,DriveType,FileSystem,FreeSpace,Size,VolumeName
      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].split(',');
        if (parts.length >= 7) {
          const driveType = parseInt(parts[2], 10);
          drives.push({
            letter: parts[1],
            name: (parts[6] || '').replace(/\r/g, '').trim(),
            totalSize: parseInt(parts[5], 10) || 0,
            freeSpace: parseInt(parts[4], 10) || 0,
            fileSystem: parts[3],
            type: driveType,
            typeLabel: this._typeName(driveType),
            isRemovable: driveType === 2
          });
        }
      }
      return drives;
    } catch (e) {
      return this._fallbackDetect();
    }
  }

  _typeName(type) {
    return { 0:'Unknown', 1:'No Root', 2:'Removable Disk', 3:'Local Disk', 4:'Network', 5:'CD-ROM', 6:'RAM' }[type] || 'Unknown';
  }

  _fallbackDetect() {
    try {
      const output = execFileSync('wmic', ['logicaldisk', 'get', 'DeviceID,DriveType', '/format:csv'], {
        encoding: 'utf8', timeout: 5000
      });
      const drives = [];
      const lines = output.trim().split('\n').filter(l => l.trim());
      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].split(',');
        if (parts.length >= 3 && parts[1]) {
          const t = parseInt(parts[2], 10) || 3;
          drives.push({ letter: parts[1], type: t, typeLabel: this._typeName(t), isRemovable: t === 2 });
        }
      }
      return drives;
    } catch (e) {
      return [];
    }
  }

  getRemovableDrives() {
    return this.detectDrives().filter(d => d.isRemovable);
  }

  async encryptFlashDrive(driveLetter, password, volumeSizeMB) {
    if (!validateDriveLetter(driveLetter)) throw new Error('Invalid drive letter');

    const drives = this.detectDrives();
    const drive = drives.find(d => d.letter === driveLetter + ':');
    if (!drive) throw new Error('Drive not found');
    if (!drive.isRemovable) throw new Error('Not a removable drive');

    const containerPath = path.join(drive.letter + '\\', 'SecureVault.dat');
    const headerPath = path.join(drive.letter + '\\', '.svault_header');
    const totalSize = volumeSizeMB * 1024 * 1024;

    const salt = CryptoEngine.generateSalt();
    const iv = CryptoEngine.generateIV();
    const key = await CryptoEngine.deriveKey(password, salt);

    // write header as binary (not plaintext JSON)
    const hdr = Buffer.alloc(7 + 4 + 32 + 16 + 8);
    let off = 0;
    Buffer.from('SECVLTD').copy(hdr, off); off += 7;
    hdr.writeUInt32BE(1, off); off += 4;
    salt.copy(hdr, off); off += 32;
    iv.copy(hdr, off); off += 16;
    hdr.writeBigUInt64BE(BigInt(totalSize), off);
    fs.writeFileSync(headerPath, hdr);

    const fd = fs.openSync(containerPath, 'w');
    const bufSize = Math.min(CHUNK_SIZE, totalSize);
    const buf = crypto.randomBytes(bufSize);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });

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
    fs.closeSync(fd);

    return {
      drive: driveLetter,
      containerPath,
      headerPath,
      volumeSize: totalSize,
      encryptedAt: new Date().toISOString()
    };
  }

  async decryptFlashDrive(driveLetter, password) {
    if (!validateDriveLetter(driveLetter)) throw new Error('Invalid drive letter');

    const headerPath = path.join(driveLetter + ':\\', '.svault_header');
    const containerPath = path.join(driveLetter + ':\\', 'SecureVault.dat');
    if (!fs.existsSync(headerPath)) throw new Error('No encrypted volume on this drive');

    const hdr = fs.readFileSync(headerPath);
    if (hdr.length < 7 + 4 + 32 + 16 + 8) throw new Error('Corrupted header');
    if (hdr.subarray(0, 7).toString() !== 'SECVLTD') throw new Error('Invalid header magic');

    let off = 7;
    off += 4; // version
    const salt = Buffer.from(hdr.subarray(off, off + 32)); off += 32;
    const iv = Buffer.from(hdr.subarray(off, off + 16)); off += 16;
    // const volSize = Number(hdr.readBigUInt64BE(off)); off += 8;

    const key = await CryptoEngine.deriveKey(password, salt);
    const testBuf = Buffer.alloc(16);
    const fd = fs.openSync(containerPath, 'r');
    fs.readSync(fd, testBuf, 0, 16, 0);
    fs.closeSync(fd);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    try {
      decipher.update(testBuf);
      decipher.final();
      return { valid: true };
    } catch (e) {
      throw new Error('Wrong password');
    }
  }

  secureWipeDrive(driveLetter) {
    if (!validateDriveLetter(driveLetter)) throw new Error('Invalid drive letter');

    const drives = this.detectDrives();
    const drive = drives.find(d => d.letter === driveLetter + ':');
    if (!drive) throw new Error('Drive not found');

    const dir = drive.letter + '\\';
    const files = fs.readdirSync(dir);
    const shredded = [];
    const failed = [];

    for (const file of files) {
      const fp = path.join(dir, file);
      try {
        if (fs.statSync(fp).isFile()) {
          this._shredFile(fp);
          shredded.push(fp);
        }
      } catch (e) {
        failed.push({ path: fp, error: e.message });
      }
    }

    return { wiped: true, drive: driveLetter, shredded: shredded.length, failed: failed.length };
  }

  _shredFile(filePath) {
    const stat = fs.statSync(filePath);
    const fd = fs.openSync(filePath, 'r+');
    try {
      // 3-pass: random, zeros, random — then unlink
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
    } finally {
      fs.closeSync(fd);
    }
    fs.unlinkSync(filePath);
  }
}

module.exports = DriveManager;
