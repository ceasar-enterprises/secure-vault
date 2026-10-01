const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class SecureShredder {
  constructor() {
    this.passes = 3;
    this.logFile = null;
  }

  setLogFile(p) { this.logFile = p; }

  _log(msg) {
    const entry = '[' + new Date().toISOString() + '] ' + msg;
    if (this.logFile) fs.appendFileSync(this.logFile, entry + '\n');
    return entry;
  }

  shredFile(filePath, passes) {
    passes = passes || this.passes;
    if (!fs.existsSync(filePath)) throw new Error('Not found: ' + filePath);
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) throw new Error('Not a file: ' + filePath);

    this._log('Shredding ' + path.basename(filePath) + ' (' + stat.size + ' bytes, ' + passes + ' passes)');

    const fd = fs.openSync(filePath, 'r+');
    try {
      for (let pass = 0; pass < passes; pass++) {
        // patterns: random, 0x00, 0xFF — decent DoD-style
        const buf = pass % 2 === 0
          ? crypto.randomBytes(Math.min(64 * 1024, stat.size))
          : Buffer.alloc(Math.min(64 * 1024, stat.size), pass % 3 === 1 ? 0x00 : 0xFF);

        let written = 0;
        while (written < stat.size) {
          const toWrite = Math.min(buf.length, stat.size - written);
          fs.writeSync(fd, buf, 0, toWrite, written);
          written += toWrite;
        }
        fs.fsyncSync(fd);
        this._log('  pass ' + (pass + 1) + '/' + passes + ' done');
      }
    } finally {
      fs.closeSync(fd);
    }

    fs.unlinkSync(filePath);
    this._log('Deleted ' + path.basename(filePath));
    return { path: filePath, shredded: true, passes };
  }

  shredFolder(folderPath, passes) {
    passes = passes || this.passes;
    if (!fs.existsSync(folderPath)) throw new Error('Not found: ' + folderPath);

    const results = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else {
          try { results.push(this.shredFile(full, passes)); }
          catch (e) { results.push({ path: full, error: e.message }); }
        }
      }
    };
    walk(folderPath);

    // try to remove empty dirs bottom-up
    const removeEmpty = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) removeEmpty(path.join(dir, entry.name));
      }
      try { fs.rmdirSync(dir); } catch (e) { /* not empty or permission denied */ }
    };
    removeEmpty(folderPath);

    return {
      folder: folderPath,
      filesShredded: results.filter(r => r.shredded).length,
      results
    };
  }

  shredFreeSpace(driveLetter, sizeMB) {
    sizeMB = sizeMB || 100;
    // validate drive letter
    if (!/^[A-Z]$/.test(driveLetter)) throw new Error('Invalid drive letter');

    const tempDir = path.join(driveLetter + ':\\', '.svault_shred_' + crypto.randomBytes(4).toString('hex'));
    fs.mkdirSync(tempDir, { recursive: true });

    const chunkSize = 1024 * 1024;
    const totalBytes = sizeMB * 1024 * 1024;
    let written = 0;

    this._log('Shredding free space on ' + driveLetter + ': ' + sizeMB + 'MB');

    try {
      while (written < totalBytes) {
        const toWrite = Math.min(chunkSize, totalBytes - written);
        const tempFile = path.join(tempDir, crypto.randomBytes(8).toString('hex'));
        fs.writeFileSync(tempFile, crypto.randomBytes(toWrite));
        written += toWrite;
      }

      // shred the temp files
      for (const f of fs.readdirSync(tempDir)) {
        try { this.shredFile(path.join(tempDir, f), 1); } catch (e) {}
      }
    } finally {
      try { fs.rmdirSync(tempDir); } catch (e) {}
    }

    this._log('Free space shredded on ' + driveLetter);
    return { drive: driveLetter, spaceShredded: sizeMB, unit: 'MB' };
  }
}

module.exports = SecureShredder;
