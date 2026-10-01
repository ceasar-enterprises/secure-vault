const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const TEMP_BASE = path.join(os.tmpdir(), 'svault_mounts');

// validate drive letter — only single uppercase A-Z allowed
function validLetter(letter) {
  return typeof letter === 'string' && /^[A-Z]$/.test(letter);
}

class MountManager {
  constructor() {
    this.mountsFile = path.join(__dirname, '..', 'data', 'mounts.json');
    this.mounts = this._load();
    if (!fs.existsSync(TEMP_BASE)) {
      fs.mkdirSync(TEMP_BASE, { recursive: true });
    }
  }

  _load() {
    try {
      if (fs.existsSync(this.mountsFile)) {
        return JSON.parse(fs.readFileSync(this.mountsFile, 'utf8'));
      }
    } catch (e) {}
    return {};
  }

  _save() {
    fs.mkdirSync(path.dirname(this.mountsFile), { recursive: true });
    fs.writeFileSync(this.mountsFile, JSON.stringify(this.mounts, null, 2));
  }

  getAvailableDriveLetter() {
    const used = new Set();
    try {
      const output = execFileSync('wmic', ['logicaldisk', 'get', 'DeviceID'], {
        encoding: 'utf8', timeout: 5000
      });
      const matches = output.match(/[A-Z]:/g);
      if (matches) matches.forEach(m => used.add(m[0]));
    } catch (e) {
      // assume common drives are used
      for (const d of 'CDEFGHIJKLMNOP') used.add(d);
    }
    // pick first available from Z downwards
    for (let i = 90; i >= 65; i--) {
      const ch = String.fromCharCode(i);
      if (!used.has(ch)) return ch;
    }
    throw new Error('No drive letters available');
  }

  mount(volumePath, driveLetter, mountId) {
    if (!validLetter(driveLetter)) throw new Error('Invalid drive letter');
    // sanitize mountId — strip anything that isn't alphanumeric, dash, or underscore
    mountId = mountId.replace(/[^a-zA-Z0-9_-]/g, '_');

    const mountDir = path.join(TEMP_BASE, mountId);
    if (!fs.existsSync(mountDir)) {
      fs.mkdirSync(mountDir, { recursive: true });
    }

    try {
      // use execFileSync to avoid shell injection
      execFileSync('subst', [driveLetter + ':', mountDir], { timeout: 5000 });
    } catch (e) {
      throw new Error('subst failed: ' + e.message);
    }

    this.mounts[driveLetter] = {
      volumePath,
      mountDir,
      mountId,
      mountedAt: new Date().toISOString()
    };
    this._save();
    return { driveLetter, mountDir, mountedAt: this.mounts[driveLetter].mountedAt };
  }

  unmount(driveLetter) {
    if (!validLetter(driveLetter)) throw new Error('Invalid drive letter');

    try {
      execFileSync('subst', [driveLetter + ':', '/d'], { timeout: 5000 });
    } catch (e) {}

    const mount = this.mounts[driveLetter];
    if (mount) {
      try {
        if (fs.existsSync(mount.mountDir)) {
          for (const f of fs.readdirSync(mount.mountDir)) {
            try { fs.unlinkSync(path.join(mount.mountDir, f)); } catch (e) {}
          }
          fs.rmdirSync(mount.mountDir);
        }
      } catch (e) {}
      delete this.mounts[driveLetter];
      this._save();
    }
    return { unmounted: true, driveLetter };
  }

  unmountAll() {
    const results = [];
    for (const letter of Object.keys(this.mounts)) {
      results.push(this.unmount(letter));
    }
    return results;
  }

  getMounted() {
    return Object.entries(this.mounts).map(([letter, info]) => ({ driveLetter: letter, ...info }));
  }

  cleanup() {
    for (const letter of Object.keys(this.mounts)) this.unmount(letter);
    try {
      if (fs.existsSync(TEMP_BASE)) fs.rmdirSync(TEMP_BASE);
    } catch (e) {}
  }
}

module.exports = MountManager;
