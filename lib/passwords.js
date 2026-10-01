const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { encryptString, decryptString } = require('./crypto');

class PasswordManager {
  constructor(vaultPath) {
    this.vaultPath = vaultPath;
    this.dataFile = path.join(vaultPath, 'data', 'passwords.json');
    this.data = this._load();
  }

  _load() {
    try {
      if (fs.existsSync(this.dataFile)) {
        return JSON.parse(fs.readFileSync(this.dataFile, 'utf8'));
      }
    } catch (e) {}
    return { passwords: [], categories: [] };
  }

  _save() {
    fs.mkdirSync(path.dirname(this.dataFile), { recursive: true });
    fs.writeFileSync(this.dataFile, JSON.stringify(this.data, null, 2));
  }

  addEntry(entry, masterPassword) {
    const id = crypto.randomUUID();

    // encrypt ALL sensitive fields — title, category, username are not leaked
    const encrypted = encryptString(JSON.stringify({
      title: entry.title || 'Untitled',
      category: entry.category || 'General',
      username: entry.username || '',
      password: entry.password,
      url: entry.url || '',
      notes: entry.notes || ''
    }), masterPassword);

    const record = {
      id,
      encrypted,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.data.passwords.push(record);
    this._save();
    return { id };
  }

  getEntry(id, masterPassword) {
    const record = this.data.passwords.find(p => p.id === id);
    if (!record) throw new Error('Not found');
    const decrypted = JSON.parse(decryptString(record.encrypted, masterPassword));
    return {
      id: record.id,
      ...decrypted,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt
    };
  }

  getAllEntries(masterPassword) {
    return this.data.passwords.map(p => {
      try {
        const decrypted = JSON.parse(decryptString(p.encrypted, masterPassword));
        return {
          id: p.id,
          title: decrypted.title,
          category: decrypted.category,
          username: decrypted.username,
          password: decrypted.password,
          url: decrypted.url,
          notes: decrypted.notes,
          createdAt: p.createdAt,
          updatedAt: p.updatedAt
        };
      } catch (e) {
        return { id: p.id, error: 'Wrong master password or corrupted entry' };
      }
    });
  }

  updateEntry(id, updates, masterPassword) {
    const index = this.data.passwords.findIndex(p => p.id === id);
    if (index === -1) throw new Error('Not found');

    const existing = JSON.parse(decryptString(this.data.passwords[index].encrypted, masterPassword));
    const merged = { ...existing, ...updates };

    this.data.passwords[index] = {
      id,
      encrypted: encryptString(JSON.stringify(merged), masterPassword),
      createdAt: this.data.passwords[index].createdAt,
      updatedAt: new Date().toISOString()
    };

    this._save();
    return { id, updated: true };
  }

  deleteEntry(id) {
    const index = this.data.passwords.findIndex(p => p.id === id);
    if (index === -1) throw new Error('Not found');
    this.data.passwords.splice(index, 1);
    this._save();
    return { deleted: true };
  }

  search(query, masterPassword) {
    // need master password to search since titles are encrypted
    if (!masterPassword) throw new Error('Master password required to search');
    const results = [];
    for (const p of this.data.passwords) {
      try {
        const dec = JSON.parse(decryptString(p.encrypted, masterPassword));
        const q = query.toLowerCase();
        if (
          dec.title.toLowerCase().includes(q) ||
          dec.category.toLowerCase().includes(q) ||
          dec.username.toLowerCase().includes(q)
        ) {
          results.push({ id: p.id, title: dec.title, category: dec.category, username: dec.username });
        }
      } catch (e) {
        // skip entries that fail to decrypt
      }
    }
    return results;
  }

  generatePassword(length = 20, options = {}) {
    const {
      uppercase = true,
      lowercase = true,
      numbers = true,
      symbols = true
    } = options;

    let chars = '';
    if (lowercase) chars += 'abcdefghijklmnopqrstuvwxyz';
    if (uppercase) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (numbers) chars += '0123456789';
    if (symbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';

    const array = new Uint32Array(length);
    crypto.randomFillSync(array);
    return Array.from(array, x => chars[x % chars.length]).join('');
  }

  getStats() {
    return { totalPasswords: this.data.passwords.length };
  }
}

module.exports = PasswordManager;
