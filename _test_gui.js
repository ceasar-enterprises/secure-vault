const fs = require('fs');
const path = require('path');
const code = fs.readFileSync('gui.js', 'utf8');
const lines = code.split('\n').filter(l => l.includes('require('));
let ok = true;
for (const line of lines) {
  const match = line.match(/require\(['"]([^'"]+)['"]\)/);
  if (match) {
    try {
      const resolved = match[1].startsWith('.') ? path.resolve(match[1]) : match[1];
      require(resolved);
      console.log('  OK:', match[1]);
    } catch(e) {
      console.log('  FAIL:', match[1], '-', e.message);
      ok = false;
    }
  }
}
console.log(ok ? 'GUI: ALL REQUIRES OK' : 'GUI: HAS ISSUES');