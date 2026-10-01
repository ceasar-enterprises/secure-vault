#!/usr/bin/env node

const { parseArgs, die, info, warn, heading, fmtSize, reqFlag, askPw, printHelp, VERSION, VAULT_PATH } = require('./cli');

async function run() {
  var a = parseArgs(process.argv);
  var cmd = a.command;
  var f = a.flags;

  if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') { printHelp(); return; }

  var FileEncryptor = require('./lib/files');
  var VolumeManager = require('./lib/volume');
  var PasswordManager = require('./lib/passwords');
  var SecureShredder = require('./lib/shredder');
  var DriveManager = require('./lib/drives');

  var fileEnc = new FileEncryptor(VAULT_PATH);
  var volMgr = new VolumeManager(VAULT_PATH);
  var passMgr = new PasswordManager(VAULT_PATH);
  var shredder = new SecureShredder();
  var driveMgr = new DriveManager();

  try {
    switch (cmd) {

    // ===== FILE ENCRYPTION =====
    case 'encrypt': {
      if (f.file) {
        var p = require('path').resolve(reqFlag(f, 'file'));
        var pw = f.password || await askPw('Encryption password');
        if (!pw) die('Password required');
        var r = await fileEnc.encryptFile(p, pw, f.output);
        heading('File Encrypted');
        info('Output: ' + r.encryptedPath);
        info('Size: ' + fmtSize(r.encryptedSize));
      } else if (f.folder) {
        var p = require('path').resolve(reqFlag(f, 'folder'));
        var pw = f.password || await askPw('Encryption password');
        if (!pw) die('Password required');
        var r = await fileEnc.encryptFolder(p, pw);
        heading('Folder Encrypted');
        info('Files: ' + r.totalFiles);
        r.results.forEach(function (x) { if (x.error) warn('  ' + x.path + ': ' + x.error); });
      } else { die('Use --file or --folder'); }
      break;
    }

    case 'decrypt': {
      var p = require('path').resolve(reqFlag(f, 'file'));
      var pw = f.password || await askPw('Decryption password');
      if (!pw) die('Password required');
      var r = await fileEnc.decryptFile(p, pw, f.output);
      heading('File Decrypted');
      info('Output: ' + r.path);
      info('Size: ' + fmtSize(r.size));
      break;
    }

    case 'list-files': {
      var files = fileEnc.getEncryptedFiles();
      heading('Encrypted Files (' + files.length + ')');
      files.forEach(function (x) {
        console.log('  ' + x.name + '  ' + fmtSize(x.size) + '  ' + x.encryptedAt);
      });
      break;
    }

    // ===== VOLUMES =====
    case 'create-volume': {
      var fp = require('path').resolve(reqFlag(f, 'file'));
      var sz = parseInt(reqFlag(f, 'size'), 10);
      if (isNaN(sz) || sz < 1) die('Invalid size');
      var pw = f.password || await askPw('Volume password');
      if (!pw) die('Password required');
      var algo = f.algo !== undefined ? parseInt(f.algo, 10) : 0;
      var pim = f.pim ? parseInt(f.pim, 10) : 1;
      var r = await volMgr.createVolume(fp, pw, sz, { algorithm: algo, pim: pim });
      heading('Volume Created');
      info('File: ' + r.path);
      info('Size: ' + fmtSize(r.size));
      info('Algorithm: ' + r.algorithmName);
      break;
    }

    case 'mount': {
      var vp = require('path').resolve(reqFlag(f, 'volume'));
      var pw = f.password || await askPw('Volume password');
      if (!pw) die('Password required');
      var r = await volMgr.mountVolume(vp, pw);
      heading('Volume Mounted');
      info('Drive: ' + r.driveLetter);
      info('Algorithm: ' + r.algorithm);
      break;
    }

    case 'unmount': {
      var letter = reqFlag(f, 'drive').replace(':', '').toUpperCase();
      var r = volMgr.unmountVolume(letter);
      info('Unmounted ' + letter + ':');
      break;
    }

    case 'unmount-all': {
      var r = volMgr.unmountAll();
      info('Unmounted ' + r.length + ' volume(s)');
      break;
    }

    case 'mounted': {
      var m = volMgr.getMounted();
      heading('Mounted Volumes (' + m.length + ')');
      m.forEach(function (x) {
        console.log('  ' + x.driveLetter + ': ' + x.volumePath);
      });
      break;
    }

    case 'volume-info': {
      var vp = require('path').resolve(reqFlag(f, 'volume'));
      var info2 = volMgr.getVolumeInfo(vp);
      heading('Volume Info');
      Object.keys(info2).forEach(function (k) {
        console.log('  ' + k + ': ' + info2[k]);
      });
      break;
    }

    case 'change-password': {
      var vp = require('path').resolve(reqFlag(f, 'volume'));
      var oldPw = f['old-password'] || await askPw('Old password');
      var newPw = f['new-password'] || await askPw('New password');
      if (!oldPw || !newPw) die('Both passwords required');
      var r = await volMgr.changePassword(vp, oldPw, newPw);
      info('Password changed for ' + vp);
      break;
    }

    case 'backup-header': {
      var vp = require('path').resolve(reqFlag(f, 'volume'));
      var out = require('path').resolve(reqFlag(f, 'output'));
      var r = volMgr.backupHeader(vp, out);
      info('Header backed up to ' + r.backupPath + ' (' + r.size + ' bytes)');
      break;
    }

    case 'restore-header': {
      var vp = require('path').resolve(reqFlag(f, 'volume'));
      var bp = require('path').resolve(reqFlag(f, 'backup'));
      volMgr.restoreHeader(vp, bp);
      info('Header restored');
      break;
    }

    case 'delete-volume': {
      var vp = require('path').resolve(reqFlag(f, 'volume'));
      if (!f.yes) {
        warn('This will permanently shred the volume file.');
        var confirm = await askPw('Type YES to confirm');
        if (confirm !== 'YES') die('Aborted');
      }
      volMgr.deleteVolume(vp);
      info('Volume deleted and shredded');
      break;
    }

    case 'list-volumes': {
      var vols = volMgr.listVolumes();
      heading('Volumes (' + vols.length + ')');
      vols.forEach(function (v) {
        console.log('  ' + v.path + '  ' + fmtSize(v.size) + '  ' + (v.algorithmName || '?') + (v.hidden ? ' [HIDDEN]' : '') + (v.exists ? '' : ' [MISSING]'));
      });
      break;
    }

    // ===== HIDDEN VOLUMES =====
    case 'create-hidden': {
      var vp = require('path').resolve(reqFlag(f, 'volume'));
      var sz = parseInt(reqFlag(f, 'size'), 10);
      if (isNaN(sz) || sz < 1) die('Invalid size');
      var outerPw = f.password || await askPw('Outer volume password');
      var hiddenPw = f['hidden-password'] || await askPw('Hidden volume password');
      if (!outerPw || !hiddenPw) die('Both passwords required');
      var r = await volMgr.createHiddenVolume(vp, outerPw, hiddenPw, sz);
      heading('Hidden Volume Created');
      info('Inside: ' + vp);
      info('Size: ' + fmtSize(r.size));
      break;
    }

    case 'mount-hidden': {
      var vp = require('path').resolve(reqFlag(f, 'volume'));
      var pw = f.password || await askPw('Hidden volume password');
      if (!pw) die('Password required');
      var r = await volMgr.mountHiddenVolume(vp, pw);
      heading('Hidden Volume Mounted');
      info('Drive: ' + r.driveLetter);
      break;
    }

    // ===== FLASH DRIVE =====
    case 'detect-drives': {
      var drives = driveMgr.detectDrives();
      heading('Detected Drives (' + drives.length + ')');
      drives.forEach(function (d) {
        var rem = d.isRemovable ? ' [REMOVABLE]' : '';
        var size = d.totalSize ? fmtSize(d.totalSize) : '?';
        console.log('  ' + d.letter + '  ' + (d.name || d.typeLabel) + '  ' + d.fileSystem + '  ' + size + rem);
      });
      break;
    }

    case 'encrypt-drive': {
      var letter = reqFlag(f, 'drive').replace(':', '').toUpperCase();
      var sz = parseInt(reqFlag(f, 'size'), 10);
      var pw = f.password || await askPw('Drive encryption password');
      if (!pw) die('Password required');
      var r = await driveMgr.encryptFlashDrive(letter, pw, sz);
      heading('Drive Encrypted');
      info('Drive: ' + letter + ':');
      info('Container: ' + r.containerPath);
      break;
    }

    case 'decrypt-drive': {
      var letter = reqFlag(f, 'drive').replace(':', '').toUpperCase();
      var pw = f.password || await askPw('Drive decryption password');
      if (!pw) die('Password required');
      var r = await driveMgr.decryptFlashDrive(letter, pw);
      info('Volume verified on ' + letter + ':');
      break;
    }

    case 'wipe-drive': {
      var letter = reqFlag(f, 'drive').replace(':', '').toUpperCase();
      if (!f.yes) {
        warn('This will PERMANENTLY DESTROY all files on ' + letter + ':');
        var confirm = await askPw('Type YES to confirm');
        if (confirm !== 'YES') die('Aborted');
      }
      var r = driveMgr.secureWipeDrive(letter);
      info('Wiped ' + r.shredded + ' files on ' + letter + ':');
      if (r.failed > 0) warn(r.failed + ' file(s) could not be shredded');
      break;
    }

    // ===== PASSWORD MANAGER =====
    case 'add-password': {
      var title = reqFlag(f, 'title');
      var pw = f.password || await askPw('Password to store');
      var master = f.master || await askPw('Master password');
      if (!pw || !master) die('Password and master password required');
      var r = passMgr.addEntry({
        title: title,
        username: f.username || '',
        password: pw,
        url: f.url || '',
        notes: f.notes || '',
        category: f.category || 'General'
      }, master);
      info('Added: ' + title + ' (id: ' + r.id + ')');
      break;
    }

    case 'get-password': {
      var id = reqFlag(f, 'id');
      var master = f.master || await askPw('Master password');
      if (!master) die('Master password required');
      var entry = passMgr.getEntry(id, master);
      heading('Password Entry');
      console.log('  title:    ' + entry.title);
      console.log('  username: ' + entry.username);
      console.log('  password: ' + entry.password);
      console.log('  url:      ' + entry.url);
      console.log('  category: ' + entry.category);
      if (entry.notes) console.log('  notes:    ' + entry.notes);
      break;
    }

    case 'list-passwords': {
      var master = f.master || await askPw('Master password');
      if (!master) die('Master password required');
      var entries = passMgr.getAllEntries(master);
      heading('Passwords (' + entries.length + ')');
      entries.forEach(function (e) {
        if (e.error) { warn('  ' + e.id + ': ' + e.error); return; }
        console.log('  ' + e.id.substring(0, 8) + '..  ' + e.title + '  [' + e.category + ']  ' + (e.username || ''));
      });
      break;
    }

    case 'delete-password': {
      var id = reqFlag(f, 'id');
      passMgr.deleteEntry(id);
      info('Deleted');
      break;
    }

    case 'generate-password': {
      var len = f.length ? parseInt(f.length, 10) : 20;
      var pw = passMgr.generatePassword(len);
      console.log(pw);
      break;
    }

    // ===== SHREDDER =====
    case 'shred': {
      var passes = f.passes ? parseInt(f.passes, 10) : 3;
      if (f.file) {
        var p = require('path').resolve(reqFlag(f, 'file'));
        var r = shredder.shredFile(p, passes);
        info('Shredded: ' + r.path + ' (' + r.passes + ' passes)');
      } else if (f.folder) {
        var p = require('path').resolve(reqFlag(f, 'folder'));
        var r = shredder.shredFolder(p, passes);
        info('Shredded ' + r.filesShredded + ' files in ' + r.folder);
      } else { die('Use --file or --folder'); }
      break;
    }

    case 'shred-free': {
      var letter = reqFlag(f, 'drive').replace(':', '').toUpperCase();
      var sz = f.size ? parseInt(f.size, 10) : 100;
      var r = shredder.shredFreeSpace(letter, sz);
      info('Shredded ' + r.spaceShredded + ' MB free space on ' + letter + ':');
      break;
    }

    default:
      die('Unknown command: ' + cmd + '. Run with "help" for usage.');
    }
  } catch (e) {
    die(e.message);
  }
}

run().catch(function (e) { die(e.message); });
