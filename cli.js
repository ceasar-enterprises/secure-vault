#!/usr/bin/env node

/*
 * SecureVault — CLI Encryption Suite
 *
 * A command-line tool for encrypting files, managing encrypted volumes,
 * and securely storing passwords. Uses AES-256-GCM, ChaCha20-Poly1305,
 * and cascading encryption with memory-hard key derivation.
 *
 * Usage: node index.js <command> [options]
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const VERSION = '2.0.0';
const VAULT_PATH = __dirname;

function parseArgs(argv) {
  const args = argv.slice(2);
  const command = args[0] || '';
  const flags = {};
  const positional = [];
  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = args[i + 1];
      if (next && !next.startsWith('--')) { flags[key] = next; i++; }
      else { flags[key] = true; }
    } else if (arg.startsWith('-')) {
      const key = arg.slice(1);
      const next = args[i + 1];
      if (next && !next.startsWith('-')) { flags[key] = next; i++; }
      else { flags[key] = true; }
    } else { positional.push(arg); }
  }
  return { command, flags, positional };
}

function die(msg) { console.error('\x1b[31merror:\x1b[0m ' + msg); process.exit(1); }
function info(msg) { console.log('\x1b[32mok\x1b[0m ' + msg); }
function warn(msg) { console.log('\x1b[33m!\x1b[0m ' + msg); }
function heading(msg) { console.log('\n\x1b[1;36m' + msg + '\x1b[0m'); }

function fmtSize(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

function reqFlag(flags, name) {
  if (!flags[name]) die('Missing --' + name);
  return flags[name];
}

async function askPw(msg) {
  msg = msg || 'Password';
  return new Promise(function (resolve) {
    process.stdout.write(msg + ': ');
    var stdin = process.stdin;
    var raw = stdin.isRaw;
    if (stdin.isTTY) stdin.setRawMode(true);
    var pw = '';
    function onKey(ch) {
      var c = ch.toString();
      if (c === '\n' || c === '\r') {
        if (stdin.isTTY) stdin.setRawMode(raw || false);
        stdin.removeListener('data', onKey);
        process.stdout.write('\n');
        resolve(pw);
      } else if (c === '\u0003') { process.exit(1); }
      else if (c === '\u007F' || c === '\b') { if (pw.length > 0) pw = pw.slice(0, -1); }
      else { pw += c; }
    }
    stdin.on('data', onKey);
  });
}

function printHelp() {
  console.log([
    '',
    '  SecureVault v' + VERSION + ' — CLI Encryption Suite',
    '',
    '  \x1b[1mFILE ENCRYPTION\x1b[0m',
    '    encrypt --file <path> [--password <pw>] [--output <path>]',
    '    decrypt --file <path> [--password <pw>] [--output <path>]',
    '    encrypt --folder <path> [--password <pw>]',
    '    list-files',
    '',
    '  \x1b[1mENCRYPTED VOLUMES\x1b[0m',
    '    create-volume --file <path> --size <MB> [--password <pw>] [--algo <0-3>] [--pim <n>]',
    '    mount --volume <path> [--password <pw>]',
    '    unmount --drive <letter>',
    '    unmount-all',
    '    mounted',
    '    volume-info --volume <path>',
    '    change-password --volume <path> [--old-password <pw>] [--new-password <pw>]',
    '    backup-header --volume <path> --output <path>',
    '    restore-header --volume <path> --backup <path>',
    '    delete-volume --volume <path>',
    '    list-volumes',
    '',
    '  \x1b[1mHIDDEN VOLUMES\x1b[0m',
    '    create-hidden --volume <path> --size <MB> [--hidden-password <pw>]',
    '    mount-hidden --volume <path> [--password <pw>]',
    '',
    '  \x1b[1mFLASH DRIVE\x1b[0m',
    '    detect-drives',
    '    encrypt-drive --drive <letter> --size <MB> [--password <pw>]',
    '    decrypt-drive --drive <letter> [--password <pw>]',
    '    wipe-drive --drive <letter>',
    '',
    '  \x1b[1mPASSWORD MANAGER\x1b[0m',
    '    add-password --title <t> [--username <u>] [--password <pw>] [--master <pw>]',
    '    get-password --id <id> [--master <pw>]',
    '    list-passwords [--master <pw>]',
    '    delete-password --id <id>',
    '    generate-password [--length <n>]',
    '',
    '  \x1b[1mSHREDDER\x1b[0m',
    '    shred --file <path> [--passes <n>]',
    '    shred --folder <path> [--passes <n>]',
    '    shred-free --drive <letter> [--size <MB>]',
    '',
    '  \x1b[1mALGORITHMS\x1b[0m',
    '    0 = AES-256-GCM   1 = ChaCha20-Poly1305',
    '    2 = AES->ChaCha    3 = ChaCha->AES',
    ''
  ].join('\n'));
}

module.exports = { parseArgs, die, info, warn, heading, fmtSize, reqFlag, askPw, printHelp, VERSION, VAULT_PATH };
