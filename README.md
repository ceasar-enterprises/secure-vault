# SecureVault 2.0

Multi-algorithm encryption suite with encrypted volumes, hidden volumes, keyfiles, and a cyberpunk dashboard.

**Zero npm dependencies.** Pure Node.js crypto.

## Quick Start

```bash
node index.js
```

Open `http://localhost:3010` — login password: `1010F`

## Features

### Multi-Algorithm Encryption
- **AES-256-GCM** — industry standard, fast
- **ChaCha20-Poly1305** — faster on CPUs without AES-NI
- **AES → ChaCha cascade** — double encryption, both algorithms
- **ChaCha → AES cascade** — reverse cascade

### Encrypted Volumes
Create encrypted container files (`.svol`) that mount as Windows drive letters:

1. Create a volume (set size, algorithm, password)
2. Mount it — appears as a drive letter (e.g. `Z:`)
3. Use it like a normal drive
4. Unmount when done — data is encrypted at rest

### Hidden Volumes
Plausible deniability — create a hidden volume inside an outer volume:
- Outer password reveals the outer volume
- Hidden password reveals the hidden volume
- Different passwords, same file

### Keyfiles
Use one or more keyfiles as additional authentication:
- Password + keyfile(s) required to decrypt
- Keyfiles are XOR-merged with the password-derived key

### PIM (Personal Iterations Multiplier)
Adjust scrypt memory cost:
- PIM 1 = default (N=2^15 = 32768)
- PIM 5 = high security (N=2^19 = 524288)
- Higher PIM = slower but more brute-force resistant

### File Encryption
Encrypt/decrypt individual files or entire folders with AES-256-GCM.

### Password Manager
Store encrypted passwords with master password protection. Categories, search, generation.

### Secure Shredder
Overwrite files before deletion (3/5/7 passes — Standard, DoD 5220.22-M, Gutmann).

### System Lock
Lock your Windows session from the dashboard.

## Architecture

```
secure-vault/
├── index.js              # HTTP server + API routes
├── lib/
│   ├── crypto.js         # Multi-algorithm engine (AES, ChaCha20, cascades, Blake2b)
│   ├── volume.js         # Volume create/mount/unmount/password-change/header-backup
│   ├── mount.js          # Windows drive letter mounting via subst
│   ├── files.js          # File/folder encryption
│   ├── drives.js         # Drive detection + flash encryption
│   ├── passwords.js      # Password manager
│   ├── shredder.js       # Secure file deletion
│   └── lock.js           # System lock screen
├── public/
│   └── index.html        # Dashboard UI (cyberpunk theme)
├── data/                 # Runtime metadata
│   ├── files.json        # Encrypted file records
│   ├── passwords.json    # Password entries
│   ├── volumes.json      # Volume registry
│   └── mounts.json       # Active mounts
└── package.json
```

## API Reference

### Authentication
| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | `{ password }` | Login |

### Volumes
| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| GET | `/api/volumes` | — | List all volumes |
| POST | `/api/volumes/create` | `{ filePath, password, sizeMB, algorithm, pim }` | Create volume |
| POST | `/api/volumes/mount` | `{ volumePath, password }` | Mount as drive letter |
| POST | `/api/volumes/unmount` | `{ driveLetter }` | Unmount drive |
| POST | `/api/volumes/unmount-all` | — | Unmount everything |
| GET | `/api/volumes/mounted` | — | List mounted volumes |
| POST | `/api/volumes/info` | `{ volumePath }` | Volume details |
| POST | `/api/volumes/change-password` | `{ volumePath, oldPassword, newPassword }` | Change password |
| POST | `/api/volumes/backup-header` | `{ volumePath, backupPath }` | Backup header |
| POST | `/api/volumes/restore-header` | `{ volumePath, backupPath }` | Restore header |
| POST | `/api/volumes/delete` | `{ volumePath }` | Delete volume |
| POST | `/api/volumes/hidden/create` | `{ outerVolumePath, outerPassword, hiddenPassword, hiddenSizeMB }` | Create hidden volume |
| POST | `/api/volumes/hidden/mount` | `{ outerVolumePath, hiddenPassword }` | Mount hidden volume |

### File Encryption
| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/encrypt/file` | `{ filePath, password }` | Encrypt file |
| POST | `/api/decrypt/file` | `{ filePath, password }` | Decrypt file |
| POST | `/api/encrypt/folder` | `{ folderPath, password }` | Encrypt folder |
| GET | `/api/encrypt/files` | — | List encrypted files |

### Drives
| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| GET | `/api/drives` | — | Detect all drives |
| GET | `/api/drives/removable` | — | Removable drives only |
| POST | `/api/drives/encrypt` | `{ drive, password, sizeMB }` | Encrypt flash drive |
| POST | `/api/drives/decrypt` | `{ drive, password }` | Verify/decrypt drive |
| POST | `/api/drives/wipe` | `{ drive }` | Secure wipe drive |

### Passwords
| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| GET | `/api/passwords?master=` | — | List passwords |
| POST | `/api/passwords/add` | `{ title, username, password, ... }` | Add entry |
| POST | `/api/passwords/get` | `{ id, masterPassword }` | Get entry |
| POST | `/api/passwords/delete` | `{ id }` | Delete entry |
| GET | `/api/passwords/generate?length=20` | — | Generate password |

### Shredder
| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/api/shred/file` | `{ filePath, passes }` | Shred file |
| POST | `/api/shred/folder` | `{ folderPath, passes }` | Shred folder |
| POST | `/api/shred/freespace` | `{ drive, sizeMB }` | Shred free space |

### System
| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| GET | `/api/stats` | — | Dashboard stats |
| POST | `/api/lock/setup` | `{ password }` | Enable lock screen |
| POST | `/api/lock/verify` | `{ password }` | Verify password |
| POST | `/api/lock/lock` | — | Lock workstation |
| POST | `/api/lock/disable` | — | Disable lock |
| GET | `/api/lock/status` | — | Lock status |
| POST | `/api/restart` | — | Restart PC |

## Volume File Format

```
Offset  Size    Field
0       7       Magic: "SECVLT2"
7       4       Version (2)
11      4       Algorithm (0=AES, 1=ChaCha, 2=AES→ChaCha, 3=ChaCha→AES)
15      32      Salt (scrypt)
47      16      IV (AES) / 12-byte nonce padded to 16 (ChaCha)
63      4       PIM
67      8       Volume size (bytes)
75      32      Keyfile hash (BLAKE2b-256)
107     16      Verification IV (AES-256-GCM)
123     16      Verification ciphertext ("SECVLT_VERIFY_OK" encrypted)
139     16      Verification auth tag
155     ...     Encrypted data
EOF-16  16      Main auth tag
```

## Security Design

- **Key derivation:** scrypt (memory-hard) → BLAKE2b-512 stretching → keyfile XOR merge
- **Verification:** Encrypted known-plaintext block in header for instant password check
- **Hidden volumes:** Outer and hidden volumes share the same file, different passwords decrypt different regions
- **No npm dependencies:** Only Node.js built-in crypto — no supply chain attacks

## Requirements

- Node.js 18+ (tested on v24)
- Windows (uses `subst` for drive mounting)
