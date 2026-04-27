# TOTP-Authenticator - Multi-Language Implementation

A secure, open-source authenticator app (like Google Authenticator) with implementations in Python, PHP, and C. Features Google OAuth login, encrypted secret storage, and works as a drop-in replacement for other authenticator apps.

## Features

- ✅ **TOTP Generation** - RFC 6238 compliant time-based one-time passwords
- ✅ **Secure Storage** - AES-256-GCM encryption for all stored secrets
- ✅ **Google OAuth Ready** - Framework for OAuth-based login
- ✅ **Password Hashing** - Stores password hash (SHA-256) instead of actual password
- ✅ **Multiple Algorithms** - Supports SHA1, SHA256, SHA512
- ✅ **Multiple Languages** - Python, PHP, C implementations
- ✅ **Import/Export** - JSON format for backup and transfer
- ✅ **QR Code URIs** - Google Authenticator compatible `otpauth://` URIs

## Project Structure

```
job16/
├── README.md              # This file
├── python/                # Python implementation
│   ├── totp_auth.py       # Main authenticator app
│   └── encryption.py      # Encryption utilities
├── php/                   # PHP implementation
│   ├── totp_auth.php      # Main authenticator library
│   └── login.php          # Example login system
├── C/                     # C implementation
│   ├── totp_auth.c        # Main authenticator (single file)
│   └── Makefile           # Build system
└── android/               # Android APK (via GitHub Actions)
```

## Security Design

### Password Security
- **Login password**: Stored as SHA-256 hash only
- **TOTP secrets**: Encrypted with AES-256-GCM using PBKDF2-derived key
- **Key derivation**: 100,000 iterations for password → key derivation

### Secret Storage
1. Master password is hashed (SHA-256) for login verification
2. TOTP secrets are encrypted with AES-256-GCM
3. Encryption key derived from master password + random salt
4. Salt stored alongside encrypted data (not secret)

## Quick Start

### Python

```bash
cd python
pip install pyotp cryptography

# Initialize and run
python totp_auth.py --init
python totp_auth.py --add "GitHub" "JBSWY3DPEHPK3PXP" "GitHub"
python totp_auth.py --codes
```

### PHP

```bash
cd php
php -S localhost:8000

# Visit http://localhost:8000/login.php
```

### C

```bash
cd C
make
./totp_auth --init
./totp_auth --add "GitHub" "JBSWY3DPEHPK3PXP" --issuer "GitHub"
./totp_auth --codes
```

## Usage

### Python CLI

```bash
# Initialize database
python totp_auth.py --init

# Add a site
python totp_auth.py --add "GitHub" "JBSWY3DPEHPK3PXP" "GitHub"

# List sites
python totp_auth.py --list

# Show current codes
python totp_auth.py --codes

# Verify a code
python totp_auth.py --verify "GitHub" "123456"

# Delete a site
python totp_auth.py --delete <site_id>

# Export/Import
python totp_auth.py --export backup.json
python totp_auth.py --import backup.json
```

### PHP CLI

```bash
# Initialize
php totp_auth.php --init

# Add site
php totp_auth.php --add "GitHub" "JBSWY3DPEHPK3PXP" "GitHub"

# List sites
php totp_auth.php --list

# Show codes
php totp_auth.php --codes

# Verify code
php totp_auth.php --verify "GitHub" "123456"
```

### C CLI

```bash
# Initialize
./totp_auth --init

# Add site
./totp_auth --add "GitHub" "JBSWY3DPEHPK3PXP" --issuer "GitHub"

# List sites
./totp_auth --list

# Show codes
./totp_auth --codes

# Verify code
./totp_auth --verify "GitHub" "123456"

# Delete site (with confirmation)
./totp_auth --delete <site_id>
```

## PHP Web Login Example

The `php/login.php` file provides a complete example of TOTP-based authentication:

1. **Registration**: User registers with username, password, and TOTP secret
2. **Login Step 1**: User enters username + password
3. **Login Step 2**: User enters TOTP code from authenticator app
4. **Success**: Authenticated session with 5-minute timeout

Run it:
```bash
cd php
php -S localhost:8000 login.php
# Open http://localhost:8000 in browser
```

## TOTP Secret Format

Secrets are Base32 encoded strings like:
```
JBSWY3DPEHPK3PXP
HS3DOMN2EBV233CC
```

When adding sites, the app automatically:
- Converts to uppercase
- Removes spaces and dashes
- Validates Base32 format

## QR Code URI Format

The app generates Google Authenticator compatible URIs:
```
otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30
```

## Database Schema

### Sites Table
```sql
CREATE TABLE sites (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    secret_encrypted TEXT NOT NULL,  -- AES-256-GCM encrypted
    issuer TEXT DEFAULT '',
    digits INTEGER DEFAULT 6,
    period INTEGER DEFAULT 30,
    algorithm TEXT DEFAULT 'SHA1',
    created_at TEXT,
    updated_at TEXT,
    enabled INTEGER DEFAULT 1,
    notes TEXT DEFAULT ''
);
```

### Settings Table
```sql
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

## Building the Android App

See `android/README.md` for GitHub Actions workflow to build APK.

## API Reference

### Python

```python
from totp_auth import AuthenticatorApp, TOTPGenerator, SecureStorage

# Create app
app = AuthenticatorApp()

# Setup password
app.setup_initial_password("mypassword")

# Add site
app.add_site_interactive("GitHub", "JBSWY3DPEHPK3PXP", "GitHub")

# Get codes
codes = app.get_current_codes("mypassword")
# Returns: {'GitHub': ('123456', 25, 'GitHub')}

# Verify
app.verify_code("GitHub", "123456", "mypassword")  # True/False
```

### PHP

```php
require_once 'totp_auth.php';

$app = new AuthenticatorApp();

// Setup
$app->setupPassword("mypassword");

// Add site
$app->addSite("GitHub", "JBSWY3DPEHPK3PXP", "GitHub");

// Get codes
$codes = $app->getCurrentCodes();

// Verify
$app->verifyCode("GitHub", "123456");
```

### C

```c
#include "totp_auth.h"

// Initialize
storage_init("./auth.db");

// Add site
Site site = {...};
storage_add_site("./auth.db", &site);

// Generate code
TOTPResult result = totp_generate("JBSWY3DPEHPK3PXP", 30, 6, ALGO_SHA1, 0);
printf("Code: %s, Remaining: %d\n", result.code, result.remaining);

// Verify
int valid = totp_verify("JBSWY3DPEHPK3PXP", "123456", 30, 6, ALGO_SHA1, 1);
```

## Requirements

### Python
- Python 3.7+
- pyotp (optional, for TOTP generation)
- cryptography (optional, for encryption)

### PHP
- PHP 7.4+
- PDO SQLite extension
- OpenSSL extension

### C
- GCC/Clang
- OpenSSL (libssl-dev)
- SQLite3 (libsqlite3-dev)

## License

MIT License - Free for personal and commercial use.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request
