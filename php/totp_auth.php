<?php
/**
 * TOTP Authenticator - PHP Implementation
 * Secure two-factor authentication library
 * 
 * This class provides TOTP (Time-based One-Time Password) generation
 * and verification compatible with Google Authenticator and other authenticator apps.
 * 
 * @version 1.0.0
 * @license MIT
 */

class TOTPException extends Exception {}

class TOTP {
    /** @var int Default time period in seconds */
    private $period = 30;
    
    /** @var int Default number of digits */
    private $digits = 6;
    
    /** @var string Default algorithm */
    private $algorithm = 'sha1';
    
    /** @var array Supported algorithms */
    private static $supportedAlgorithms = ['sha1', 'sha256', 'sha512'];
    
    /**
     * Constructor
     * 
     * @param int $period Time step in seconds (default: 30)
     * @param int $digits Number of digits (default: 6, max: 8)
     * @param string $algorithm Hash algorithm (sha1, sha256, sha512)
     */
    public function __construct(int $period = 30, int $digits = 6, string $algorithm = 'sha1') {
        $this->period = $period;
        $this->digits = min(max($digits, 6), 8);
        $this->algorithm = strtolower($algorithm);
        
        if (!in_array($this->algorithm, self::$supportedAlgorithms)) {
            throw new TOTPException("Unsupported algorithm: $algorithm");
        }
    }
    
    /**
     * Generate a TOTP code
     * 
     * @param string $secret Base32 encoded secret
     * @param int|null $timestamp Unix timestamp (null = current time)
     * @return string TOTP code
     */
    public function generate(string $secret, ?int $timestamp = null): string {
        $timestamp = $timestamp ?? time();
        
        // Normalize secret (remove spaces, dashes, convert to uppercase)
        $secret = $this->normalizeSecret($secret);
        
        // Decode base32 secret
        $key = $this->base32Decode($secret);
        
        if ($key === false) {
            throw new TOTPException("Invalid base32 secret");
        }
        
        // Calculate counter value
        $counter = intdiv($timestamp, $this->period);
        
        // Pack counter into 8 bytes (big-endian)
        $counterBytes = pack('J', $counter);
        
        // Generate HMAC hash
        $hash = hash_hmac($this->algorithm, $counterBytes, $key, true);
        
        // Dynamic truncation
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        
        $unpacked = unpack('N', substr($hash, $offset, 4));
        $truncated = $unpacked[1] & 0x7FFFFFFF;
        
        // Generate code
        $code = $truncated % pow(10, $this->digits);
        
        return str_pad((string)$code, $this->digits, '0', STR_PAD_LEFT);
    }
    
    /**
     * Verify a TOTP code
     * 
     * @param string $secret Base32 encoded secret
     * @param string $code TOTP code to verify
     * @param int $window Number of periods to check before/after (for clock skew)
     * @return bool True if code is valid
     */
    public function verify(string $secret, string $code, int $window = 1): bool {
        $timestamp = time();
        
        for ($i = -$window; $i <= $window; $i++) {
            $testTime = $timestamp + ($i * $this->period);
            $testCode = $this->generate($secret, $testTime);
            
            if (hash_equals($testCode, $code)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Get time remaining in current period
     * 
     * @return int Seconds remaining
     */
    public function getTimeRemaining(): int {
        return $this->period - (time() % $this->period);
    }
    
    /**
     * Generate a URI for QR code (Google Authenticator compatible)
     * 
     * @param string $secret Base32 encoded secret
     * @param string $account Account name (usually email)
     * @param string $issuer Service name
     * @return string otpauth:// URI
     */
    public function getUri(string $secret, string $account, string $issuer): string {
        $secret = $this->normalizeSecret($secret);
        $issuer = rawurlencode($issuer);
        $account = rawurlencode($account);
        
        $algo = strtoupper($this->algorithm);
        $digits = $this->digits;
        $period = $this->period;
        
        return "otpauth://totp/{$issuer}:{$account}?secret={$secret}&issuer={$issuer}&algorithm={$algo}&digits={$digits}&period={$period}";
    }
    
    /**
     * Generate a random secret
     * 
     * @param int $length Secret length in bytes (default: 20)
     * @return string Base32 encoded secret
     */
    public static function generateSecret(int $length = 20): string {
        $bytes = random_bytes($length);
        return self::base32Encode($bytes);
    }
    
    /**
     * Normalize secret (remove spaces, dashes, convert to uppercase)
     * 
     * @param string $secret Secret to normalize
     * @return string Normalized secret
     */
    private function normalizeSecret(string $secret): string {
        return strtoupper(preg_replace(['/\s+/', '/-+/'], '', $secret));
    }
    
    /**
     * Base32 encode
     * 
     * @param string $data Binary data
     * @return string Base32 encoded string
     */
    public static function base32Encode(string $data): string {
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $binary = '';
        
        foreach (str_split($data) as $char) {
            $binary .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }
        
        $result = '';
        $chunks = str_split($binary, 5);
        
        foreach ($chunks as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $result .= $base32Chars[bindec($chunk)];
        }
        
        // Add padding
        $remainder = strlen($result) % 8;
        if ($remainder > 0) {
            $result .= str_repeat('=', 8 - $remainder);
        }
        
        return $result;
    }
    
    /**
     * Base32 decode
     * 
     * @param string $encoded Base32 encoded string
     * @return string|false Decoded binary data or false on error
     */
    public static function base32Decode(string $encoded) {
        $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $encoded = strtoupper(preg_replace(['/\s+/', '/-+/', '/=+$/'], '', $encoded));
        
        $binary = '';
        foreach (str_split($encoded) as $char) {
            $pos = strpos($base32Chars, $char);
            if ($pos === false) {
                return false;
            }
            $binary .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
        
        $result = '';
        $chunks = str_split($binary, 8);
        
        foreach ($chunks as $chunk) {
            if (strlen($chunk) === 8) {
                $result .= chr(bindec($chunk));
            }
        }
        
        return $result;
    }
}


/**
 * Secure Storage for TOTP Secrets
 * Provides encrypted storage using AES-256-GCM
 */
class TOTPStorage {
    private $dbPath;
    private $masterPasswordHash;
    
    /**
     * Constructor
     * 
     * @param string $dbPath Path to SQLite database
     */
    public function __construct(string $dbPath = './totp_auth.db') {
        $this->dbPath = $dbPath;
        $this->initDatabase();
    }
    
    /**
     * Initialize database schema
     */
    private function initDatabase(): void {
        $db = new PDO("sqlite:{$this->dbPath}");
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $db->exec("
            CREATE TABLE IF NOT EXISTS sites (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                secret_encrypted TEXT NOT NULL,
                issuer TEXT DEFAULT '',
                digits INTEGER DEFAULT 6,
                period INTEGER DEFAULT 30,
                algorithm TEXT DEFAULT 'SHA1',
                created_at TEXT,
                updated_at TEXT,
                enabled INTEGER DEFAULT 1,
                notes TEXT DEFAULT ''
            )
        ");
        
        $db->exec("
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ");
    }
    
    /**
     * Set master password hash
     * 
     * @param string $hash Password hash
     */
    public function setMasterPasswordHash(string $hash): void {
        $this->masterPasswordHash = $hash;
    }
    
    /**
     * Get master password hash
     * 
     * @return string|null
     */
    public function getMasterPasswordHash(): ?string {
        if (!isset($this->masterPasswordHash)) {
            $db = new PDO("sqlite:{$this->dbPath}");
            $stmt = $db->prepare("SELECT value FROM settings WHERE key = 'master_password_hash'");
            $stmt->execute();
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $this->masterPasswordHash = $result ? $result['value'] : null;
        }
        return $this->masterPasswordHash;
    }
    
    /**
     * Setup initial password
     * 
     * @param string $password Plain text password
     * @return string Password hash
     */
    public function setupPassword(string $password): string {
        $hash = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536,
            'time_cost' => 4,
            'threads' => 3
        ]);
        $this->masterPasswordHash = $hash;
        
        $db = new PDO("sqlite:{$this->dbPath}");
        $stmt = $db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('master_password_hash', ?)");
        $stmt->execute([$hash]);
        
        return $hash;
    }
    
    /**
     * Verify master password
     * 
     * @param string $password Plain text password
     * @return bool True if password matches
     */
    public function verifyPassword(string $password): bool {
        $hash = $this->getMasterPasswordHash();
        if (!$hash) return false;
        return password_verify($password, $hash);
    }
    
    /**
     * Encrypt data
     * 
     * @param string $data Data to encrypt
     * @param string $password Password
     * @return string Encrypted data (base64)
     */
    public function encrypt(string $data, string $password): string {
        $salt = random_bytes(16);
        $nonce = random_bytes(12);
        
        $key = $this->deriveKey($password, $salt);
        
        $encrypted = openssl_encrypt(
            $data,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag
        );
        
        // Combine: salt + nonce + tag + ciphertext
        return base64_encode($salt . $nonce . $tag . $encrypted);
    }
    
    /**
     * Decrypt data
     * 
     * @param string $encryptedData Encrypted data (base64)
     * @param string $password Password
     * @return string|false Decrypted data or false on failure
     */
    public function decrypt(string $encryptedData, string $password) {
        $data = base64_decode($encryptedData);
        
        $salt = substr($data, 0, 16);
        $nonce = substr($data, 16, 12);
        $tag = substr($data, 28, 16);
        $ciphertext = substr($data, 44);
        
        $key = $this->deriveKey($password, $salt);
        
        return openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag
        );
    }
    
    /**
     * Derive key from password using PBKDF2
     * 
     * @param string $password Password
     * @param string $salt Salt
     * @return string 32-byte key
     */
    private function deriveKey(string $password, string $salt): string {
        return hash_pbkdf2(
            'sha256',
            $password,
            $salt,
            100000,
            32,
            true
        );
    }
    
    /**
     * Add a new site
     * 
     * @param array $site Site data
     * @param string $masterPassword Master password
     * @return bool Success
     */
    public function addSite(array $site, string $masterPassword): bool {
        try {
            $db = new PDO("sqlite:{$this->dbPath}");
            
            $secretEncrypted = $this->encrypt($site['secret'], $masterPassword);
            
            $now = date('c');
            $id = bin2hex(random_bytes(16));
            
            $stmt = $db->prepare("
                INSERT INTO sites (id, name, secret_encrypted, issuer, digits, period, algorithm, created_at, updated_at, enabled, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            return $stmt->execute([
                $id,
                $site['name'],
                $secretEncrypted,
                $site['issuer'] ?? '',
                $site['digits'] ?? 6,
                $site['period'] ?? 30,
                $site['algorithm'] ?? 'SHA1',
                $now,
                $now,
                $site['enabled'] ?? 1,
                $site['notes'] ?? ''
            ]);
        } catch (PDOException $e) {
            error_log("TOTP Storage Error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Get all sites
     * 
     * @param string $masterPassword Master password
     * @return array Sites with decrypted secrets
     */
    public function getAllSites(string $masterPassword): array {
        try {
            $db = new PDO("sqlite:{$this->dbPath}");
            $stmt = $db->prepare("SELECT * FROM sites ORDER BY name");
            $stmt->execute();
            
            $sites = [];
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $row['secret'] = $this->decrypt($row['secret_encrypted'], $masterPassword);
                unset($row['secret_encrypted']);
                $sites[] = $row;
            }
            
            return $sites;
        } catch (PDOException $e) {
            error_log("TOTP Storage Error: " . $e->getMessage());
            return [];
        }
    }
    
    /**
     * Get a single site
     * 
     * @param string $id Site ID
     * @param string $masterPassword Master password
     * @return array|null Site data or null
     */
    public function getSite(string $id, string $masterPassword): ?array {
        try {
            $db = new PDO("sqlite:{$this->dbPath}");
            $stmt = $db->prepare("SELECT * FROM sites WHERE id = ?");
            $stmt->execute([$id]);
            
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) return null;
            
            $row['secret'] = $this->decrypt($row['secret_encrypted'], $masterPassword);
            unset($row['secret_encrypted']);
            
            return $row;
        } catch (PDOException $e) {
            error_log("TOTP Storage Error: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Update a site
     * 
     * @param array $site Site data
     * @param string $masterPassword Master password
     * @return bool Success
     */
    public function updateSite(array $site, string $masterPassword): bool {
        try {
            $db = new PDO("sqlite:{$this->dbPath}");
            
            $secretEncrypted = $this->encrypt($site['secret'], $masterPassword);
            $now = date('c');
            
            $stmt = $db->prepare("
                UPDATE sites SET 
                    name = ?, secret_encrypted = ?, issuer = ?, 
                    digits = ?, period = ?, algorithm = ?,
                    updated_at = ?, enabled = ?, notes = ?
                WHERE id = ?
            ");
            
            return $stmt->execute([
                $site['name'],
                $secretEncrypted,
                $site['issuer'] ?? '',
                $site['digits'] ?? 6,
                $site['period'] ?? 30,
                $site['algorithm'] ?? 'SHA1',
                $now,
                $site['enabled'] ?? 1,
                $site['notes'] ?? '',
                $site['id']
            ]);
        } catch (PDOException $e) {
            error_log("TOTP Storage Error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Delete a site
     * 
     * @param string $id Site ID
     * @return bool Success
     */
    public function deleteSite(string $id): bool {
        try {
            $db = new PDO("sqlite:{$this->dbPath}");
            $stmt = $db->prepare("DELETE FROM sites WHERE id = ?");
            return $stmt->execute([$id]);
        } catch (PDOException $e) {
            error_log("TOTP Storage Error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Export sites as JSON
     * 
     * @param string $masterPassword Master password
     * @return string JSON string
     */
    public function exportJson(string $masterPassword): string {
        return json_encode($this->getAllSites($masterPassword), JSON_PRETTY_PRINT);
    }
    
    /**
     * Import sites from JSON
     * 
     * @param string $json JSON string
     * @param string $masterPassword Master password
     * @return int Number of sites imported
     */
    public function importJson(string $json, string $masterPassword): int {
        try {
            $data = json_decode($json, true);
            if (!$data) return 0;
            
            $count = 0;
            foreach ($data as $site) {
                if ($this->addSite($site, $masterPassword)) {
                    $count++;
                }
            }
            return $count;
        } catch (Exception $e) {
            error_log("Import Error: " . $e->getMessage());
            return 0;
        }
    }
}


/**
 * Authenticator App - Main Application Class
 */
class AuthenticatorApp {
    private $storage;
    private $totp;
    private $masterPassword;
    
    /**
     * Constructor
     * 
     * @param string $dbPath Database path
     */
    public function __construct(string $dbPath = './totp_auth.db') {
        $this->storage = new TOTPStorage($dbPath);
        $this->totp = new TOTP();
    }
    
    /**
     * Set master password
     * 
     * @param string $password Master password
     */
    public function setMasterPassword(string $password): void {
        $this->masterPassword = $password;
        $this->storage->setMasterPasswordHash($this->storage->getMasterPasswordHash());
    }
    
    /**
     * Setup initial password
     * 
     * @param string $password New password
     */
    public function setupPassword(string $password): void {
        $this->storage->setupPassword($password);
        $this->masterPassword = $password;
    }
    
    /**
     * Verify master password
     * 
     * @param string $password Password to verify
     * @return bool True if correct
     */
    public function verifyPassword(string $password): bool {
        return $this->storage->verifyPassword($password);
    }
    
    /**
     * Check if password is set
     * 
     * @return bool True if password exists
     */
    public function hasPassword(): bool {
        return $this->storage->getMasterPasswordHash() !== null;
    }
    
    /**
     * Add a new site
     * 
     * @param string $name Site name
     * @param string $secret TOTP secret
     * @param string $issuer Issuer name
     * @param string $notes Optional notes
     * @return bool Success
     */
    public function addSite(string $name, string $secret, string $issuer = '', string $notes = ''): bool {
        if (!$this->masterPassword) {
            throw new TOTPException("Master password not set");
        }
        
        // Normalize secret
        $secret = strtoupper(preg_replace(['/\s+/', '/-+/'], '', $secret));
        
        return $this->storage->addSite([
            'name' => $name,
            'secret' => $secret,
            'issuer' => $issuer,
            'notes' => $notes
        ], $this->masterPassword);
    }
    
    /**
     * Get all sites
     * 
     * @return array Sites
     */
    public function getSites(): array {
        if (!$this->masterPassword) {
            return [];
        }
        return $this->storage->getAllSites($this->masterPassword);
    }
    
    /**
     * Get current TOTP codes for all sites
     * 
     * @return array Codes with site info
     */
    public function getCurrentCodes(): array {
        if (!$this->masterPassword) {
            return [];
        }
        
        $sites = $this->storage->getAllSites($this->masterPassword);
        $codes = [];
        
        foreach ($sites as $site) {
            if (!$site['enabled']) continue;
            
            $totp = new TOTP(
                (int)$site['period'],
                (int)$site['digits'],
                strtolower($site['algorithm'])
            );
            
            $codes[] = [
                'name' => $site['name'],
                'issuer' => $site['issuer'],
                'code' => $totp->generate($site['secret']),
                'remaining' => $totp->getTimeRemaining()
            ];
        }
        
        return $codes;
    }
    
    /**
     * Verify a code for a site
     * 
     * @param string $siteName Site name
     * @param string $code TOTP code
     * @return bool True if valid
     */
    public function verifyCode(string $siteName, string $code): bool {
        if (!$this->masterPassword) {
            return false;
        }
        
        $sites = $this->storage->getAllSites($this->masterPassword);
        
        foreach ($sites as $site) {
            if ($site['name'] === $siteName && $site['enabled']) {
                $totp = new TOTP(
                    (int)$site['period'],
                    (int)$site['digits'],
                    strtolower($site['algorithm'])
                );
                return $totp->verify($site['secret'], $code);
            }
        }
        
        return false;
    }
    
    /**
     * Delete a site
     * 
     * @param string $id Site ID
     * @return bool Success
     */
    public function deleteSite(string $id): bool {
        return $this->storage->deleteSite($id);
    }
    
    /**
     * Update a site
     * 
     * @param array $site Site data
     * @return bool Success
     */
    public function updateSite(array $site): bool {
        if (!$this->masterPassword) {
            throw new TOTPException("Master password not set");
        }
        
        // Normalize secret
        $site['secret'] = strtoupper(preg_replace(['/\s+/', '/-+/'], '', $site['secret']));
        
        return $this->storage->updateSite($site, $this->masterPassword);
    }
}


// CLI interface when run directly
if (php_sapi_name() === 'cli' && basename(__FILE__) === basename($argv[0])) {
    $app = new AuthenticatorApp();
    $action = $argv[1] ?? '--help';
    
    echo "\n  TOTP Authenticator - PHP v1.0\n";
    echo "  ─────────────────────────────────\n\n";
    
    switch ($action) {
        case '--init':
            echo "Setting up initial password...\n";
            $password = readline("Enter new master password: ");
            $app->setupPassword($password);
            echo "[OK] Password set up successfully.\n";
            break;
            
        case '--add':
            if (count($argv) < 4) {
                echo "Usage: php totp_auth.php --add <name> <secret> [issuer]\n";
                exit(1);
            }
            $name = $argv[2];
            $secret = $argv[3];
            $issuer = $argv[4] ?? '';
            
            $app->setMasterPassword(readline("Master password: "));
            
            if ($app->addSite($name, $secret, $issuer)) {
                echo "[OK] Site added: $name\n";
            } else {
                echo "[ERROR] Failed to add site\n";
            }
            break;
            
        case '--list':
            $app->setMasterPassword(readline("Master password: "));
            $sites = $app->getSites();
            
            echo "\nSites (" . count($sites) . "):\n";
            foreach ($sites as $site) {
                echo "  [{$site['id']}] {$site['name']}";
                if ($site['issuer']) echo " ({$site['issuer']})";
                echo " - " . ($site['enabled'] ? 'Enabled' : 'Disabled') . "\n";
            }
            break;
            
        case '--codes':
            $app->setMasterPassword(readline("Master password: "));
            $codes = $app->getCurrentCodes();
            
            echo "\nCurrent Codes:\n";
            foreach ($codes as $entry) {
                printf("  %-20s %s [%ds]\n", $entry['name'], $entry['code'], $entry['remaining']);
            }
            break;
            
        case '--verify':
            if (count($argv) < 4) {
                echo "Usage: php totp_auth.php --verify <name> <code>\n";
                exit(1);
            }
            $name = $argv[2];
            $code = $argv[3];
            
            $app->setMasterPassword(readline("Master password: "));
            
            if ($app->verifyCode($name, $code)) {
                echo "[SUCCESS] Code is valid for $name\n";
            } else {
                echo "[FAILED] Code is invalid for $name\n";
            }
            break;
            
        default:
            echo "Usage: php totp_auth.php [options]\n";
            echo "\nOptions:\n";
            echo "  --init              Initialize and set master password\n";
            echo "  --add NAME SECRET   Add a new site\n";
            echo "  --list              List all sites\n";
            echo "  --codes             Show current TOTP codes\n";
            echo "  --verify NAME CODE  Verify a code\n";
            echo "  --help              Show this help\n";
            echo "\n";
    }
}
