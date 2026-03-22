/**
 * TOTP Authenticator - C Implementation
 * Cross-platform TOTP generator with secure storage
 * 
 * Compile: gcc -o totp_auth main.c totp.c storage.c encryption.c -lcrypto -lsqlite3
 * Or with Make: make
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sqlite3.h>

/* Platform-specific */
#ifdef _WIN32
    #include <windows.h>
    #define PLATFORM_WINDOWS 1
#else
    #include <sys/stat.h>
    #include <fcntl.h>
    #define PLATFORM_WINDOWS 0
#endif

/* Constants */
#define MAX_SECRET_LEN 256
#define MAX_NAME_LEN 128
#define MAX_ISSUER_LEN 128
#define MAX_DIGITS 8
#define DEFAULT_DIGITS 6
#define DEFAULT_PERIOD 30
#define MAX_SITES 100

/* Algorithms */
#define ALGO_SHA1   0
#define ALGO_SHA256 1
#define ALGO_SHA512 2

/* Site structure */
typedef struct {
    char id[33];
    char name[MAX_NAME_LEN];
    char secret[MAX_SECRET_LEN];
    char issuer[MAX_ISSUER_LEN];
    int digits;
    int period;
    int algorithm;
    int enabled;
    char created_at[64];
    char updated_at[64];
    char notes[512];
} Site;

/* TOTP generation result */
typedef struct {
    char code[MAX_DIGITS + 1];
    int remaining;
} TOTPResult;

/* ============================================================================
 * BASE32 ENCODING/DECODING
 * ============================================================================ */

static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int base32_encode(const uint8_t *data, int len, char *output) {
    int i, j;
    int output_len = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
    
    for (i = 0; i < len; i++) {
        buffer = (buffer << 8) | data[i];
        bits_left += 8;
        
        while (bits_left >= 5) {
            output[output_len++] = base32_chars[(buffer >> (bits_left - 5)) & 0x1F];
            bits_left -= 5;
        }
    }
    
    if (bits_left > 0) {
        output[output_len++] = base32_chars[(buffer << (5 - bits_left)) & 0x1F];
    }
    
    output[output_len] = '\0';
    return output_len;
}

static int base32_decode(const char *input, uint8_t *output) {
    int len = strlen(input);
    int i, j;
    int output_len = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
    
    /* Remove padding and convert to uppercase */
    for (i = 0; i < len; i++) {
        char c = input[i];
        if (c == '=' || c == ' ') continue;
        if (c >= 'a' && c <= 'z') c = c - 'a' + 'A';
        
        int value = -1;
        for (j = 0; j < 32; j++) {
            if (base32_chars[j] == c) {
                value = j;
                break;
            }
        }
        
        if (value < 0) return -1;
        
        buffer = (buffer << 5) | value;
        bits_left += 5;
        
        if (bits_left >= 8) {
            output[output_len++] = (buffer >> (bits_left - 8)) & 0xFF;
            bits_left -= 8;
        }
    }
    
    return output_len;
}

/* ============================================================================
 * HMAC IMPLEMENTATIONS
 * ============================================================================ */

#include <openssl/hmac.h>
#include <openssl/evp.h>

static void hmac_sha1(const uint8_t *key, int key_len, 
                      const uint8_t *data, int data_len,
                      uint8_t *output) {
    HMAC(EVP_sha1(), key, key_len, data, data_len, output, NULL);
}

static void hmac_sha256(const uint8_t *key, int key_len,
                        const uint8_t *data, int data_len,
                        uint8_t *output) {
    HMAC(EVP_sha256(), key, key_len, data, data_len, output, NULL);
}

static void hmac_sha512(const uint8_t *key, int key_len,
                        const uint8_t *data, int data_len,
                        uint8_t *output) {
    HMAC(EVP_sha512(), key, key_len, data, data_len, output, NULL);
}

/* ============================================================================
 * TOTP GENERATION
 * ============================================================================ */

/**
 * Generate a TOTP code
 * 
 * @param secret Base32 encoded secret
 * @param period Time step in seconds
 * @param digits Number of digits to generate
 * @param algorithm Hash algorithm (ALGO_SHA1, ALGO_SHA256, ALGO_SHA512)
 * @param timestamp Unix timestamp (0 = use current time)
 * @return TOTPResult with code and seconds remaining
 */
TOTPResult totp_generate(const char *secret, int period, int digits, 
                         int algorithm, time_t timestamp) {
    TOTPResult result = {{0}, 0};
    
    if (timestamp == 0) {
        timestamp = time(NULL);
    }
    
    /* Calculate time counter */
    uint64_t counter = timestamp / period;
    result.remaining = period - (timestamp % period);
    
    /* Convert counter to 8-byte big-endian */
    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }
    
    /* Decode base32 secret */
    uint8_t key[MAX_SECRET_LEN];
    int key_len = base32_decode(secret, key);
    
    if (key_len <= 0) {
        /* Invalid secret, return zeros */
        for (int i = 0; i < digits; i++) result.code[i] = '0';
        result.code[digits] = '\0';
        return result;
    }
    
    /* Calculate HMAC */
    uint8_t hmac_result[64];  /* SHA512 produces 64 bytes */
    
    switch (algorithm) {
        case ALGO_SHA256:
            hmac_sha256(key, key_len, counter_bytes, 8, hmac_result);
            break;
        case ALGO_SHA512:
            hmac_sha512(key, key_len, counter_bytes, 8, hmac_result);
            break;
        case ALGO_SHA1:
        default:
            hmac_sha1(key, key_len, counter_bytes, 8, hmac_result);
            break;
    }
    
    /* Dynamic truncation */
    int offset = hmac_result[19] & 0x0F;
    
    uint32_t truncated = 
        ((uint32_t)(hmac_result[offset] & 0x7F) << 24) |
        ((uint32_t)(hmac_result[offset + 1] & 0xFF) << 16) |
        ((uint32_t)(hmac_result[offset + 2] & 0xFF) << 8) |
        ((uint32_t)(hmac_result[offset + 3] & 0xFF));
    
    uint32_t code = truncated % (uint32_t)pow(10, digits);
    
    /* Format result */
    snprintf(result.code, digits + 1, "%0*u", digits, code);
    
    return result;
}

/**
 * Verify a TOTP code with window tolerance
 */
int totp_verify(const char *secret, const char *code, 
                int period, int digits, int algorithm, int window) {
    time_t current = time(NULL);
    
    for (int i = -window; i <= window; i++) {
        time_t test_time = current + (i * period);
        TOTPResult result = totp_generate(secret, period, digits, algorithm, test_time);
        
        if (strcmp(result.code, code) == 0) {
            return 1;  /* Match */
        }
    }
    
    return 0;  /* No match */
}

/* ============================================================================
 * SECURE STORAGE (SQLite)
 * ============================================================================ */

typedef struct {
    Site sites[MAX_SITES];
    int count;
} SiteStore;

static int site_callback(void *context, int argc, char **argv, char **col_names) {
    SiteStore *store = (SiteStore *)context;
    
    if (store->count >= MAX_SITES) return 0;
    
    Site *site = &store->sites[store->count];
    memset(site, 0, sizeof(Site));
    
    for (int i = 0; i < argc; i++) {
        if (argv[i] == NULL) continue;
        
        if (strcmp(col_names[i], "id") == 0) {
            strncpy(site->id, argv[i], 32);
        } else if (strcmp(col_names[i], "name") == 0) {
            strncpy(site->name, argv[i], MAX_NAME_LEN - 1);
        } else if (strcmp(col_names[i], "secret") == 0) {
            strncpy(site->secret, argv[i], MAX_SECRET_LEN - 1);
        } else if (strcmp(col_names[i], "issuer") == 0) {
            strncpy(site->issuer, argv[i], MAX_ISSUER_LEN - 1);
        } else if (strcmp(col_names[i], "digits") == 0) {
            site->digits = atoi(argv[i]);
        } else if (strcmp(col_names[i], "period") == 0) {
            site->period = atoi(argv[i]);
        } else if (strcmp(col_names[i], "algorithm") == 0) {
            if (strcmp(argv[i], "SHA256") == 0) site->algorithm = ALGO_SHA256;
            else if (strcmp(argv[i], "SHA512") == 0) site->algorithm = ALGO_SHA512;
            else site->algorithm = ALGO_SHA1;
        } else if (strcmp(col_names[i], "enabled") == 0) {
            site->enabled = atoi(argv[i]);
        } else if (strcmp(col_names[i], "notes") == 0) {
            strncpy(site->notes, argv[i], 511);
        }
    }
    
    store->count++;
    return 0;
}

typedef struct {
    int success;
    char error[256];
} InitResult;

static int init_callback(void *context, int argc, char **argv, char **col_names) {
    return 0;
}

int storage_init(const char *db_path) {
    sqlite3 *db;
    char *err_msg = NULL;
    
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    
    /* Create sites table */
    const char *sql = 
        "CREATE TABLE IF NOT EXISTS sites ("
        "   id TEXT PRIMARY KEY,"
        "   name TEXT NOT NULL,"
        "   secret TEXT NOT NULL,"
        "   issuer TEXT DEFAULT '',"
        "   digits INTEGER DEFAULT 6,"
        "   period INTEGER DEFAULT 30,"
        "   algorithm TEXT DEFAULT 'SHA1',"
        "   enabled INTEGER DEFAULT 1,"
        "   created_at TEXT,"
        "   updated_at TEXT,"
        "   notes TEXT DEFAULT ''"
        ");"
        "CREATE TABLE IF NOT EXISTS settings ("
        "   key TEXT PRIMARY KEY,"
        "   value TEXT NOT NULL"
        ");";
    
    if (sqlite3_exec(db, sql, init_callback, NULL, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 0;
    }
    
    sqlite3_close(db);
    return 1;
}

int storage_add_site(const char *db_path, Site *site) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *err_msg = NULL;
    time_t now = time(NULL);
    
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        return 0;
    }
    
    const char *sql = "INSERT INTO sites (id, name, secret, issuer, digits, period, algorithm, enabled, created_at, updated_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }
    
    char algo_name[8];
    if (site->algorithm == ALGO_SHA256) strcpy(algo_name, "SHA256");
    else if (site->algorithm == ALGO_SHA512) strcpy(algo_name, "SHA512");
    else strcpy(algo_name, "SHA1");
    
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", localtime(&now));
    
    sqlite3_bind_text(stmt, 1, site->id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, site->secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, site->issuer, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, site->digits);
    sqlite3_bind_int(stmt, 6, site->period);
    sqlite3_bind_text(stmt, 7, algo_name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 8, site->enabled);
    sqlite3_bind_text(stmt, 9, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 11, site->notes, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE ? 1 : 0;
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return result;
}

int storage_get_all_sites(const char *db_path, SiteStore *store) {
    sqlite3 *db;
    char *err_msg = NULL;
    
    store->count = 0;
    
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        return 0;
    }
    
    const char *sql = "SELECT id, name, secret, issuer, digits, period, algorithm, enabled, notes FROM sites ORDER BY name";
    
    if (sqlite3_exec(db, sql, site_callback, store, &err_msg) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return 0;
    }
    
    sqlite3_close(db);
    return store->count;
}

int storage_delete_site(const char *db_path, const char *site_id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        return 0;
    }
    
    if (sqlite3_prepare_v2(db, "DELETE FROM sites WHERE id = ?", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, site_id, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE ? 1 : 0;
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return result;
}

int storage_update_site(const char *db_path, Site *site) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    time_t now = time(NULL);
    
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        return 0;
    }
    
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", localtime(&now));
    
    char algo_name[8];
    if (site->algorithm == ALGO_SHA256) strcpy(algo_name, "SHA256");
    else if (site->algorithm == ALGO_SHA512) strcpy(algo_name, "SHA512");
    else strcpy(algo_name, "SHA1");
    
    const char *sql = "UPDATE sites SET name=?, secret=?, issuer=?, digits=?, period=?, algorithm=?, enabled=?, updated_at=?, notes=? WHERE id=?";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, site->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site->secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, site->issuer, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, site->digits);
    sqlite3_bind_int(stmt, 5, site->period);
    sqlite3_bind_text(stmt, 6, algo_name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, site->enabled);
    sqlite3_bind_text(stmt, 8, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, site->notes, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, site->id, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE ? 1 : 0;
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return result;
}

/* ============================================================================
 * ENCRYPTION (AES-256-GCM via OpenSSL)
 * ============================================================================ */

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#define ENCRYPTION_KEY_LEN 32
#define ENCRYPTION_SALT_LEN 16
#define ENCRYPTION_NONCE_LEN 12

static int encrypt_aes_256_gcm(const char *plaintext, const char *password,
                                unsigned char *output, int *output_len) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;
    unsigned char salt[ENCRYPTION_SALT_LEN];
    unsigned char nonce[ENCRYPTION_NONCE_LEN];
    unsigned char key[ENCRYPTION_KEY_LEN];
    unsigned char iv[ENCRYPTION_NONCE_LEN];
    
    /* Generate random salt and nonce */
    if (!RAND_bytes(salt, ENCRYPTION_SALT_LEN) ||
        !RAND_bytes(nonce, ENCRYPTION_NONCE_LEN)) {
        return 0;
    }
    
    /* Derive key from password using PBKDF2 */
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), 
                           salt, ENCRYPTION_SALT_LEN,
                           100000, EVP_sha256(),
                           ENCRYPTION_KEY_LEN, key)) {
        return 0;
    }
    
    /* Create cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    
    /* Initialize encryption */
    memcpy(iv, nonce, ENCRYPTION_NONCE_LEN);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    /* Encrypt */
    if (EVP_EncryptUpdate(ctx, output, &len, 
                         (const unsigned char *)plaintext, strlen(plaintext)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len = len;
    
    /* Finalize */
    if (EVP_EncryptFinal_ex(ctx, output + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += len;
    
    /* Get tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, output + ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    ciphertext_len += 16;
    
    EVP_CIPHER_CTX_free(ctx);
    
    /* Copy salt + nonce + ciphertext to output */
    memcpy(output, salt, ENCRYPTION_SALT_LEN);
    memcpy(output + ENCRYPTION_SALT_LEN, nonce, ENCRYPTION_NONCE_LEN);
    /* ciphertext is already in place */
    
    *output_len = ciphertext_len + ENCRYPTION_SALT_LEN + ENCRYPTION_NONCE_LEN;
    
    return 1;
}

static int decrypt_aes_256_gcm(const unsigned char *input, int input_len,
                                const char *password, char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;
    unsigned char salt[ENCRYPTION_SALT_LEN];
    unsigned char nonce[ENCRYPTION_NONCE_LEN];
    unsigned char key[ENCRYPTION_KEY_LEN];
    unsigned char iv[ENCRYPTION_NONCE_LEN];
    unsigned char *ciphertext;
    unsigned char tag[16];
    int ciphertext_len;
    
    if (input_len < ENCRYPTION_SALT_LEN + ENCRYPTION_NONCE_LEN + 16) {
        return 0;
    }
    
    /* Extract salt, nonce, ciphertext, tag */
    memcpy(salt, input, ENCRYPTION_SALT_LEN);
    memcpy(nonce, input + ENCRYPTION_SALT_LEN, ENCRYPTION_NONCE_LEN);
    ciphertext_len = input_len - ENCRYPTION_SALT_LEN - ENCRYPTION_NONCE_LEN - 16;
    ciphertext = (unsigned char *)input + ENCRYPTION_SALT_LEN + ENCRYPTION_NONCE_LEN;
    memcpy(tag, input + input_len - 16, 16);
    
    /* Derive key */
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                           salt, ENCRYPTION_SALT_LEN,
                           100000, EVP_sha256(),
                           ENCRYPTION_KEY_LEN, key)) {
        return 0;
    }
    
    /* Create cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    
    /* Initialize decryption */
    memcpy(iv, nonce, ENCRYPTION_NONCE_LEN);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    /* Set expected tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    
    /* Decrypt */
    if (EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len = len;
    
    /* Finalize and verify tag */
    if (EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    plaintext[plaintext_len] = '\0';
    
    return plaintext_len;
}

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

static void generate_id(char *output) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    unsigned char random_bytes[16];
    
    RAND_bytes(random_bytes, 16);
    
    for (int i = 0; i < 16; i++) {
        output[i] = chars[random_bytes[i] % (sizeof(chars) - 1)];
    }
    output[16] = '\0';
}

static void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════╗\n");
    printf("  ║     TOTP Authenticator - C v1.0       ║\n");
    printf("  ╚══════════════════════════════════════╝\n");
    printf("\n");
}

static void print_usage(const char *program) {
    printf("Usage: %s [options]\n", program);
    printf("\nOptions:\n");
    printf("  --init              Initialize database\n");
    printf("  --add NAME SECRET    Add a new site\n");
    printf("  --issuer ISSUER     Issuer name (use with --add)\n");
    printf("  --list              List all sites\n");
    printf("  --codes             Show current TOTP codes\n");
    printf("  --verify NAME CODE  Verify a code\n");
    printf("  --delete ID         Delete a site\n");
    printf("  --edit ID           Edit a site\n");
    printf("  --db PATH           Database path (default: ./auth.db)\n");
    printf("  --help              Show this help\n");
    printf("\n");
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(int argc, char *argv[]) {
    const char *db_path = "./auth.db";
    char *action = NULL;
    char *site_name = NULL;
    char *site_secret = NULL;
    char *site_issuer = NULL;
    char *site_id = NULL;
    char *code = NULL;
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--init") == 0) {
            action = "init";
        } else if (strcmp(argv[i], "--add") == 0 && i + 2 < argc) {
            action = "add";
            site_name = argv[++i];
            site_secret = argv[++i];
        } else if (strcmp(argv[i], "--list") == 0) {
            action = "list";
        } else if (strcmp(argv[i], "--codes") == 0) {
            action = "codes";
        } else if (strcmp(argv[i], "--verify") == 0 && i + 2 < argc) {
            action = "verify";
            site_name = argv[++i];
            code = argv[++i];
        } else if (strcmp(argv[i], "--delete") == 0 && i + 1 < argc) {
            action = "delete";
            site_id = argv[++i];
        } else if (strcmp(argv[i], "--issuer") == 0 && i + 1 < argc) {
            site_issuer = argv[++i];
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    print_banner();
    
    if (action == NULL) {
        print_usage(argv[0]);
        return 0;
    }
    
    /* Initialize database */
    if (strcmp(action, "init") == 0) {
        if (storage_init(db_path)) {
            printf("[OK] Database initialized: %s\n", db_path);
        } else {
            printf("[ERROR] Failed to initialize database\n");
            return 1;
        }
    }
    
    /* Add site */
    else if (strcmp(action, "add") == 0) {
        Site site;
        memset(&site, 0, sizeof(site));
        
        generate_id(site.id);
        strncpy(site.name, site_name, MAX_NAME_LEN - 1);
        strncpy(site.secret, site_secret, MAX_SECRET_LEN - 1);
        strncpy(site.issuer, site_issuer ? site_issuer : "", MAX_ISSUER_LEN - 1);
        site.digits = DEFAULT_DIGITS;
        site.period = DEFAULT_PERIOD;
        site.algorithm = ALGO_SHA1;
        site.enabled = 1;
        
        /* Normalize secret (uppercase, no spaces/dashes) */
        for (char *p = site.secret; *p; p++) {
            if (*p == ' ' || *p == '-') {
                memmove(p, p + 1, strlen(p));
            }
            if (*p >= 'a' && *p <= 'z') {
                *p = *p - 'a' + 'A';
            }
        }
        
        if (storage_add_site(db_path, &site)) {
            printf("[OK] Site added: %s\n", site.name);
            printf("     ID: %s\n", site.id);
        } else {
            printf("[ERROR] Failed to add site\n");
            return 1;
        }
    }
    
    /* List sites */
    else if (strcmp(action, "list") == 0) {
        SiteStore store;
        int count = storage_get_all_sites(db_path, &store);
        
        printf("Sites (%d):\n", count);
        printf("──────────────────────────────────────────\n");
        
        for (int i = 0; i < count; i++) {
            printf("  [%s] %s", store.sites[i].id, store.sites[i].name);
            if (store.sites[i].issuer[0]) {
                printf(" (%s)", store.sites[i].issuer);
            }
            printf(" - %s\n", store.sites[i].enabled ? "Enabled" : "Disabled");
        }
        
        if (count == 0) {
            printf("  No sites configured. Use --add to add one.\n");
        }
    }
    
    /* Show current codes */
    else if (strcmp(action, "codes") == 0) {
        SiteStore store;
        int count = storage_get_all_sites(db_path, &store);
        
        printf("Current TOTP Codes:\n");
        printf("────────────────────────────────────────────────────────\n");
        
        for (int i = 0; i < count; i++) {
            if (!store.sites[i].enabled) continue;
            
            TOTPResult result = totp_generate(
                store.sites[i].secret,
                store.sites[i].period,
                store.sites[i].digits,
                store.sites[i].algorithm,
                0
            );
            
            printf("  %-20s", store.sites[i].name);
            if (store.sites[i].issuer[0]) {
                printf(" (%-10s)", store.sites[i].issuer);
            }
            printf(" %s  [%ds]\n", result.code, result.remaining);
        }
        
        if (count == 0) {
            printf("  No sites configured.\n");
        }
    }
    
    /* Verify code */
    else if (strcmp(action, "verify") == 0) {
        SiteStore store;
        int count = storage_get_all_sites(db_path, &store);
        int found = 0;
        
        for (int i = 0; i < count; i++) {
            if (strcmp(store.sites[i].name, site_name) == 0) {
                found = 1;
                
                int valid = totp_verify(
                    store.sites[i].secret,
                    code,
                    store.sites[i].period,
                    store.sites[i].digits,
                    store.sites[i].algorithm,
                    1  /* window */
                );
                
                if (valid) {
                    printf("[SUCCESS] Code is valid for %s\n", site_name);
                } else {
                    printf("[FAILED] Code is invalid for %s\n", site_name);
                }
                break;
            }
        }
        
        if (!found) {
            printf("[ERROR] Site not found: %s\n", site_name);
        }
    }
    
    /* Delete site */
    else if (strcmp(action, "delete") == 0) {
        printf("Delete site %s? (y/N): ", site_id);
        char confirm;
        scanf(" %c", &confirm);
        
        if (confirm == 'y' || confirm == 'Y') {
            if (storage_delete_site(db_path, site_id)) {
                printf("[OK] Site deleted\n");
            } else {
                printf("[ERROR] Failed to delete site\n");
            }
        } else {
            printf("Cancelled.\n");
        }
    }
    
    return 0;
}
