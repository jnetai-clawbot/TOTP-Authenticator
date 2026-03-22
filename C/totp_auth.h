#ifndef TOTP_AUTH_H
#define TOTP_AUTH_H

#include <stdint.h>
#include <time.h>

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
 * BASE32
 * ============================================================================ */

/**
 * Encode data to base32
 * @param data Input data
 * @param len Length of input data
 * @param output Output buffer (caller must allocate)
 * @return Length of output string
 */
int base32_encode(const uint8_t *data, int len, char *output);

/**
 * Decode base32 string
 * @param input Base32 input string
 * @param output Output buffer (caller must allocate)
 * @return Length of decoded data, or -1 on error
 */
int base32_decode(const char *input, uint8_t *output);

/* ============================================================================
 * HMAC
 * ============================================================================ */

/**
 * Calculate HMAC-SHA1
 */
void hmac_sha1(const uint8_t *key, int key_len,
               const uint8_t *data, int data_len,
               uint8_t *output);

/**
 * Calculate HMAC-SHA256
 */
void hmac_sha256(const uint8_t *key, int key_len,
                 const uint8_t *data, int data_len,
                 uint8_t *output);

/**
 * Calculate HMAC-SHA512
 */
void hmac_sha512(const uint8_t *key, int key_len,
                 const uint8_t *data, int data_len,
                 uint8_t *output);

/* ============================================================================
 * TOTP
 * ============================================================================ */

/**
 * Generate a TOTP code
 * @param secret Base32 encoded secret
 * @param period Time step in seconds
 * @param digits Number of digits to generate
 * @param algorithm Hash algorithm (ALGO_SHA1, ALGO_SHA256, ALGO_SHA512)
 * @param timestamp Unix timestamp (0 = use current time)
 * @return TOTPResult with code and seconds remaining
 */
TOTPResult totp_generate(const char *secret, int period, int digits,
                          int algorithm, time_t timestamp);

/**
 * Verify a TOTP code with window tolerance
 * @param secret Base32 encoded secret
 * @param code TOTP code to verify
 * @param period Time step in seconds
 * @param digits Number of digits
 * @param algorithm Hash algorithm
 * @param window Number of periods to check before/after
 * @return 1 if valid, 0 if invalid
 */
int totp_verify(const char *secret, const char *code,
                 int period, int digits, int algorithm, int window);

/* ============================================================================
 * STORAGE (SQLite)
 * ============================================================================ */

#define STORAGE_INITIALIZED  0x01
#define STORAGE_HAS_PASSWORD 0x02

typedef struct {
    Site sites[MAX_SITES];
    int count;
    int flags;
} SiteStore;

/**
 * Initialize storage
 * @param db_path Path to SQLite database
 * @return 1 on success, 0 on failure
 */
int storage_init(const char *db_path);

/**
 * Close storage connection
 */
void storage_close(void);

/**
 * Check storage flags
 */
int storage_has_password(void);

/**
 * Add a site
 * @return 1 on success, 0 on failure
 */
int storage_add_site(Site *site);

/**
 * Get all sites
 * @param store Pointer to store structure
 * @return Number of sites retrieved
 */
int storage_get_all_sites(SiteStore *store);

/**
 * Get a site by name
 * @param name Site name
 * @param site Output site structure
 * @return 1 on success, 0 if not found
 */
int storage_get_site_by_name(const char *name, Site *site);

/**
 * Update a site
 * @return 1 on success, 0 on failure
 */
int storage_update_site(Site *site);

/**
 * Delete a site by ID
 * @return 1 on success, 0 on failure
 */
int storage_delete_site(const char *site_id);

/* ============================================================================
 * PASSWORD
 * ============================================================================ */

/**
 * Setup master password (first time)
 * @param password Plain text password
 * @return 1 on success, 0 if already set
 */
int password_setup(const char *password);

/**
 * Verify master password
 * @param password Password to verify
 * @return 1 if valid, 0 if invalid
 */
int password_verify(const char *password);

/**
 * Check if password is set
 * @return 1 if set, 0 if not
 */
int password_is_set(void);

/* ============================================================================
 * ENCRYPTION
 * ============================================================================ */

/**
 * Encrypt data using AES-256-GCM
 * @param plaintext Data to encrypt
 * @param password Encryption password
 * @param output Output buffer (base64 encoded)
 * @param output_len Pointer to output length
 * @return 1 on success, 0 on failure
 */
int encrypt_aes_256_gcm(const char *plaintext, const char *password,
                         char *output, int *output_len);

/**
 * Decrypt data using AES-256-GCM
 * @param encrypted Base64 encoded encrypted data
 * @param password Decryption password
 * @param plaintext Output buffer
 * @param plaintext_len Pointer to plaintext length
 * @return 1 on success, 0 on failure
 */
int decrypt_aes_256_gcm(const char *encrypted, const char *password,
                         char *plaintext, int *plaintext_len);

/* ============================================================================
 * UTILITIES
 * ============================================================================ */

/**
 * Generate random ID
 * @param output Output buffer (at least 17 bytes)
 */
void generate_id(char *output);

/**
 * Get current timestamp as ISO string
 * @param output Output buffer (at least 64 bytes)
 */
void get_timestamp(char *output, size_t size);

/**
 * Print banner
 */
void print_banner(void);

/**
 * Print usage
 */
void print_usage(const char *program);

/* Import/export functions */
int export_sites_json(const char *filename);
int import_sites_json(const char *filename);

#endif /* TOTP_AUTH_H */
