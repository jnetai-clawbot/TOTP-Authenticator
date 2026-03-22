/**
 * TOTP Authenticator - C Implementation
 * Single-file version for simplicity
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <sqlite3.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <math.h>

/* Constants */
#define MAX_SECRET_LEN 256
#define MAX_NAME_LEN 128
#define MAX_ISSUER_LEN 128
#define MAX_DIGITS 8
#define DEFAULT_DIGITS 6
#define DEFAULT_PERIOD 30
#define MAX_SITES 100
#define DEFAULT_DB_PATH "./totp_auth.db"

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
 * UTILITIES
 * ============================================================================ */

static void generate_id(char *output) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) {
        unsigned char random_bytes[16];
        (void)fread(random_bytes, 1, 16, fp);
        fclose(fp);
        for (int i = 0; i < 16; i++) {
            output[i] = chars[random_bytes[i] % (sizeof(chars) - 1)];
        }
        output[16] = '\0';
    } else {
        snprintf(output, 17, "%ld%ld", (long)time(NULL), (long)rand());
    }
}

static void get_timestamp(char *output, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(output, size, "%Y-%m-%dT%H:%M:%S", tm_info);
}

/* ============================================================================
 * BASE32
 * ============================================================================ */

static const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static int base32_decode(const char *input, uint8_t *output) {
    int len = strlen(input);
    int i;
    int output_len = 0;
    uint32_t buffer = 0;
    int bits_left = 0;
    
    for (i = 0; i < len; i++) {
        char c = input[i];
        if (c == '=') continue;
        
        int val = -1;
        for (int j = 0; j < 32; j++) {
            if (base32_chars[j] == toupper(c)) {
                val = j;
                break;
            }
        }
        if (val < 0) continue;
        
        buffer = (buffer << 5) | val;
        bits_left += 5;
        
        if (bits_left >= 8) {
            output[output_len++] = (buffer >> (bits_left - 8)) & 0xFF;
            bits_left -= 8;
        }
    }
    return output_len;
}

/* ============================================================================
 * HMAC
 * ============================================================================ */

static void calc_hmac(const uint8_t *key, int key_len,
                      const uint8_t *data, int data_len,
                      uint8_t *output, int algorithm) {
    switch (algorithm) {
        case ALGO_SHA256:
            HMAC(EVP_sha256(), key, key_len, data, data_len, output, NULL);
            break;
        case ALGO_SHA512:
            HMAC(EVP_sha512(), key, key_len, data, data_len, output, NULL);
            break;
        case ALGO_SHA1:
        default:
            HMAC(EVP_sha1(), key, key_len, data, data_len, output, NULL);
            break;
    }
}

/* ============================================================================
 * TOTP
 * ============================================================================ */

static uint32_t dynamic_truncate(const uint8_t *hash, int hash_len) {
    int offset = hash[hash_len - 1] & 0x0F;
    uint32_t truncated = 0;
    for (int i = 0; i < 4; i++) {
        truncated = (truncated << 8) | hash[offset + i];
    }
    return truncated & 0x7FFFFFFF;
}

static TOTPResult totp_generate(const char *secret, int period, int digits, int algorithm) {
    TOTPResult result = {{0}, 0};
    if (!secret || strlen(secret) == 0) return result;
    
    time_t timestamp = time(NULL);
    time_t time_step = timestamp / period;
    result.remaining = period - (timestamp % period);
    
    uint8_t key[128];
    int key_len = base32_decode(secret, key);
    if (key_len <= 0) return result;
    
    uint64_t counter = time_step;
    uint8_t counter_bytes[8];
    for (int i = 7; i >= 0; i--) {
        counter_bytes[i] = counter & 0xFF;
        counter >>= 8;
    }
    
    int hash_len = (algorithm == ALGO_SHA256) ? SHA256_DIGEST_LENGTH : 
                   (algorithm == ALGO_SHA512) ? SHA512_DIGEST_LENGTH : 20;
    uint8_t hash[SHA512_DIGEST_LENGTH];
    calc_hmac(key, key_len, counter_bytes, 8, hash, algorithm);
    
    uint32_t truncated = dynamic_truncate(hash, hash_len);
    uint32_t code = truncated % (uint32_t)pow(10, digits);
    snprintf(result.code, sizeof(result.code), "%0*d", digits, code);
    
    return result;
}

/* ============================================================================
 * STORAGE
 * ============================================================================ */

static sqlite3 *db = NULL;

static int storage_init(const char *db_path) {
    if (sqlite3_open(db_path, &db) != SQLITE_OK) return 0;
    
    const char *sql = 
        "CREATE TABLE IF NOT EXISTS sites ("
        "   id TEXT PRIMARY KEY,"
        "   name TEXT UNIQUE NOT NULL,"
        "   secret_encrypted TEXT NOT NULL,"
        "   issuer TEXT DEFAULT '',"
        "   digits INTEGER DEFAULT 6,"
        "   period INTEGER DEFAULT 30,"
        "   algorithm INTEGER DEFAULT 0,"
        "   enabled INTEGER DEFAULT 1,"
        "   created_at TEXT,"
        "   updated_at TEXT,"
        "   notes TEXT DEFAULT ''"
        ");";
    
    char *err_msg = NULL;
    sqlite3_exec(db, sql, NULL, NULL, &err_msg);
    if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }
    
    return 1;
}

static void storage_close(void) {
    if (db) { sqlite3_close(db); db = NULL; }
}

static int storage_add_site(Site *site) {
    if (!db || !site) return 0;
    char timestamp[64]; get_timestamp(timestamp, sizeof(timestamp));
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO sites (id, name, secret_encrypted, issuer, digits, period, algorithm, enabled, created_at, updated_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK) return 0;
    
    sqlite3_bind_text(stmt, 1, site->id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, site->secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, site->issuer, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, site->digits);
    sqlite3_bind_int(stmt, 6, site->period);
    sqlite3_bind_int(stmt, 7, site->algorithm);
    sqlite3_bind_int(stmt, 8, site->enabled);
    sqlite3_bind_text(stmt, 9, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 11, site->notes, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return result;
}

static int storage_get_all_sites(Site **sites_out, int *count_out) {
    if (!db) return 0;
    
    static Site sites[MAX_SITES];
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
        "SELECT name, secret_encrypted, issuer, digits, period, algorithm, enabled FROM sites ORDER BY name",
        -1, &stmt, NULL) != SQLITE_OK) return 0;
    
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && count < MAX_SITES) {
        Site *s = &sites[count];
        strncpy(s->name, (const char *)sqlite3_column_text(stmt, 0), MAX_NAME_LEN - 1);
        strncpy(s->secret, (const char *)sqlite3_column_text(stmt, 1), MAX_SECRET_LEN - 1);
        strncpy(s->issuer, (const char *)sqlite3_column_text(stmt, 2), MAX_ISSUER_LEN - 1);
        s->digits = sqlite3_column_int(stmt, 3);
        s->period = sqlite3_column_int(stmt, 4);
        s->algorithm = sqlite3_column_int(stmt, 5);
        s->enabled = sqlite3_column_int(stmt, 6);
        count++;
    }
    sqlite3_finalize(stmt);
    *sites_out = sites;
    *count_out = count;
    return count;
}

static int storage_delete_site(const char *name) {
    if (!db || !name) return 0;
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "DELETE FROM sites WHERE name = ?", -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return result;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static void print_banner(void) {
    printf("\n");
    printf("========================================\n");
    printf("     TOTP Authenticator - C Version    \n");
    printf("========================================\n\n");
}

static void print_usage(const char *program) {
    printf("Usage: %s [options] <action> [args]\n\n", program);
    printf("Options:\n");
    printf("  --db <path>    Database path (default: ./totp_auth.db)\n\n");
    printf("Actions:\n");
    printf("  list                       List all sites\n");
    printf("  add <name> <secret>        Add a new site\n");
    printf("  delete <name>              Delete a site\n");
    printf("  get <name>                 Get TOTP code for site\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    const char *db_path = DEFAULT_DB_PATH;
    const char *action = NULL;
    const char *name = NULL;
    const char *secret = NULL;
    
    print_banner();
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (!action) {
            action = argv[i];
            if (strcmp(action, "add") == 0 && i + 2 < argc) {
                name = argv[++i];
                secret = argv[++i];
            } else if (strcmp(action, "delete") == 0 && i + 1 < argc) {
                name = argv[++i];
            } else if (strcmp(action, "get") == 0 && i + 1 < argc) {
                name = argv[++i];
            }
        }
    }
    
    if (!action) {
        print_usage(argv[0]);
        return 1;
    }
    
    /* Initialize storage */
    if (!storage_init(db_path)) {
        fprintf(stderr, "[ERROR] Failed to initialize storage\n");
        return 1;
    }
    
    /* Handle actions */
    if (strcmp(action, "list") == 0) {
        Site *sites = NULL;
        int count = 0;
        storage_get_all_sites(&sites, &count);
        
        printf("Stored sites (%d):\n", count);
        printf("----------------------------------------\n");
        for (int i = 0; i < count; i++) {
            Site *s = &sites[i];
            TOTPResult r = totp_generate(s->secret, s->period, s->digits, s->algorithm);
            printf("  %s\n", s->name);
            printf("    Code: %s (expires in %ds)\n", r.code, r.remaining);
            printf("    Issuer: %s | Algo: %s | Digits: %d\n", 
                   s->issuer[0] ? s->issuer : "-",
                   s->algorithm == ALGO_SHA256 ? "SHA256" : 
                   s->algorithm == ALGO_SHA512 ? "SHA512" : "SHA1",
                   s->digits);
            printf("\n");
        }
    }
    else if (strcmp(action, "add") == 0) {
        Site site;
        memset(&site, 0, sizeof(site));
        generate_id(site.id);
        strncpy(site.name, name, MAX_NAME_LEN - 1);
        strncpy(site.secret, secret, MAX_SECRET_LEN - 1);
        site.digits = DEFAULT_DIGITS;
        site.period = DEFAULT_PERIOD;
        site.algorithm = ALGO_SHA1;
        site.enabled = 1;
        
        if (storage_add_site(&site)) {
            printf("[OK] Added site: %s\n", name);
        } else {
            printf("[ERROR] Failed to add site (may already exist)\n");
        }
    }
    else if (strcmp(action, "delete") == 0) {
        printf("Delete %s? (y/N): ", name);
        char confirm;
        if (scanf(" %c", &confirm) == 1 && (confirm == 'y' || confirm == 'Y')) {
            if (storage_delete_site(name)) {
                printf("[OK] Deleted site: %s\n", name);
            } else {
                printf("[ERROR] Failed to delete site\n");
            }
        } else {
            printf("Cancelled.\n");
        }
    }
    else if (strcmp(action, "get") == 0) {
        Site *sites = NULL;
        int count = 0;
        storage_get_all_sites(&sites, &count);
        
        for (int i = 0; i < count; i++) {
            if (strcmp(sites[i].name, name) == 0) {
                Site *s = &sites[i];
                TOTPResult r = totp_generate(s->secret, s->period, s->digits, s->algorithm);
                printf("%s: %s (expires in %ds)\n", s->name, r.code, r.remaining);
                break;
            }
        }
    }
    else {
        fprintf(stderr, "[ERROR] Unknown action: %s\n", action);
        print_usage(argv[0]);
    }
    
    storage_close();
    return 0;
}
