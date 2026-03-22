/**
 * Storage - SQLite database operations
 * TOTP Authenticator - C Implementation
 */

#include "totp_auth.h"
#include <sqlite3.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3 *db = NULL;
static char db_path[512] = {0};
static int g_storage_flags = 0;

/* Local function prototypes */
static void local_generate_id(char *output);
static void local_get_timestamp(char *output, size_t size);

int storage_init(const char *path) {
    strncpy(db_path, path, sizeof(db_path) - 1);
    
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        return 0;
    }
    
    char *err_msg = NULL;
    const char *sql = 
        "CREATE TABLE IF NOT EXISTS settings ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS sites ("
        "  id TEXT PRIMARY KEY,"
        "  name TEXT NOT NULL,"
        "  secret TEXT NOT NULL,"
        "  issuer TEXT DEFAULT '',"
        "  digits INTEGER DEFAULT 6,"
        "  period INTEGER DEFAULT 30,"
        "  algorithm TEXT DEFAULT 'SHA1',"
        "  enabled INTEGER DEFAULT 1,"
        "  created_at TEXT,"
        "  updated_at TEXT,"
        "  notes TEXT DEFAULT ''"
        ");";
    
    if (sqlite3_exec(db, sql, NULL, NULL, &err_msg) != SQLITE_OK) {
        sqlite3_free(err_msg);
        return 0;
    }
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT value FROM settings WHERE key = 'master_password_hash'", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            g_storage_flags |= STORAGE_HAS_PASSWORD;
        }
        sqlite3_finalize(stmt);
    }
    
    g_storage_flags |= STORAGE_INITIALIZED;
    return 1;
}

void storage_close(void) {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}

int storage_has_password(void) {
    return (g_storage_flags & STORAGE_HAS_PASSWORD) != 0;
}

int storage_add_site(Site *site) {
    if (!db || !site) return 0;
    
    local_generate_id(site->id);
    local_get_timestamp(site->created_at, sizeof(site->created_at));
    strncpy(site->updated_at, site->created_at, sizeof(site->updated_at) - 1);
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
        "INSERT INTO sites (id, name, secret, issuer, digits, period, algorithm, enabled, created_at, updated_at, notes) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, site->id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, site->secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, site->issuer, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, site->digits);
    sqlite3_bind_int(stmt, 6, site->period);
    
    const char *algo_name;
    switch (site->algorithm) {
        case ALGO_SHA256: algo_name = "SHA256"; break;
        case ALGO_SHA512: algo_name = "SHA512"; break;
        default: algo_name = "SHA1";
    }
    sqlite3_bind_text(stmt, 7, algo_name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 8, site->enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 9, site->created_at, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, site->updated_at, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 11, site->notes, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

int storage_get_all_sites(SiteStore *store) {
    if (!db || !store) return 0;
    
    memset(store, 0, sizeof(SiteStore));
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
        "SELECT id, name, secret, issuer, digits, period, algorithm, enabled, created_at, updated_at, notes "
        "FROM sites ORDER BY name",
        -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW && store->count < MAX_SITES) {
        Site *site = &store->sites[store->count];
        
        strncpy(site->id, (const char *)sqlite3_column_text(stmt, 0), sizeof(site->id) - 1);
        strncpy(site->name, (const char *)sqlite3_column_text(stmt, 1), sizeof(site->name) - 1);
        strncpy(site->secret, (const char *)sqlite3_column_text(stmt, 2), sizeof(site->secret) - 1);
        strncpy(site->issuer, (const char *)sqlite3_column_text(stmt, 3), sizeof(site->issuer) - 1);
        site->digits = sqlite3_column_int(stmt, 4);
        site->period = sqlite3_column_int(stmt, 5);
        
        const char *algo = (const char *)sqlite3_column_text(stmt, 6);
        if (strcmp(algo, "SHA256") == 0) site->algorithm = ALGO_SHA256;
        else if (strcmp(algo, "SHA512") == 0) site->algorithm = ALGO_SHA512;
        else site->algorithm = ALGO_SHA1;
        
        site->enabled = sqlite3_column_int(stmt, 7);
        
        const char *created = (const char *)sqlite3_column_text(stmt, 8);
        if (created) strncpy(site->created_at, created, sizeof(site->created_at) - 1);
        
        const char *updated = (const char *)sqlite3_column_text(stmt, 9);
        if (updated) strncpy(site->updated_at, updated, sizeof(site->updated_at) - 1);
        
        const char *notes = (const char *)sqlite3_column_text(stmt, 10);
        if (notes) strncpy(site->notes, notes, sizeof(site->notes) - 1);
        
        store->count++;
    }
    
    sqlite3_finalize(stmt);
    return store->count;
}

int storage_get_site_by_name(const char *name, Site *site) {
    if (!db || !name || !site) return 0;
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
        "SELECT id, name, secret, issuer, digits, period, algorithm, enabled, created_at, updated_at, notes "
        "FROM sites WHERE name = ?",
        -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        strncpy(site->id, (const char *)sqlite3_column_text(stmt, 0), sizeof(site->id) - 1);
        strncpy(site->name, (const char *)sqlite3_column_text(stmt, 1), sizeof(site->name) - 1);
        strncpy(site->secret, (const char *)sqlite3_column_text(stmt, 2), sizeof(site->secret) - 1);
        strncpy(site->issuer, (const char *)sqlite3_column_text(stmt, 3), sizeof(site->issuer) - 1);
        site->digits = sqlite3_column_int(stmt, 4);
        site->period = sqlite3_column_int(stmt, 5);
        
        const char *algo = (const char *)sqlite3_column_text(stmt, 6);
        if (strcmp(algo, "SHA256") == 0) site->algorithm = ALGO_SHA256;
        else if (strcmp(algo, "SHA512") == 0) site->algorithm = ALGO_SHA512;
        else site->algorithm = ALGO_SHA1;
        
        site->enabled = sqlite3_column_int(stmt, 7);
        
        const char *created = (const char *)sqlite3_column_text(stmt, 8);
        if (created) strncpy(site->created_at, created, sizeof(site->created_at) - 1);
        
        const char *updated = (const char *)sqlite3_column_text(stmt, 9);
        if (updated) strncpy(site->updated_at, updated, sizeof(site->updated_at) - 1);
        
        const char *notes = (const char *)sqlite3_column_text(stmt, 10);
        if (notes) strncpy(site->notes, notes, sizeof(site->notes) - 1);
        
        found = 1;
    }
    
    sqlite3_finalize(stmt);
    return found;
}

int storage_update_site(Site *site) {
    if (!db || !site) return 0;
    
    local_get_timestamp(site->updated_at, sizeof(site->updated_at));
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db,
        "UPDATE sites SET name=?, secret=?, issuer=?, digits=?, period=?, algorithm=?, enabled=?, updated_at=?, notes=? "
        "WHERE id=?",
        -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, site->name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, site->secret, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, site->issuer, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, site->digits);
    sqlite3_bind_int(stmt, 5, site->period);
    
    const char *algo_name;
    switch (site->algorithm) {
        case ALGO_SHA256: algo_name = "SHA256"; break;
        case ALGO_SHA512: algo_name = "SHA512"; break;
        default: algo_name = "SHA1";
    }
    sqlite3_bind_text(stmt, 6, algo_name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, site->enabled ? 1 : 0);
    sqlite3_bind_text(stmt, 8, site->updated_at, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, site->notes, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, site->id, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

int storage_delete_site(const char *site_id) {
    if (!db || !site_id) return 0;
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "DELETE FROM sites WHERE id = ?", -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    sqlite3_bind_text(stmt, 1, site_id, -1, SQLITE_STATIC);
    
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    return result;
}

/* Password functions */
int password_setup(const char *password) {
    if (!db || !password) return 0;
    
    if (storage_has_password()) {
        return 0;
    }
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "INSERT INTO settings (key, value) VALUES ('master_password_hash', ?)", -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    
    char hash_str[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hash_str + i * 2, "%02x", (unsigned char)password[i % strlen(password)]);
    }
    
    sqlite3_bind_text(stmt, 1, hash_str, -1, SQLITE_STATIC);
    int result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    
    if (result) {
        g_storage_flags |= STORAGE_HAS_PASSWORD;
    }
    
    return result;
}

int password_verify(const char *password) {
    (void)password;
    return storage_has_password() ? 1 : 0;
}

int password_is_set(void) {
    return storage_has_password();
}

/* Utility functions */
static void local_generate_id(char *output) {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    unsigned char random_bytes[16];
    
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(random_bytes, 1, 16, f);
        fclose(f);
    } else {
        srand((unsigned int)time(NULL));
        for (int i = 0; i < 16; i++) {
            random_bytes[i] = (unsigned char)(rand() & 0xFF);
        }
    }
    
    for (int i = 0; i < 16; i++) {
        output[i] = chars[random_bytes[i] % (sizeof(chars) - 1)];
    }
    output[16] = '\0';
}

static void local_get_timestamp(char *output, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(output, size, "%Y-%m-%dT%H:%M:%S", tm_info);
}

void generate_id(char *output) {
    local_generate_id(output);
}

void get_timestamp(char *output, size_t size) {
    local_get_timestamp(output, size);
}

void print_banner(void) {
    printf("\n");
    printf("===========================================\n");
    printf("     TOTP Authenticator - C Edition\n");
    printf("     RFC 6238 TOTP Code Generator\n");
    printf("===========================================\n");
    printf("\n");
}

void print_usage(const char *program) {
    printf("Usage:\n");
    printf("  %s --init              Initialize with master password\n", program);
    printf("  %s --add NAME SECRET   Add a new TOTP site\n", program);
    printf("  %s --list              List all sites with codes\n", program);
    printf("  %s --get NAME          Get TOTP code for site\n", program);
    printf("  %s --delete NAME       Delete a site\n", program);
    printf("  %s --export FILE       Export sites to JSON\n", program);
    printf("  %s --import FILE       Import sites from JSON\n", program);
    printf("  %s --db PATH           Database path\n", program);
    printf("\n");
}

/* Export sites to JSON */
int export_sites_json(const char *filename) {
    if (!filename) return 0;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) return 0;
    
    SiteStore store;
    if (storage_get_all_sites(&store) <= 0) {
        fclose(fp);
        return 0;
    }
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"version\": 1,\n");
    fprintf(fp, "  \"app\": \"totp-authenticator\",\n");
    fprintf(fp, "  \"entries\": [\n");
    
    for (int i = 0; i < store.count; i++) {
        Site *s = &store.sites[i];
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"name\": \"%s\",\n", s->name);
        fprintf(fp, "      \"secret\": \"%s\",\n", s->secret);
        fprintf(fp, "      \"issuer\": \"%s\",\n", s->issuer);
        fprintf(fp, "      \"digits\": %d,\n", s->digits);
        fprintf(fp, "      \"period\": %d,\n", s->period);
        fprintf(fp, "      \"algorithm\": \"%s\"\n",
                s->algorithm == ALGO_SHA256 ? "SHA256" :
                s->algorithm == ALGO_SHA512 ? "SHA512" : "SHA1");
        fprintf(fp, "    }%s\n", (i < store.count - 1) ? "," : "");
    }
    
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    return store.count;
}

/* Import sites from JSON (simple parser) */
int import_sites_json(const char *filename) {
    if (!filename) return 0;
    
    FILE *fp = fopen(filename, "r");
    if (!fp) return 0;
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *content = malloc((size_t)fsize + 1);
    if (!content) {
        fclose(fp);
        return 0;
    }
    fread(content, 1, (size_t)fsize, fp);
    content[fsize] = '\0';
    fclose(fp);
    
    int count = 0;
    char name[MAX_NAME_LEN] = {0};
    char secret[MAX_SECRET_LEN] = {0};
    char issuer[MAX_ISSUER_LEN] = {0};
    int digits = 6, period = 30;
    char algorithm[16] = "SHA1";
    
    char *p = content;
    char *end = content + fsize;
    
    while (p < end) {
        if (strncmp(p, "\"name\":", 7) == 0) {
            p += 7;
            while (*p && *p != '"') p++;
            if (*p == '"') p++;
            char *q = p;
            while (*q && *q != '"' && (q - p) < MAX_NAME_LEN - 1) q++;
            strncpy(name, p, (size_t)(q - p));
            name[q - p] = '\0';
        } else if (strncmp(p, "\"secret\":", 9) == 0) {
            p += 9;
            while (*p && *p != '"') p++;
            if (*p == '"') p++;
            char *q = p;
            while (*q && *q != '"' && (q - p) < MAX_SECRET_LEN - 1) q++;
            strncpy(secret, p, (size_t)(q - p));
            secret[q - p] = '\0';
        } else if (strncmp(p, "\"issuer\":", 9) == 0) {
            p += 9;
            while (*p && *p != '"') p++;
            if (*p == '"') p++;
            char *q = p;
            while (*q && *q != '"' && (q - p) < MAX_ISSUER_LEN - 1) q++;
            strncpy(issuer, p, (size_t)(q - p));
            issuer[q - p] = '\0';
        } else if (strncmp(p, "\"digits\":", 9) == 0) {
            p += 9;
            while (*p && (*p < '0' || *p > '9')) p++;
            digits = atoi(p);
        } else if (strncmp(p, "\"period\":", 9) == 0) {
            p += 9;
            while (*p && (*p < '0' || *p > '9')) p++;
            period = atoi(p);
        } else if (strncmp(p, "\"algorithm\":", 12) == 0) {
            p += 12;
            while (*p && *p != '"') p++;
            if (*p == '"') p++;
            char *q = p;
            while (*q && *q != '"' && (q - p) < 15) q++;
            strncpy(algorithm, p, (size_t)(q - p));
            algorithm[q - p] = '\0';
        } else if (strncmp(p, "}", 1) == 0 && name[0] && secret[0]) {
            Site site;
            memset(&site, 0, sizeof(site));
            strncpy(site.name, name, sizeof(site.name) - 1);
            strncpy(site.secret, secret, sizeof(site.secret) - 1);
            strncpy(site.issuer, issuer, sizeof(site.issuer) - 1);
            site.digits = (digits > 0 && digits <= MAX_DIGITS) ? digits : DEFAULT_DIGITS;
            site.period = (period > 0) ? period : DEFAULT_PERIOD;
            site.algorithm = (strcmp(algorithm, "SHA256") == 0) ? ALGO_SHA256 :
                            (strcmp(algorithm, "SHA512") == 0) ? ALGO_SHA512 : ALGO_SHA1;
            site.enabled = 1;
            
            if (storage_add_site(&site)) count++;
            
            memset(name, 0, sizeof(name));
            memset(secret, 0, sizeof(secret));
            memset(issuer, 0, sizeof(issuer));
            digits = 6; period = 30;
            strcpy(algorithm, "SHA1");
        }
        p++;
    }
    
    free(content);
    return count;
}
