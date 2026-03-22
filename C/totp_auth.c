/**
 * TOTP Authenticator - C Implementation
 * Main entry point and CLI interface
 */

#include "totp_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_DB_PATH "./totp_auth.db"

int main(int argc, char *argv[]) {
    const char *db_path = DEFAULT_DB_PATH;
    const char *action = NULL;
    const char *name = NULL;
    const char *secret = NULL;
    const char *filename = NULL;
    
    print_banner();
    
    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else if (strcmp(argv[i], "--init") == 0) {
            action = "init";
        } else if (strcmp(argv[i], "--add") == 0 && i + 2 < argc) {
            action = "add";
            name = argv[++i];
            secret = argv[++i];
        } else if (strcmp(argv[i], "--list") == 0) {
            action = "list";
        } else if (strcmp(argv[i], "--get") == 0 && i + 1 < argc) {
            action = "get";
            name = argv[++i];
        } else if (strcmp(argv[i], "--delete") == 0 && i + 1 < argc) {
            action = "delete";
            name = argv[++i];
        } else if (strcmp(argv[i], "--export") == 0 && i + 1 < argc) {
            action = "export";
            filename = argv[++i];
        } else if (strcmp(argv[i], "--import") == 0 && i + 1 < argc) {
            action = "import";
            filename = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
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
    
    /* Handle init */
    if (strcmp(action, "init") == 0) {
        char password[256];
        printf("Enter master password: ");
        if (fgets(password, sizeof(password), stdin) == NULL) {
            printf("[ERROR] Failed to read password\n");
            storage_close();
            return 1;
        }
        password[strcspn(password, "\n")] = '\0';
        
        if (password_setup(password)) {
            printf("[OK] Master password set up\n");
        } else {
            printf("[ERROR] Password already set or invalid\n");
        }
        storage_close();
        return 0;
    }
    
    /* Handle list */
    if (strcmp(action, "list") == 0) {
        SiteStore store;
        if (storage_get_all_sites(&store) >= 0) {
            printf("\nStored sites (%d):\n", store.count);
            printf("────────────────────────────────────────────\n");
            for (int i = 0; i < store.count; i++) {
                Site *s = &store.sites[i];
                TOTPResult r = totp_generate(s->secret, s->period, s->digits, s->algorithm, 0);
                printf("  %s\n", s->name);
                printf("    Code: %s (expires in %ds)\n", r.code, r.remaining);
                if (s->issuer[0]) printf("    Issuer: %s\n", s->issuer);
                printf("    Algorithm: %s, %d digits, %ds period\n",
                        s->algorithm == ALGO_SHA256 ? "SHA256" :
                        s->algorithm == ALGO_SHA512 ? "SHA512" : "SHA1",
                        s->digits, s->period);
                printf("\n");
            }
        }
        storage_close();
        return 0;
    }
    
    /* Handle get */
    if (strcmp(action, "get") == 0) {
        Site site;
        if (storage_get_site_by_name(name, &site)) {
            TOTPResult r = totp_generate(site.secret, site.period, site.digits, site.algorithm, 0);
            printf("\n%s", r.code);
            storage_close();
            return 0;
        } else {
            printf("[ERROR] Site not found: %s\n", name);
            storage_close();
            return 1;
        }
    }
    
    /* Handle add */
    if (strcmp(action, "add") == 0) {
        Site site;
        memset(&site, 0, sizeof(site));
        strncpy(site.name, name, sizeof(site.name) - 1);
        strncpy(site.secret, secret, sizeof(site.secret) - 1);
        site.digits = DEFAULT_DIGITS;
        site.period = DEFAULT_PERIOD;
        site.algorithm = ALGO_SHA1;
        site.enabled = 1;
        
        if (storage_add_site(&site)) {
            printf("[OK] Added site: %s\n", name);
        } else {
            printf("[ERROR] Failed to add site\n");
        }
        storage_close();
        return 0;
    }
    
    /* Handle delete */
    if (strcmp(action, "delete") == 0) {
        Site site;
        if (storage_get_site_by_name(name, &site)) {
            printf("Delete %s? (y/N): ", name);
            char confirm[8];
            if (fgets(confirm, sizeof(confirm), stdin) != NULL && (confirm[0] == 'y' || confirm[0] == 'Y')) {
                if (storage_delete_site(site.id)) {
                    printf("[OK] Deleted site: %s\n", name);
                } else {
                    printf("[ERROR] Failed to delete site\n");
                }
            } else {
                printf("Cancelled.\n");
            }
        } else {
            printf("[ERROR] Site not found: %s\n", name);
        }
        storage_close();
        return 0;
    }
    
    /* Handle export */
    if (strcmp(action, "export") == 0) {
        if (export_sites_json(filename)) {
            printf("[OK] Exported to %s\n", filename);
        } else {
            printf("[ERROR] Export failed\n");
        }
        storage_close();
        return 0;
    }
    
    /* Handle import */
    if (strcmp(action, "import") == 0) {
        int count = import_sites_json(filename);
        printf("[OK] Imported %d sites from %s\n", count, filename);
        storage_close();
        return 0;
    }
    
    storage_close();
    return 0;
}
