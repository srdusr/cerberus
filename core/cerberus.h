#ifndef CERBERUS_H
#define CERBERUS_H

#ifdef __cplusplus
extern "C" {
#endif

// Public API for Cerberus C core
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdbool.h>

// Constants
#define SALT_LEN 16
#define KEY_LEN 32
#define IV_LEN 12
#define PBKDF2_ITERATIONS 200000
#define MAX_PASSWORD_LEN 256

// Error codes
typedef enum cerb_error_e {
    CERB_OK = 0,
    CERB_INVALID_ARG = 1,
    CERB_CRYPTO_ERROR = 2,
    CERB_MEMORY_ERROR = 3,
    CERB_STORAGE_ERROR = 4,
    CERB_DUPLICATE = 5,
    CERB_NOT_FOUND = 6
} cerb_error_t;

// Password entry
typedef struct cerb_entry_s {
    char id[37];            // UUID v4 (36 chars + NUL)
    char website[128];
    char username[128];
    char url[256];
    char password[MAX_PASSWORD_LEN];
    time_t created_at;
    time_t updated_at;
    time_t last_used;
} cerb_entry_t;

// Opaque vault type
typedef struct cerb_vault_s cerb_vault_t;

// Crypto lifecycle
cerb_error_t cerb_crypto_init(void);
void cerb_crypto_cleanup(void);

// Vault lifecycle
cerb_error_t cerb_vault_create(const char *master_password, cerb_vault_t **vault);
cerb_error_t cerb_vault_save(cerb_vault_t *vault, const char *vault_path);
cerb_error_t cerb_vault_open(const char *master_password, const char *vault_path, cerb_vault_t **vault);
void cerb_vault_close(cerb_vault_t *vault);

// Vault CRUD
cerb_error_t cerb_vault_add_entry(cerb_vault_t *vault, const cerb_entry_t *entry);
cerb_error_t cerb_vault_update_entry(cerb_vault_t *vault, const cerb_entry_t *entry);
cerb_error_t cerb_vault_delete_entry(cerb_vault_t *vault, const char *entry_id);
cerb_error_t cerb_vault_get_entry(cerb_vault_t *vault, const char *entry_id, cerb_entry_t *entry);
cerb_error_t cerb_vault_get_entries(cerb_vault_t *vault, cerb_entry_t **entries, size_t *count);
cerb_error_t cerb_vault_search(cerb_vault_t *vault, const char *query, cerb_entry_t **results, size_t *count);

// Utilities
cerb_error_t cerb_generate_password(uint32_t length, bool use_upper, bool use_lower, bool use_digits, bool use_special, char *buffer, size_t buffer_size);
void cerb_generate_uuid(char *uuid);
time_t cerb_current_timestamp(void);

#ifdef __cplusplus
}
#endif

#endif // CERBERUS_H
