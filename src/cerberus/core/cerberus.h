#ifndef CERBERUS_CORE_H
#define CERBERUS_CORE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// Maximum lengths for fields
#define MAX_WEBSITE_LEN 256
#define MAX_USERNAME_LEN 256
#define MAX_PASSWORD_LEN 1024
#define MAX_NOTES_LEN 4096
#define MAX_TAGS 32
#define MAX_TAG_LEN 64
#define MAX_CUSTOM_FIELDS 32
#define MAX_CUSTOM_KEY_LEN 64
#define MAX_CUSTOM_VALUE_LEN 1024
#define MAX_ENTRIES 65536
#define SALT_LEN 32
#define KEY_LEN 32  // 256 bits for AES-256
#define IV_LEN 16   // 128 bits for AES block size
#define PBKDF2_ITERATIONS 100000

// Error codes
typedef enum {
    CERB_OK = 0,
    CERB_ERROR = -1,
    CERB_INVALID_ARG = -2,
    CERB_NOT_FOUND = -3,
    CERB_DUPLICATE = -4,
    CERB_STORAGE_ERROR = -5,
    CERB_CRYPTO_ERROR = -6,
    CERB_MEMORY_ERROR = -7,
    CERB_INVALID_STATE = -8,
    CERB_NOT_IMPLEMENTED = -9
} cerb_error_t;

// Custom field structure
typedef struct {
    char key[MAX_CUSTOM_KEY_LEN];
    char value[MAX_CUSTOM_VALUE_LEN];
} cerb_custom_field_t;

// Password entry structure
typedef struct {
    char id[37];  // UUID string (36 chars + null terminator)
    char website[MAX_WEBSITE_LEN];
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char notes[MAX_NOTES_LEN];
    char url[1024];
    char tags[MAX_TAGS][MAX_TAG_LEN];
    size_t num_tags;
    time_t created_at;
    time_t updated_at;
    time_t last_used;
    bool favorite;
    cerb_custom_field_t custom_fields[MAX_CUSTOM_FIELDS];
    size_t num_custom_fields;
} cerb_entry_t;

// Vault structure
typedef struct cerb_vault_t cerb_vault_t;

// Basic entry struct for FFI bindings (avoids nested arrays)
typedef struct {
    char id[37];
    char website[MAX_WEBSITE_LEN];
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    char notes[MAX_NOTES_LEN];
    char url[1024];
    time_t created_at;
    time_t updated_at;
} cerb_entry_basic_t;

// Core API

// Initialize the crypto subsystem
cerb_error_t cerb_crypto_init(void);

// Cleanup the crypto subsystem
void cerb_crypto_cleanup(void);

// Initialize a new vault
cerb_error_t cerb_vault_create(const char *master_password, cerb_vault_t **vault);

// Open an existing vault
cerb_error_t cerb_vault_open(const char *master_password, const char *vault_path, cerb_vault_t **vault);

// Save vault to file
cerb_error_t cerb_vault_save(cerb_vault_t *vault, const char *vault_path);

// Close and free a vault
void cerb_vault_close(cerb_vault_t *vault);

// Add a new entry to the vault
cerb_error_t cerb_vault_add_entry(cerb_vault_t *vault, const cerb_entry_t *entry);
cerb_error_t cerb_vault_add_entry_basic(cerb_vault_t *vault, const cerb_entry_basic_t *entry);

// Update an existing entry
cerb_error_t cerb_vault_update_entry(cerb_vault_t *vault, const cerb_entry_t *entry);
cerb_error_t cerb_vault_update_entry_basic(cerb_vault_t *vault, const cerb_entry_basic_t *entry);

// Delete an entry by ID
cerb_error_t cerb_vault_delete_entry(cerb_vault_t *vault, const char *entry_id);

// Get an entry by ID
cerb_error_t cerb_vault_get_entry(cerb_vault_t *vault, const char *entry_id, cerb_entry_t *entry);
cerb_error_t cerb_vault_get_entry_basic(cerb_vault_t *vault, const char *entry_id, cerb_entry_basic_t *entry);

// Get all entries
cerb_error_t cerb_vault_get_entries(cerb_vault_t *vault, cerb_entry_t **entries, size_t *count);
cerb_error_t cerb_vault_get_entries_basic(cerb_vault_t *vault, cerb_entry_basic_t **entries, size_t *count);

// Search entries by query string
cerb_error_t cerb_vault_search(cerb_vault_t *vault, const char *query, cerb_entry_t **results, size_t *count);
cerb_error_t cerb_vault_search_basic(cerb_vault_t *vault, const char *query, cerb_entry_basic_t **results, size_t *count);

// Generate a secure random password
cerb_error_t cerb_generate_password(
    uint32_t length,
    bool use_upper,
    bool use_lower,
    bool use_digits,
    bool use_special,
    char *buffer,
    size_t buffer_size
);

// Import from other password managers
cerb_error_t cerb_import_bitwarden_json(cerb_vault_t *vault, const char *json_path);
cerb_error_t cerb_import_lastpass_csv(cerb_vault_t *vault, const char *csv_path);
cerb_error_t cerb_import_chrome_csv(cerb_vault_t *vault, const char *csv_path);

// Export to various formats
cerb_error_t cerb_export_json(cerb_vault_t *vault, const char *json_path);
cerb_error_t cerb_export_csv(cerb_vault_t *vault, const char *csv_path);

// Utility functions
void cerb_generate_uuid(char *uuid);
time_t cerb_current_timestamp(void);

#endif // CERBERUS_CORE_H
