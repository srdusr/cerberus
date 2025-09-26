#include "cerberus.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
// uuid/uuid.h not required; implement UUID v4 using RAND_bytes

// Vault structure
typedef struct {
    uint8_t salt[SALT_LEN];
    uint8_t key[KEY_LEN];
    bool key_initialized;
    cerb_entry_t *entries;
    size_t num_entries;
    size_t capacity;
} cerb_vault_internal_t;

// Initialize crypto
cerb_error_t cerb_crypto_init(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return RAND_poll() ? CERB_OK : CERB_CRYPTO_ERROR;
}

// Cleanup crypto
void cerb_crypto_cleanup(void) {
    EVP_cleanup();
    ERR_free_strings();
}

// Create new vault
cerb_error_t cerb_vault_create(const char *master_password, cerb_vault_t **vault) {
    if (!master_password || !vault) return CERB_INVALID_ARG;
    
    cerb_vault_internal_t *v = calloc(1, sizeof(cerb_vault_internal_t));
    if (!v) return CERB_MEMORY_ERROR;
    
    if (RAND_bytes(v->salt, SALT_LEN) != 1) {
        free(v);
        return CERB_CRYPTO_ERROR;
    }
    
    // Derive key from password and salt
    if (!PKCS5_PBKDF2_HMAC(master_password, (int)strlen(master_password),
                           v->salt, SALT_LEN, PBKDF2_ITERATIONS,
                           EVP_sha256(), KEY_LEN, v->key)) {
        free(v);
        return CERB_CRYPTO_ERROR;
    }
    v->key_initialized = true;
    
    v->capacity = 32;
    v->entries = calloc(v->capacity, sizeof(cerb_entry_t));
    if (!v->entries) {
        free(v);
        return CERB_MEMORY_ERROR;
    }
    
    *vault = (cerb_vault_t *)v;
    return CERB_OK;
}

// Save vault to file (AES-256-GCM encrypted blob)
cerb_error_t cerb_vault_save(cerb_vault_t *vault, const char *vault_path) {
    if (!vault || !vault_path) return CERB_INVALID_ARG;
    cerb_vault_internal_t *v = (cerb_vault_internal_t *)vault;

    FILE *fp = fopen(vault_path, "wb");
    if (!fp) return CERB_STORAGE_ERROR;

    // Serialize entries: [num_entries][entries...]
    size_t plain_len = sizeof(uint32_t) + v->num_entries * sizeof(cerb_entry_t);
    unsigned char *plaintext = malloc(plain_len);
    if (!plaintext) { fclose(fp); return CERB_MEMORY_ERROR; }

    uint32_t n = (uint32_t)v->num_entries;
    memcpy(plaintext, &n, sizeof(uint32_t));
    if (v->num_entries > 0) {
        memcpy(plaintext + sizeof(uint32_t), v->entries, v->num_entries * sizeof(cerb_entry_t));
    }

    // Prepare AES-GCM
    unsigned char iv[IV_LEN];
    if (RAND_bytes(iv, IV_LEN) != 1) { free(plaintext); fclose(fp); return CERB_CRYPTO_ERROR; }
    unsigned char *ciphertext = malloc(plain_len);
    if (!ciphertext) { free(plaintext); fclose(fp); return CERB_MEMORY_ERROR; }
    int len = 0, ciphertext_len = 0;
    unsigned char tag[16];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(plaintext); free(ciphertext); fclose(fp); return CERB_CRYPTO_ERROR; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(plaintext); free(ciphertext); fclose(fp); return CERB_CRYPTO_ERROR;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(plaintext); free(ciphertext); fclose(fp); return CERB_CRYPTO_ERROR;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, v->key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(plaintext); free(ciphertext); fclose(fp); return CERB_CRYPTO_ERROR;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plain_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(plaintext); free(ciphertext); fclose(fp); return CERB_CRYPTO_ERROR;
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(plaintext); free(ciphertext); fclose(fp); return CERB_CRYPTO_ERROR;
    }
    ciphertext_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx); free(plaintext); free(ciphertext); fclose(fp); return CERB_CRYPTO_ERROR;
    }
    EVP_CIPHER_CTX_free(ctx);

    // Write file: MAGIC, VERSION, SALT, IV, TAG, CIPHERTEXT_LEN, CIPHERTEXT
    const char magic[8] = { 'C','E','R','B','E','R','U','S' };
    uint32_t version = 1;
    uint32_t clen = (uint32_t)ciphertext_len;

    if (fwrite(magic, 1, sizeof(magic), fp) != sizeof(magic) ||
        fwrite(&version, 1, sizeof(version), fp) != sizeof(version) ||
        fwrite(v->salt, 1, SALT_LEN, fp) != SALT_LEN ||
        fwrite(iv, 1, IV_LEN, fp) != IV_LEN ||
        fwrite(tag, 1, sizeof(tag), fp) != sizeof(tag) ||
        fwrite(&clen, 1, sizeof(clen), fp) != sizeof(clen) ||
        fwrite(ciphertext, 1, ciphertext_len, fp) != (size_t)ciphertext_len) {
        free(plaintext); free(ciphertext); fclose(fp); return CERB_STORAGE_ERROR;
    }

    free(plaintext);
    free(ciphertext);
    fclose(fp);
    return CERB_OK;
}

// Open vault from file
cerb_error_t cerb_vault_open(const char *master_password, const char *vault_path, cerb_vault_t **vault) {
    if (!master_password || !vault_path || !vault) return CERB_INVALID_ARG;
    FILE *fp = fopen(vault_path, "rb");
    if (!fp) return CERB_STORAGE_ERROR;

    const char expected_magic[8] = { 'C','E','R','B','E','R','U','S' };
    char magic[8];
    uint32_t version = 0;
    unsigned char salt[SALT_LEN];
    unsigned char iv[IV_LEN];
    unsigned char tag[16];
    uint32_t clen = 0;

    if (fread(magic, 1, sizeof(magic), fp) != sizeof(magic) ||
        memcmp(magic, expected_magic, sizeof(magic)) != 0 ||
        fread(&version, 1, sizeof(version), fp) != sizeof(version) ||
        fread(salt, 1, SALT_LEN, fp) != SALT_LEN ||
        fread(iv, 1, IV_LEN, fp) != IV_LEN ||
        fread(tag, 1, sizeof(tag), fp) != sizeof(tag) ||
        fread(&clen, 1, sizeof(clen), fp) != sizeof(clen)) {
        fclose(fp);
        return CERB_STORAGE_ERROR;
    }

    unsigned char *ciphertext = malloc(clen);
    if (!ciphertext) { fclose(fp); return CERB_MEMORY_ERROR; }
    if (fread(ciphertext, 1, clen, fp) != clen) { free(ciphertext); fclose(fp); return CERB_STORAGE_ERROR; }
    fclose(fp);

    // Derive key
    unsigned char key[KEY_LEN];
    if (!PKCS5_PBKDF2_HMAC(master_password, (int)strlen(master_password),
                           salt, SALT_LEN, PBKDF2_ITERATIONS,
                           EVP_sha256(), KEY_LEN, key)) {
        free(ciphertext);
        return CERB_CRYPTO_ERROR;
    }

    // Decrypt
    unsigned char *plaintext = malloc(clen); // ciphertext_len >= plaintext_len
    if (!plaintext) { free(ciphertext); return CERB_MEMORY_ERROR; }
    int len = 0, plain_len = 0;
    cerb_error_t status = CERB_OK;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(ciphertext); free(plaintext); return CERB_CRYPTO_ERROR; }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) status = CERB_CRYPTO_ERROR;
    if (status == CERB_OK && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) status = CERB_CRYPTO_ERROR;
    if (status == CERB_OK && EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) status = CERB_CRYPTO_ERROR;
    if (status == CERB_OK && EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)clen) != 1) status = CERB_CRYPTO_ERROR;
    plain_len = len;
    if (status == CERB_OK && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) status = CERB_CRYPTO_ERROR;
    if (status == CERB_OK && EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) status = CERB_CRYPTO_ERROR;
    plain_len += len;
    EVP_CIPHER_CTX_free(ctx);
    if (status != CERB_OK) { free(ciphertext); free(plaintext); return CERB_CRYPTO_ERROR; }

    // Deserialize
    if ((size_t)plain_len < sizeof(uint32_t)) { free(ciphertext); free(plaintext); return CERB_STORAGE_ERROR; }
    uint32_t n = 0; memcpy(&n, plaintext, sizeof(uint32_t));
    size_t expected = sizeof(uint32_t) + (size_t)n * sizeof(cerb_entry_t);
    if ((size_t)plain_len != expected) { free(ciphertext); free(plaintext); return CERB_STORAGE_ERROR; }

    cerb_vault_internal_t *v = calloc(1, sizeof(cerb_vault_internal_t));
    if (!v) { free(ciphertext); free(plaintext); return CERB_MEMORY_ERROR; }
    memcpy(v->salt, salt, SALT_LEN);
    memcpy(v->key, key, KEY_LEN);
    v->key_initialized = true;
    v->capacity = n > 0 ? n : 32;
    v->entries = calloc(v->capacity, sizeof(cerb_entry_t));
    if (!v->entries) { free(v); free(ciphertext); free(plaintext); return CERB_MEMORY_ERROR; }
    v->num_entries = n;
    if (n > 0) {
        memcpy(v->entries, plaintext + sizeof(uint32_t), (size_t)n * sizeof(cerb_entry_t));
    }

    *vault = (cerb_vault_t *)v;
    free(ciphertext);
    free(plaintext);
    return CERB_OK;
}

// Add entry to vault
cerb_error_t cerb_vault_add_entry(cerb_vault_t *vault, const cerb_entry_t *entry) {
    if (!vault || !entry) return CERB_INVALID_ARG;
    
    cerb_vault_internal_t *v = (cerb_vault_internal_t *)vault;
    
    // Check for duplicates
    for (size_t i = 0; i < v->num_entries; i++) {
        if (strcmp(v->entries[i].id, entry->id) == 0) {
            return CERB_DUPLICATE;
        }
    }
    
    // Resize if needed
    if (v->num_entries >= v->capacity) {
        size_t new_capacity = v->capacity * 2;
        cerb_entry_t *new_entries = realloc(v->entries, new_capacity * sizeof(cerb_entry_t));
        if (!new_entries) return CERB_MEMORY_ERROR;
        v->entries = new_entries;
        v->capacity = new_capacity;
    }
    
    // Add entry
    v->entries[v->num_entries++] = *entry;
    return CERB_OK;
}

// Update existing entry
cerb_error_t cerb_vault_update_entry(cerb_vault_t *vault, const cerb_entry_t *entry) {
    if (!vault || !entry) return CERB_INVALID_ARG;

    cerb_vault_internal_t *v = (cerb_vault_internal_t *)vault;

    for (size_t i = 0; i < v->num_entries; i++) {
        if (strcmp(v->entries[i].id, entry->id) == 0) {
            v->entries[i] = *entry;
            return CERB_OK;
        }
    }

    return CERB_NOT_FOUND;
}

// Delete entry by ID
cerb_error_t cerb_vault_delete_entry(cerb_vault_t *vault, const char *entry_id) {
    if (!vault || !entry_id) return CERB_INVALID_ARG;

    cerb_vault_internal_t *v = (cerb_vault_internal_t *)vault;

    for (size_t i = 0; i < v->num_entries; i++) {
        if (strcmp(v->entries[i].id, entry_id) == 0) {
            // Move last entry into this slot to keep array compact
            if (i != v->num_entries - 1) {
                v->entries[i] = v->entries[v->num_entries - 1];
            }
            memset(&v->entries[v->num_entries - 1], 0, sizeof(cerb_entry_t));
            v->num_entries--;
            return CERB_OK;
        }
    }

    return CERB_NOT_FOUND;
}

// Get entry by ID
cerb_error_t cerb_vault_get_entry(cerb_vault_t *vault, const char *entry_id, cerb_entry_t *entry) {
    if (!vault || !entry_id || !entry) return CERB_INVALID_ARG;

    cerb_vault_internal_t *v = (cerb_vault_internal_t *)vault;

    for (size_t i = 0; i < v->num_entries; i++) {
        if (strcmp(v->entries[i].id, entry_id) == 0) {
            *entry = v->entries[i];
            return CERB_OK;
        }
    }

    return CERB_NOT_FOUND;
}

// Get all entries (returns a newly allocated array the caller must free)
cerb_error_t cerb_vault_get_entries(cerb_vault_t *vault, cerb_entry_t **entries, size_t *count) {
    if (!vault || !entries || !count) return CERB_INVALID_ARG;

    cerb_vault_internal_t *v = (cerb_vault_internal_t *)vault;

    if (v->num_entries == 0) {
        *entries = NULL;
        *count = 0;
        return CERB_OK;
    }

    cerb_entry_t *out = calloc(v->num_entries, sizeof(cerb_entry_t));
    if (!out) return CERB_MEMORY_ERROR;

    memcpy(out, v->entries, v->num_entries * sizeof(cerb_entry_t));
    *entries = out;
    *count = v->num_entries;
    return CERB_OK;
}

// Basic substring search across website, username, and url
cerb_error_t cerb_vault_search(cerb_vault_t *vault, const char *query, cerb_entry_t **results, size_t *count) {
    if (!vault || !results || !count) return CERB_INVALID_ARG;

    cerb_vault_internal_t *v = (cerb_vault_internal_t *)vault;

    if (!query || *query == '\0') {
        return cerb_vault_get_entries(vault, results, count);
    }

    size_t matched = 0;
    // First pass: count
    for (size_t i = 0; i < v->num_entries; i++) {
        if ((strstr(v->entries[i].website, query) != NULL) ||
            (strstr(v->entries[i].username, query) != NULL) ||
            (strstr(v->entries[i].url, query) != NULL)) {
            matched++;
        }
    }

    if (matched == 0) {
        *results = NULL;
        *count = 0;
        return CERB_OK;
    }

    cerb_entry_t *out = calloc(matched, sizeof(cerb_entry_t));
    if (!out) return CERB_MEMORY_ERROR;

    size_t idx = 0;
    for (size_t i = 0; i < v->num_entries; i++) {
        if ((strstr(v->entries[i].website, query) != NULL) ||
            (strstr(v->entries[i].username, query) != NULL) ||
            (strstr(v->entries[i].url, query) != NULL)) {
            out[idx++] = v->entries[i];
        }
    }

    *results = out;
    *count = matched;
    return CERB_OK;
}

// Generate password
cerb_error_t cerb_generate_password(
    uint32_t length,
    bool use_upper,
    bool use_lower,
    bool use_digits,
    bool use_special,
    char *buffer,
    size_t buffer_size
) {
    if (!buffer || length < 8 || length > MAX_PASSWORD_LEN || buffer_size < length + 1) {
        return CERB_INVALID_ARG;
    }
    
    const char *lower = "abcdefghijklmnopqrstuvwxyz";
    const char *upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *digits = "0123456789";
    const char *special = "!@#$%^&*()-_=+[]{}|;:,.<>?";
    
    char charset[256] = {0};
    size_t pos = 0;
    
    if (use_lower) { strcpy(charset + pos, lower); pos += strlen(lower); }
    if (use_upper) { strcpy(charset + pos, upper); pos += strlen(upper); }
    if (use_digits) { strcpy(charset + pos, digits); pos += strlen(digits); }
    if (use_special) { strcpy(charset + pos, special); pos += strlen(special); }
    
    if (pos == 0) return CERB_INVALID_ARG;
    
    // Generate random password
    for (size_t i = 0; i < length; i++) {
        unsigned char byte;
        do {
            if (RAND_bytes(&byte, 1) != 1) {
                return CERB_CRYPTO_ERROR;
            }
        } while (byte >= (256 / pos) * pos);
        
        buffer[i] = charset[byte % pos];
    }
    
    buffer[length] = '\0';
    return CERB_OK;
}

// Generate UUID v4 (xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx)
void cerb_generate_uuid(char *uuid) {
    unsigned char bytes[16];
    if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
        // Fallback to zeroed UUID on failure
        memset(uuid, '0', 36);
        uuid[8] = uuid[13] = uuid[18] = uuid[23] = '-';
        uuid[36] = '\0';
        return;
    }
    // Set version (4)
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    // Set variant (10xx)
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    static const char *hex = "0123456789abcdef";
    int p = 0;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            uuid[p++] = '-';
        }
        uuid[p++] = hex[(bytes[i] >> 4) & 0x0F];
        uuid[p++] = hex[bytes[i] & 0x0F];
    }
    uuid[p] = '\0';
}

// Get current timestamp
time_t cerb_current_timestamp(void) {
    return time(NULL);
}

// Cleanup vault
void cerb_vault_close(cerb_vault_t *vault) {
    if (!vault) return;
    
    cerb_vault_internal_t *v = (cerb_vault_internal_t *)vault;
    
    // Securely wipe sensitive data
    memset(v->key, 0, KEY_LEN);
    memset(v->salt, 0, SALT_LEN);
    
    // Wipe entries
    for (size_t i = 0; i < v->num_entries; i++) {
        memset(&v->entries[i], 0, sizeof(cerb_entry_t));
    }
    
    free(v->entries);
    free(v);
}
