// TODO: Fix not specifying password length
// TODO: Fix not specifying password options for which characters/digits/lowercase or uppercase letters
// TODO: Fix generated encryption key must not be put in directly by user
// TODO: Use PBKDF2 for generating keys,
// TODO: Secret stored in memory must be encrypted with a key derived from the user password or consider making password manager stateless (no passwords stored locally)
// TODO: Replace CBC with GCM or CCM to prevent padding attacks
// TODO: Have ascii art of a cerberus on start menu/page

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#define MAX_PASSWORD_LENGTH 128
#define AES_KEY_SIZE 256 / 8

struct Password {
    char website[128];
    char username[128];
    char password[MAX_PASSWORD_LENGTH];
    char notes[256];
};

void generate_password(char *password, int length) {
    // Generate a random password of the specified length
    // using a combination of upper and lowercase letters, digits, and special characters
    char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}\\|;:'\",.<>/?";
    int charset_size = strlen(charset);

    for (int i = 0; i < length; i++) {
        int index = rand() % charset_size;
        password[i] = charset[index];
    }

    password[length] = '\0';
}

void encrypt_password(struct Password *password, unsigned char *key) {
    AES_KEY aes_key;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char encrypted_password[AES_BLOCK_SIZE];

    // Generate a random initialization vector
    RAND_bytes(iv, AES_BLOCK_SIZE);

    // Initialize the encryption key
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Encrypt the password using AES-256 encryption
    int outlen, tmplen;
    EVP_EncryptUpdate(ctx, encrypted_password, &outlen, (unsigned char*)password->password, AES_BLOCK_SIZE);
    EVP_EncryptFinal_ex(ctx, encrypted_password + outlen, &tmplen);

    // Copy the encrypted password and IV back into the password struct
    memcpy(password->password, encrypted_password, AES_BLOCK_SIZE);
    memcpy(password->notes, iv, AES_BLOCK_SIZE);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void decrypt_password(struct Password *password, unsigned char *key) {
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char decrypted_password[AES_BLOCK_SIZE];

    // Read the initialization vector from the password struct
    memcpy(iv, password->notes, AES_BLOCK_SIZE);

    // Initialize the decryption context
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    // Decrypt the password using AES-256 decryption
    int outlen, tmplen;
    EVP_DecryptUpdate(ctx, decrypted_password, &outlen, (unsigned char*)password->password, AES_BLOCK_SIZE);
    EVP_DecryptFinal_ex(ctx, decrypted_password + outlen, &tmplen);

    // Copy the decrypted password back into the password struct
    memcpy(password->password, decrypted_password, MAX_PASSWORD_LENGTH);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void save_password(struct Password *password, char *filename, unsigned char *key) {
    // Save the password information to a file in an encrypted format using AES-256 encryption
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        printf("Error: could not open file %s for writing.\n", filename);
        return;
    }

    // Encrypt the password information
    encrypt_password(password, key);

    // Write the encrypted password information to the file
    fwrite(password, sizeof(struct Password), 1, fp);

    fclose(fp);
}

void load_password(struct Password *password, char *filename, unsigned char *key) {
    // Load the password information from a file and decrypt it using AES-256 decryption
    // Open the file for reading
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Error: Could not open file %s\n", filename);
        return;
    }

    // Read the encrypted password information from the file
    unsigned char iv[AES_BLOCK_SIZE];
    fread(iv, 1, AES_BLOCK_SIZE, file);
    unsigned char encrypted[sizeof(struct Password)];
    fread(encrypted, 1, sizeof(struct Password), file);

    // Decrypt the password information
    AES_KEY aes_key;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    int outlen, finallen;
    EVP_DecryptUpdate(ctx, (unsigned char*)password, &outlen, encrypted, sizeof(struct Password));
    EVP_DecryptFinal_ex(ctx, ((unsigned char*)password) + outlen, &finallen);
    EVP_CIPHER_CTX_free(ctx);

    // Close the file
    fclose(file);
}

int main() {
    int choice;
    char filename[256];
    struct Password password;
    unsigned char key[AES_BLOCK_SIZE];

    // Get the encryption key from the user
    printf("Enter the encryption key: ");
    char key_str[AES_BLOCK_SIZE];
    printf("Enter the encryption key: ");
    fgets(key_str, AES_BLOCK_SIZE, stdin);
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        key[i] = (unsigned char) key_str[i];
    }

    // Loop until the user chooses to exit the program
    do {
        // Display the menu of options to the user
        printf("\n1. Generate new password\n");
        printf("2. Save password information to file\n");
        printf("3. Load password information from file\n");
        printf("4. Exit program\n\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                // Generate a new password and display it to the user
                generate_password(password.password, MAX_PASSWORD_LENGTH);
                printf("New password: %s\n", password.password);
                break;
            case 2:
                // Get the filename from the user and save the password information to a file
                printf("Enter the filename to save to: ");
                scanf("%s", filename);
                save_password(&password, filename, key);
                printf("Password information saved to %s\n", filename);
                break;
            case 3:
                // Get the filename from the user and load the password information from a file
                printf("Enter the filename to load from:");
                scanf("%s", filename);
                load_password(&password, filename, key);
                printf("Password information loaded from %s\n", filename);
                // Display the password information to the user
                printf("Website: %s\n", password.website);
                printf("Username: %s\n", password.username);
                printf("Password: %s\n", password.password);
                printf("Notes: %s\n", password.notes);
                break;
            case 4:
                // Exit the program
                printf("Exiting program...\n");
                break;
            default:
                // Invalid choice
                printf("Invalid choice. Please enter a number between 1 and 4.\n");
                break;
        }
    } while (choice != 4);

    return 0;
}
