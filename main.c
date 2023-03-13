#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define MAX_PASSWORD_LENGTH 128

struct Password {
    char website[128];
    char username[128];
    char password[MAX_PASSWORD_LENGTH];
    char notes[256];
};

void generate_password(char *password, int length) {
    // Generate a random password of the specified length
    // using a combination of upper and lowercase letters, digits, and special characters
}

void encrypt_password(struct Password *password, unsigned char *key) {
    // Encrypt the password using AES-256 encryption
}

void decrypt_password(struct Password *password, unsigned char *key) {
    // Decrypt the password using AES-256 decryption
}

void save_password(struct Password *password, char *filename, unsigned char *key) {
    // Save the password information to a file in an encrypted format using AES-256 encryption
}

void load_password(struct Password *password, char *filename, unsigned char *key) {
    // Load the password information from a file and decrypt it using AES-256 decryption
}

int main() {
    int choice;
    char filename[256];
    struct Password password;
    unsigned char key[AES_BLOCK_SIZE];

    // Get the encryption key from the user
    printf("Enter the encryption key: ");
    fgets(key, AES_BLOCK_SIZE, stdin);

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


