#ifndef MAIN_H
#define MAIN_H

#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/io.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SALT_SIZE 16
#define PBKDF2_ITERATIONS 10000
#define AES_KEY_SIZE 32 // AES-256
#define AES_BLOCK_SIZE 16

#define MAX_PASSWORD_LENGTH 128
#define MAX_WEBSITE_LENGTH 128
#define MAX_USERNAME_LENGTH 128
#define MAX_PASSWORDS 100

struct Password {
  char website[MAX_WEBSITE_LENGTH];
  char username[MAX_USERNAME_LENGTH];
  char password[MAX_PASSWORD_LENGTH];
};

extern struct Password passwords[MAX_PASSWORDS];
extern int numPasswords;

void generate_password(char *password, int length);
void save_password(struct Password *password, const char *website,
                   const char *dir, const char *user_password);
void load_passwords(const char *dir, const char *user_password);
void copy_to_clipboard(char *text);
void print_ascii_art(const char *filename);

#endif /* MAIN_H */
