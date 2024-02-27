#ifndef MAIN_H
#define MAIN_H

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

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
void save_password(struct Password *password, const char *dir);
void load_passwords(const char *dir);
void copy_to_clipboard(char *text);

#endif /* MAIN_H */
