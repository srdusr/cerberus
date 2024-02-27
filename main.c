// TODO: Secret stored in memory must be encrypted with a key derived from the
// user password or consider making password manager stateless (no passwords
// stored locally)
// TODO: Replace CBC with GCM or CCM to prevent padding attacks
// TODO: Have ascii art of a cerberus on start menu/page

#include "main.h"

struct Password passwords[MAX_PASSWORDS];
int numPasswords = 0;

void generate_password(char *password, int length) {
  // Define the character set for the password
  char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"
                   "789!@#$%^&*-_=+{}[]|;:',.<>/?";
  int charset_size = strlen(charset);

  // Seed the random number generator
  srand(time(NULL));

  for (int i = 0; i < length; i++) {
    int index = rand() % charset_size;
    password[i] = charset[index];
  }

  password[length] = '\0'; // Null-terminate the password
  printf("Generated Password: %s\n", password);
}

void save_password(struct Password *password, const char *dir) {
  // Save the password information to a file
  FILE *fp;
  char filename[256];
  snprintf(filename, sizeof(filename), "%s/%s.dat", dir, password->website);
  fp = fopen(filename, "wb");
  if (fp == NULL) {
    printf("Error: could not open file %s for writing.\n", filename);
    return;
  }

  // Write the password to the file
  fwrite(password, sizeof(struct Password), 1, fp);

  fclose(fp);
}

void load_passwords(const char *dir) {
  printf("Available Passwords:\n");
  DIR *d;
  struct dirent *dir_entry;
  d = opendir(dir);
  if (d) {
    int count = 0;
    while ((dir_entry = readdir(d)) != NULL) {
      if (dir_entry->d_type == DT_REG) { // If it's a regular file
        char filename[256];
        snprintf(filename, sizeof(filename), "%s/%s", dir, dir_entry->d_name);
        FILE *file = fopen(filename, "rb");
        if (file != NULL) {
          struct Password password;
          fread(&password, sizeof(struct Password), 1, file);

          // Null-terminate the strings
          password.website[MAX_WEBSITE_LENGTH - 1] = '\0';
          password.username[MAX_USERNAME_LENGTH - 1] = '\0';
          password.password[MAX_PASSWORD_LENGTH - 1] = '\0';

          passwords[count++] = password;
          printf("%d. Website: %s, Username: %s\n", count, password.website,
                 password.username);
          fclose(file);
        }
      }
    }
    numPasswords = count;
    closedir(d);
    if (count == 0) {
      printf("No passwords found.\n");
    }
  }
}

void copy_to_clipboard(char *text) {
  // Use xclip command to copy text to clipboard
  FILE *pipe = popen("xclip -selection clipboard", "w");
  if (pipe != NULL) {
    fprintf(pipe, "%s", text);
    pclose(pipe);
    printf("Copied to clipboard: %s\n", text);
  } else {
    printf("Error: Could not copy to clipboard.\n");
  }
}

int main() {
  const char *dir = "tmp"; // Directory to store password files
  mkdir(dir, 0700);        // Create directory if it doesn't exist

  char user_password[MAX_PASSWORD_LENGTH];

  FILE *key_file = fopen("master.key", "rb");
  if (key_file == NULL) {
    printf("Enter your new master password: ");
    fgets(user_password, sizeof(user_password), stdin);
    user_password[strcspn(user_password, "\n")] = 0; // Remove newline character

    // Save master password to file
    key_file = fopen("master.key", "wb");
    if (key_file == NULL) {
      printf("Error: Could not create master password file.\n");
      return 1;
    }
    fwrite(user_password, sizeof(user_password), 1, key_file);
    fclose(key_file);
  } else {
    // If master key exists, ask for the password
    printf("Enter your master password: ");
    fgets(user_password, sizeof(user_password), stdin);
    user_password[strcspn(user_password, "\n")] = 0; // Remove newline character

    // Check if the entered password matches the stored master password
    char stored_password[MAX_PASSWORD_LENGTH];
    fread(stored_password, sizeof(stored_password), 1, key_file);
    fclose(key_file);
    if (strcmp(user_password, stored_password) != 0) {
      printf("Invalid master password. Exiting...\n");
      return 1;
    }
  }

  int choice;
  while (1) {
    printf("\n1. Create New Password\n");
    printf("2. Show Passwords\n");
    printf("3. Exit\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);

    switch (choice) {
    case 1: {
      if (numPasswords >= MAX_PASSWORDS) {
        printf("Maximum number of passwords reached.\n");
        break;
      }
      struct Password password;
      int length;
      printf("Enter password length: ");
      scanf("%d", &length);
      generate_password(password.password, length);
      printf("Enter website: ");
      scanf("%s", password.website);
      printf("Enter username: ");
      scanf("%s", password.username);
      save_password(&password, dir);
      printf("Password information saved to %s\n", password.website);
      passwords[numPasswords++] = password;
      break;
    }
    case 2: {
      load_passwords(dir);
      printf("Enter the number of the password to copy (0 to cancel): ");
      int selection;
      scanf("%d", &selection);
      if (selection > 0 && selection <= numPasswords) {
        struct Password selected_password = passwords[selection - 1];
        printf("Selected Password:\n");
        printf("- Website: %s\n", selected_password.website);
        printf("- Username: %s\n", selected_password.username);
        printf("- Password: %s\n", selected_password.password);
        printf("Copy to clipboard? (1 for Password, 2 for Username, 0 to "
               "cancel): ");
        int copy_choice;
        scanf("%d", &copy_choice);
        switch (copy_choice) {
        case 1:
          copy_to_clipboard(selected_password.password);
          break;
        case 2:
          copy_to_clipboard(selected_password.username);
          break;
        default:
          printf("Canceled.\n");
        }
      } else if (selection != 0) {
        printf("Invalid selection.\n");
      }
      break;
    }
    case 3:
      printf("Exiting program...\n");
      return 0;
    default:
      printf("Invalid choice. Please enter 1, 2, or 3.\n");
    }
  }

  return 0;
}
