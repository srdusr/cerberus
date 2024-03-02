// TODO: Secret stored in memory must be encrypted with a key derived from the
// user password or consider making password manager stateless (no passwords
// stored locally)

#include "main.h"

struct Password passwords[MAX_PASSWORDS];
int numPasswords = 0;

FILE *log_file;

void log_message(const char *message) {
  if (log_file == NULL) {
    printf("Error: Log file not available.\n");
    return;
  }

  time_t current_time;
  struct tm *time_info;
  char time_string[80];

  time(&current_time);
  time_info = localtime(&current_time);

  strftime(time_string, sizeof(time_string), "[%Y-%m-%d %H:%M:%S] ", time_info);
  fprintf(log_file, "%s %s\n", time_string,
          message); // Print timestamp and message
}

void initialize_log() {
  log_file = fopen("cerberus.log", "a");
  if (log_file == NULL) {
    printf("Error: Could not open log file.\n");
  } else {
    log_message("=== cerberus log ==="); // Initial log message
  }
}

void close_log() {
  if (log_file != NULL) {
    fclose(log_file);
  }
}

void error_exit(const char *error_message) {
  log_message(error_message);
  if (log_file != NULL) {
    fclose(log_file);
  }
  exit(1);
}

void clear_input_buffer() {
  int c;
  while ((c = getchar()) != '\n' && c != EOF)
    ;
}

void check_password_policy(const char *password) {
  int length = strlen(password);
  if (length < 8) {
    error_exit("Password must be at least 8 characters long.");
  }

  bool has_upper = false, has_lower = false, has_digit = false,
       has_special = false;
  for (int i = 0; i < length; i++) {
    if (isupper(password[i])) {
      has_upper = true;
    } else if (islower(password[i])) {
      has_lower = true;
    } else if (isdigit(password[i])) {
      has_digit = true;
    } else {
      has_special = true;
    }
  }

  if (!has_upper || !has_lower || !has_digit || !has_special) {
    error_exit("Password must contain at least one uppercase letter, one "
               "lowercase letter, one digit, and one special character.");
  }
}

void generate_password(char *password, int length) {
  if (length < 8 || length > MAX_PASSWORD_LENGTH - 1) {
    printf("Invalid password length. Please enter a length between 8 and %d.\n",
           MAX_PASSWORD_LENGTH - 1);
    return;
  }

  char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456"
                   "789!@#$%^&*()-_=+[]{}|;:',.<>?";
  int charset_size = strlen(charset);

  srand(time(NULL));

  // Initialize flags to check if each required character type is included
  bool has_upper = false, has_lower = false, has_digit = false,
       has_special = false;

  // Create password with at least one character from each required type
  password[0] = charset[rand() % 26];      // at least one uppercase letter
  password[1] = charset[26 + rand() % 26]; // at least one lowercase letter
  password[2] = charset[52 + rand() % 10]; // at least one digit
  password[3] = charset[62 + rand() % 14]; // at least one special character

  // Fill the rest of the password randomly from the character set
  for (int i = 4; i < length; i++) {
    password[i] = charset[rand() % charset_size];
  }

  password[length] = '\0';

  // Shuffle the password characters
  for (int i = 0; i < length; i++) {
    int j = rand() % length;
    char temp = password[i];
    password[i] = password[j];
    password[j] = temp;
  }

  printf("Generated Password: %s\n", password);
}

void derive_key(unsigned char *key, const char *password, unsigned char *salt) {
  PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE,
                    PBKDF2_ITERATIONS, EVP_sha256(), AES_KEY_SIZE, key);
}

void encrypt_password(struct Password *password, const char *user_password) {
  unsigned char iv[AES_BLOCK_SIZE];
  unsigned char encrypted_password[MAX_PASSWORD_LENGTH];

  RAND_bytes(iv, AES_BLOCK_SIZE);

  unsigned char key[AES_KEY_SIZE];
  derive_key(key, user_password, iv);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

  int outlen, tmplen;
  EVP_EncryptUpdate(ctx, encrypted_password, &outlen,
                    (unsigned char *)password->password,
                    strlen(password->password));
  EVP_EncryptFinal_ex(ctx, encrypted_password + outlen, &tmplen);

  memcpy(password->password, encrypted_password, outlen + tmplen);
  memcpy(password->username, iv, AES_BLOCK_SIZE);

  EVP_CIPHER_CTX_free(ctx);
}

void decrypt_password(struct Password *password, const char *user_password) {
  unsigned char iv[AES_BLOCK_SIZE];
  unsigned char decrypted_password[MAX_PASSWORD_LENGTH];
  int decrypted_len = 0;

  memcpy(iv, password->username, AES_BLOCK_SIZE);

  unsigned char key[AES_KEY_SIZE];
  derive_key(key, user_password, iv);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

  int outlen, tmplen;
  EVP_DecryptUpdate(ctx, decrypted_password, &outlen,
                    (unsigned char *)password->password,
                    strlen(password->password));
  EVP_DecryptFinal_ex(ctx, decrypted_password + outlen, &tmplen);

  decrypted_password[outlen + tmplen] = '\0';

  strcpy(password->password, (char *)decrypted_password);

  EVP_CIPHER_CTX_free(ctx);
}

void save_password(struct Password *password, const char *website,
                   const char *dir, const char *user_password) {
  unsigned char iv[AES_BLOCK_SIZE];
  RAND_bytes(iv, AES_BLOCK_SIZE);

  unsigned char key[AES_KEY_SIZE];
  derive_key(key, user_password, iv);

  unsigned char encrypted_password[MAX_PASSWORD_LENGTH];
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

  int outlen, tmplen;
  EVP_EncryptUpdate(ctx, encrypted_password, &outlen,
                    (unsigned char *)password->password,
                    strlen(password->password));
  EVP_EncryptFinal_ex(ctx, encrypted_password + outlen, &tmplen);

  char filename[256];
  snprintf(filename, sizeof(filename), "%s/%s_%s.dat", dir, website,
           password->username);
  FILE *fp = fopen(filename, "wb");
  if (fp == NULL) {
    printf("Error: could not open file %s for writing.\n", filename);
    return;
  }
  fwrite(iv, sizeof(iv), 1, fp);
  fwrite(encrypted_password, outlen + tmplen, 1, fp);

  fclose(fp);
  EVP_CIPHER_CTX_free(ctx);
}

void load_passwords(const char *dir, const char *user_password) {
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

          unsigned char iv[AES_BLOCK_SIZE];
          fread(iv, sizeof(iv), 1, file);

          unsigned char encrypted_password[MAX_PASSWORD_LENGTH];
          int len = fread(encrypted_password, 1, MAX_PASSWORD_LENGTH, file);

          unsigned char key[AES_KEY_SIZE];
          derive_key(key, user_password, iv);

          unsigned char decrypted_password[MAX_PASSWORD_LENGTH];
          EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
          EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);

          int outlen, tmplen;
          EVP_DecryptUpdate(ctx, decrypted_password, &outlen,
                            encrypted_password, len);
          EVP_DecryptFinal_ex(ctx, decrypted_password + outlen, &tmplen);

          decrypted_password[outlen + tmplen] = '\0';

          fclose(file);
          EVP_CIPHER_CTX_free(ctx);

          // Extract website and username from filename
          char website[MAX_WEBSITE_LENGTH];
          char username[MAX_USERNAME_LENGTH];
          sscanf(dir_entry->d_name, "%[^_]_%[^.]", website, username);

          // Copy decrypted password to password field
          strncpy(password.website, website, MAX_WEBSITE_LENGTH - 1);
          password.website[MAX_WEBSITE_LENGTH - 1] = '\0';
          strncpy(password.username, username, MAX_USERNAME_LENGTH - 1);
          password.username[MAX_USERNAME_LENGTH - 1] = '\0';
          strncpy(password.password, decrypted_password,
                  MAX_PASSWORD_LENGTH - 1);
          password.password[MAX_PASSWORD_LENGTH - 1] = '\0';

          passwords[count++] = password;
          printf("%d. Website: %s, Username: %s\n", count, password.website,
                 password.username);
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

void print_ascii_art(const char *filename) {
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    printf("Unable to open ASCII art file.\n");
    return;
  }

  // Get console width
  struct winsize w;
  ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
  int console_width = w.ws_col;

  char line[256];
  while (fgets(line, sizeof(line), file)) {
    // Calculate padding for centering
    int padding = (console_width - strlen(line)) / 2;
    if (padding > 0) {
      for (int i = 0; i < padding; i++) {
        printf(" ");
      }
    }
    printf("%s", line);
  }

  fclose(file);
}

int main() {
  initialize_log();

  const char *dir = "tmp"; // Directory to store password files
  mkdir(dir, 0700);        // Create directory if it doesn't exist

  char user_password[MAX_PASSWORD_LENGTH];

  FILE *key_file = fopen("master.key", "rb");
  if (key_file == NULL) {
    printf("Enter your new master password: ");
    fgets(user_password, sizeof(user_password), stdin);
    user_password[strcspn(user_password, "\n")] = 0;

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

  // Print ASCII art
  print_ascii_art("ascii-art.txt");

  int choice;
  while (1) {
    printf("\n1. Create New Password\n");
    printf("2. Show Passwords\n");
    printf("3. Exit\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);
    clear_input_buffer(); // Clear input buffer after scanf

    switch (choice) {
    case 1: {
      struct Password password;
      int length;
      do {
        printf("Enter password length: ");
        scanf("%d", &length);
        clear_input_buffer();
        if (length < 8 || length > MAX_PASSWORD_LENGTH - 1) {
          printf("Invalid password length. Please enter a length between 8 and "
                 "%d.\n",
                 MAX_PASSWORD_LENGTH - 1);
        }
      } while (length < 8 || length > MAX_PASSWORD_LENGTH - 1);
      generate_password(password.password, length);
      printf("Enter website: ");
      fgets(password.website, sizeof(password.website), stdin);
      password.website[strcspn(password.website, "\n")] =
          0; // Remove newline character
      printf("Enter username: ");
      fgets(password.username, sizeof(password.username), stdin);
      password.username[strcspn(password.username, "\n")] =
          0; // Remove newline character
      save_password(&password, password.website, dir, user_password);
      printf("Password information saved to %s\n", password.website);
      break;
    }
    case 2: {
      load_passwords(dir, user_password);
      printf("Enter the number of the password to copy (0 to cancel): ");
      int selection;
      scanf("%d", &selection);
      clear_input_buffer();
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
        clear_input_buffer();
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
      close_log();
      return 0;
    default:
      printf("Invalid choice. Please enter 1, 2, or 3.\n");
    }
  }

  close_log();
  return 0;
}
