#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/wait.h>

#define BLOCK_SIZE 16 // AES block size
#define SHA256_DIGEST_LENGTH 32 // SHA-256 Digest Length
#define min(a, b) ((a) < (b) ? (a) : (b))


// Declaration before usage
char* trim_whitespace(char *str);
void handle_encryption_or_decryption(int choice, const unsigned char *key);
void handle_errors(const char* context);
void list_files(const char *path);
int encrypt_file(const char *input_filename, const char *output_filename, const unsigned char *key, int keylen);
int decrypt_file(const char *input_filename, const char *output_filename, const unsigned char *key, int keylen);

int main(int argc, char *argv[]) {
    printf("\033[0;32m-----Welcome to use the file encryption-----\033[0m\n");

    char current_path[1024];
    if (getcwd(current_path, sizeof(current_path)) == NULL) {
        perror("Failed to get current directory");
        return 1;
    }

    // Adjusted key for AES-256
    unsigned char key[32];
    SHA256((unsigned char *)argv[3], strlen(argv[3]), key);

    printf("Files in the current directory:\n");
    list_files(current_path);

    int choice;
    do {
        printf("\nPlease enter your operation choice:\n");
        printf("1. Encrypt\n");
        printf("2. Decrypt\n");
        printf("3. Quit\n");

        // Check if the input is a valid integer
        if (scanf("%d", &choice) != 1) {
            printf("\033[0;31mInvalid input. Please enter a number.\033[0m\n");
            while (getchar() != '\n'); // Clear the input buffer
            continue; // Restart the loop to prompt for input again
        }

        // Handle different choices
        switch (choice) {
            case 1:
            case 2:
                handle_encryption_or_decryption(choice, key); // Pass 'key' as an argument
                break;
            case 3:
                printf("Exiting...\n");
                break;
            default:
                printf("\033[0;31mInvalid choice. Please enter 1, 2, or 3.\033[0m\n");
                break;
        }

        // Display updated file list
        printf("Updated files in the current directory:\n");
        list_files(current_path);
        printf("\n");
    } while (choice != 3);

    return 0;
}

#include <sys/wait.h>
void handle_encryption_or_decryption(int choice, const unsigned char *key) {
    printf("Enter file name(s) to operate on (separated by comma): ");
    char input_filenames[1024];
    fgets(input_filenames, sizeof(input_filenames), stdin); // Using fgets instead of scanf
    if (input_filenames[0] == '\n') {
        fgets(input_filenames, sizeof(input_filenames), stdin);
    }
    input_filenames[strcspn(input_filenames, "\n")] = 0; // Remove any trailing newline character
    char *input_file = strtok(input_filenames, ",");
    pid_t pid;
    int status;

    while (input_file) {
        input_file = trim_whitespace(input_file); // Ensure we trim whitespace for accurate file handling
        if (choice == 1) { // Encrypt
            pid = fork(); // Create a new process
            if (pid == 0) { // Child process
                // In child process
                char output_filename[1024] = {0};
                sprintf(output_filename, "%s.enc", input_file); // Prepare output filename
                if (encrypt_file(input_file, output_filename, key, 32) != 0) {
                    fprintf(stderr, "Failed to encrypt file: %s\n", input_file);
                }
                exit(0); // Exit child process after task is complete
            } else if (pid < 0) {
                // Fork failed
                fprintf(stderr, "Failed to fork for file: %s\n", input_idile);
            }
            // Parent process does nothing here and goes back to create another child for the next file
        }
        input_file = strtok(NULL, ",");
    }

    // Parent process waits for all child processes to complete
    while ((pid = waitpid(-1, &status, 0)) > 0) {
        if (WIFEXITED(status)) {
            // Check if child exited normally
            printf("Child %d terminated with status: %d\n", pid, WEXITSTATUS(status));
        }
    }
}

char* trim_whitespace(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) { // All spaces?
        return str;
    }

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // Write new null terminator character
    end[1] = '\0';

    return str;
}

void list_files(const char *path) {
    DIR *dir;
    struct dirent *entry;
    int file_number = 1;
    dir = opendir(path);
    if (!dir) {
        perror("Failed to open directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            printf("%d. %s\n", file_number++, entry->d_name);
        }
    }
    closedir(dir);
}

void handle_errors(const char* context) {
    fprintf(stderr, "\033[0;31mError occurred during %s:\033[0m\n", context);
    ERR_print_errors_fp(stderr);
    ERR_clear_error();
}

// keylen = key length
int encrypt_file(const char *input_filename, const char *output_filename, const unsigned char *key, int keylen) {
    int out_len, final_len, bytes_read;
    FILE *infile = fopen(input_filename, "rb");
    FILE *outfile = fopen(output_filename, "wb");
    // if file can't open
    if (!infile || !outfile) {
        if (infile) fclose(infile);
        if (outfile) fclose(outfile);
        perror("Failed to open files");
        return 1;
    }

    unsigned char iv[BLOCK_SIZE];
    // Generate a random IV
    if (!RAND_bytes(iv, sizeof(iv))) {
        handle_errors("IV generation");
        fclose(infile);
        fclose(outfile);
        return 1;
    }
    // Write IV to the output file
    fwrite(iv, 1, sizeof(iv), outfile);

    // Initialize hash context for data integrity check
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx;
    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        handle_errors("Failed to create EVP_MD_CTX");
        fclose(infile);
        fclose(outfile);
        return 1;
    }
    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        handle_errors("Failed to initialize digest");
        fclose(infile);
        fclose(outfile);
        return 1;
    }

    // encrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_errors("Cipher context creation");
        fclose(infile);
        fclose(outfile);
        return 1;
    }
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv)) {
        handle_errors("Encrypt init");
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return 1;
    }

    unsigned char inbuf[BLOCK_SIZE], outbuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    while ((bytes_read = fread(inbuf, 1, BLOCK_SIZE, infile)) > 0) {
        // Update hash with plaintext
        if(1 != EVP_DigestUpdate(mdctx, inbuf, bytes_read)) {
            handle_errors("Failed to update digest");
            fclose(infile);
            fclose(outfile);
            return 1;
        }

        if (!EVP_EncryptUpdate(ctx, outbuf, &out_len, inbuf, bytes_read)) {
            handle_errors("Encrypt update");
            EVP_CIPHER_CTX_free(ctx);
            fclose(infile);
            fclose(outfile);
            return 1;
        }
        fwrite(outbuf, 1, out_len, outfile);
    }

    if (!EVP_EncryptFinal_ex(ctx, outbuf + out_len, &final_len)) {
        handle_errors("Encrypt final");
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return 1;
    }
    fwrite(outbuf + out_len, 1, final_len, outfile);

    // Finalize hash and write to the output file
    if(1 != EVP_DigestFinal_ex(mdctx, hash, NULL)) {
        handle_errors("Failed to finalize digest");
        fclose(infile);
        fclose(outfile);
        return 1;
    }
    fwrite(hash, 1, SHA256_DIGEST_LENGTH, outfile);  // Append hash at the end of file

    EVP_CIPHER_CTX_free(ctx);
    EVP_MD_CTX_free(mdctx);
    fclose(infile);
    fclose(outfile);
    return 0;
}

int decrypt_file(const char *input_filename, const char *output_filename, const unsigned char *key, int keylen) {
    int out_len, final_len, bytes_read;
    FILE *infile = fopen(input_filename, "rb");
    FILE *outfile = fopen(output_filename, "wb");
    if (!infile || !outfile) {
        if (infile) fclose(infile);
        if (outfile) fclose(outfile);
        perror("Failed to open files");
        return 1;
    }

    unsigned char iv[BLOCK_SIZE];
    fread(iv, 1, sizeof(iv), infile);  // Read the IV from the start of the file

    // decrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_errors("Cipher context creation");
        fclose(infile);
        fclose(outfile);
        return 1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cfb(), NULL, key, iv)) {
        handle_errors("Decrypt init");
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return 1;
    }

    unsigned char inbuf[BLOCK_SIZE], outbuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    fseek(infile, 0, SEEK_END); // Position to the end of the file
    long end_pos = ftell(infile) - SHA256_DIGEST_LENGTH; // Exclude the hash length from the end
    rewind(infile);
    fread(iv, 1, sizeof(iv), infile); // Re-read IV after rewinding

    // Decrypt data excluding the hash
    while (ftell(infile) < end_pos) {
        int to_read = min(BLOCK_SIZE, end_pos - ftell(infile));
        bytes_read = fread(inbuf, 1, to_read, infile);
        if (bytes_read > 0) {
            if (!EVP_DecryptUpdate(ctx, outbuf, &out_len, inbuf, bytes_read)) {
                handle_errors("Decrypt update");
                EVP_CIPHER_CTX_free(ctx);
                fclose(infile);
                fclose(outfile);
                return 1;
            }
            fwrite(outbuf, 1, out_len, outfile);
        }
    }

    if (!EVP_DecryptFinal_ex(ctx, outbuf + out_len, &final_len)) {
        handle_errors("Decrypt final");
        EVP_CIPHER_CTX_free(ctx);
        fclose(infile);
        fclose(outfile);
        return 1;
    }
    fwrite(outbuf + out_len, 1, final_len, outfile);

    fclose(infile);
    fclose(outfile);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}


