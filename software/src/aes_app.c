#define _DEFAULT_SOURCE
#include "aes_app.h"

char sysfs_device_path[256];

/**
 *  @brief: Helper function to find the dynamic sysfs path
    @param: None
    @result: Fail or success
*/
int find_sysfs_path(void) {
  glob_t glob_result;
  if (glob(SYSFS_PATH_TEMPLATE, 0, NULL, &glob_result) == 0 &&
      glob_result.gl_pathc > 0) {
    strncpy(sysfs_device_path, glob_result.gl_pathv[0],
            sizeof(sysfs_device_path) - 1);
    globfree(&glob_result);
    printf("INFO: Found AES device at: %s\n", sysfs_device_path);
    return AES_SUCCESS;
  }
  fprintf(stderr, "Unable to find AES device sysfs path matching '%s'.\n",
          SYSFS_PATH_TEMPLATE);
  return AES_FAILURE;
}

/**
 *  @brief: Helper function to write a value to a sysfs attribute
    @param: attr
    @param: value
    @result: Fail or success
*/
int write_to_sysfs(const char *attr, uint32_t value) {
  char path[512];
  snprintf(path, sizeof(path), "%s/%s", sysfs_device_path, attr);
  FILE *fp = fopen(path, "w");
  if (!fp) {
    fprintf(stderr, "ERROR: fopen failed for %s", path);
    perror(" ");
    return AES_FAILURE;
  }
  fprintf(fp, "%u", value);
  fclose(fp);
  return AES_SUCCESS;
}

/**
 *  @brief: Helper function to read a value from sysfs attribute
    @param: attr
    @param: value
    @result: Fail or success
*/
int read_from_sysfs(const char *attr, uint32_t *value) {
  char path[512];
  snprintf(path, sizeof(path), "%s/%s", sysfs_device_path, attr);
  FILE *fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr, "ERROR: fopen failed for %s", path);
    perror(" ");
    return AES_FAILURE;
  }
  if (fscanf(fp, "%u", value) != 1) {
    fprintf(stderr, "ERROR: Could not parse value from %s\n", path);
    fclose(fp);
    return AES_FAILURE;
  }
  fclose(fp);
  return AES_SUCCESS;
}

/**
 *  @brief: Function to get the key length from the key choice (in bytes)
    @param: key_choice
    @param: out_key_len
    @result: Fail or success
*/
int get_key_len_from_choice(int key_choice, int *out_key_len) {
  if (!out_key_len)
    return AES_FAILURE;

  switch (key_choice) {
  case 0:
    *out_key_len = 16;
    return AES_SUCCESS;
  case 1:
    *out_key_len = 24;
    return AES_SUCCESS;
  case 2:
    *out_key_len = 32;
    return AES_SUCCESS;
  default:
    fprintf(stderr, "Invalid key choice\n");
    return AES_FAILURE;
  }
}

/**
 *  @brief: Function to set the key choice, key, plain text data based on user
 input to start the encryption
    @param: choice
    @param: key
    @param: key_len
    @param: plaintext
    @param: data_len
    @result: Fail or success
*/
int start_encryption(int key_choice, const uint8_t *key, int key_len,
                     const uint8_t *plaintext, int data_len) {
  uint8_t final_ciphertext[MAX_DATA_LEN] = {0};
  int num_blocks = data_len / BLOCK_SIZE;

  /* Reset all key registers to zero and then load the new key */
  printf("[start_encryption] Resetting key registers and loading new key...\n");
  for (int i = 0; i < NUM_KEY_REG; i++) {
    char key_attr[20];
    snprintf(key_attr, sizeof(key_attr), "key%d", i);
    write_to_sysfs(key_attr, 0);
  }

  /* Storing the user input key into each of the key registers */
  /* Splitting the key len and loading into registers rest all are reset to 0 at
   * start*/
  for (int i = 0; i < key_len / 4; i++) {
    char key_attr[20];
    uint32_t key_val = 0;
    memcpy(&key_val, key + i * 4, 4);
    snprintf(key_attr, sizeof(key_attr), "key%d", i);
    write_to_sysfs(key_attr, key_val);
  }

  printf("[start_encryption] Setting key choice to %d-bit...\n",
         (128 + (64 * key_choice)));
  write_to_sysfs("aes_key_choice", key_choice);

  /* Repeat for all data */
  for (int i = 0; i < num_blocks; i++) {
    const uint8_t *pt_chunk = plaintext + (i * BLOCK_SIZE);
    uint8_t *ct_chunk = final_ciphertext + (i * BLOCK_SIZE);
    uint32_t comp_state = 0, done_signal = 0;

    printf("[start_encryption] Processing Block %d of %d \n", i + 1,
           num_blocks);
    print_hex("Plaintext Chunk:", pt_chunk, BLOCK_SIZE);

    /* Load plaintext chunk into registers */
    /* Splitting the 16 bytes pt_chunk into 4 blocks of 4 bytes(32 bits) and
     * loading into registers */
    for (int j = 0; j < 4; j++) {
      char pt_attr[20];
      uint32_t pt_val = 0;
      snprintf(pt_attr, sizeof(pt_attr), "plain_text%d", j);
      memcpy(&pt_val, pt_chunk + j * 4, 4);
      write_to_sysfs(pt_attr, pt_val);
    }

    /* Write enable */
    printf("[start_encryption] Writing to enable bit\n");
    write_to_sysfs("aes_enable", 1);

    /* Poll for finished signal */
    printf("[start_encryption] Polling for completion signal...");
    fflush(stdout);
    do {
      read_from_sysfs("comp_state", &comp_state);
      usleep(10000); // Poll for every 10ms
    } while (comp_state != COMP_STATE_FINISHED);
    printf("[start_encryption] Received FINISHED signal \n");

    /* Check done signal */
    read_from_sysfs("done", &done_signal);
    if (done_signal != DONE_SIGNAL) {
      fprintf(
          stderr,
          "ERROR: Encryption for block %d failed! DONE signal was not set.\n",
          i + 1);
      write_to_sysfs("aes_enable", 0); // reset the enable bit
      return AES_FAILURE;
    }
    printf("[start_encryption] DONE signal confirmed.\n");

    /* Read the ciphertext chunk */
    /* Splitting the 16 bytes ct_chunk into 4 blocks of 4 bytes(32 bits) and
     * loading into registers */
    for (int j = 0; j < 4; j++) {
      char ct_attr[20];
      uint32_t ct_val = 0;
      snprintf(ct_attr, sizeof(ct_attr), "cipher_text%d", j);
      if (read_from_sysfs(ct_attr, &ct_val) != AES_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to read cipher text %s\n", ct_attr);
        return AES_FAILURE;
      }
      memcpy(ct_chunk + j * 4, &ct_val, 4);
    }

    /* Cleanup for next loop */
    write_to_sysfs("aes_enable", 0); // reset the enable bit
  }

  /* Concatenate and print result */
  printf("\n[start_encryption] Encryption Completed Successfully\n");
  print_hex("Final Ciphertext:", final_ciphertext, data_len);
  return AES_SUCCESS;
}

/**
 *  @brief: Helper function to print hex data
    @param: label
    @param: data
    @param: len
    @result: None
*/
void print_hex(const char *label, const uint8_t *data, int len) {
  printf("%-20s", label);
  for (int i = 0; i < len; i++) {
    printf("%02X ", data[i]);
  }
  printf("\n");
}

int main(void) {
  if (find_sysfs_path() != AES_SUCCESS) {
    return EXIT_FAILURE;
  }
  int key_choice, key_len, data_len;
  uint8_t key[32] = {0};
  uint8_t plaintext[MAX_DATA_LEN] = {0};

  /* Take user input */
  printf("Select AES Key Size:\n 0. 128-bit)\n  1. 192-bit\n  2. "
         "256-bit\nEnter choice: ");
  if (scanf("%d", &key_choice) != 1)
    return EXIT_FAILURE;
  while (getchar() != '\n')
    ;

  if (get_key_len_from_choice(key_choice, &key_len) != AES_SUCCESS) {
    fprintf(stderr, "ERROR: Invalid key choice.\n");
    return EXIT_FAILURE;
  }

  printf("Enter plaintext data length in bytes (must be 16, 32, 48, or 64): ");
  if (scanf("%d", &data_len) != 1)
    return EXIT_FAILURE;
  while (getchar() != '\n')
    ;

  /* Reject if data length is invalid */
  if (data_len <= 0 || data_len > MAX_DATA_LEN || data_len % 16 != 0) {
    fprintf(stderr,
            "ERROR: Invalid length. Must be a multiple of 16, up to %d.\n",
            MAX_DATA_LEN);
    return EXIT_FAILURE;
  }

  printf("Enter a key of exactly %d characters: ", key_len);
  fgets((char *)key, key_len + 2, stdin);

  /* Reject key length mismatch */
  if ((strnlen((char *)key, key_len + 1)) != (size_t)key_len) {
    fprintf(
        stderr,
        "ERROR: Key length mismatch. Expected %d characters, but got %zu.\n",
        key_len, (size_t)strnlen((char *)key, key_len + 1));
    return EXIT_FAILURE;
  }

  printf("Enter a plaintext message of exactly %d bytes: ", data_len);
  fgets((char *)plaintext, data_len + 2, stdin);

  /* Reject data length mismatch */
  if ((strnlen((char *)plaintext, data_len + 1)) != (size_t)data_len) {
    fprintf(stderr,
            "ERROR: Plaintext length mismatch. Expected %d characters, but got "
            "%zu.\n",
            data_len, (size_t)strnlen((char *)plaintext, data_len + 1));
    return EXIT_FAILURE;
  }

  if (start_encryption(key_choice, key, key_len, plaintext, data_len) !=
      AES_SUCCESS) {
    fprintf(stderr, "ERROR: Encryption failed.\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}