#ifndef AES_APP_H
#define AES_APP_H

#include <fcntl.h>
#include <glob.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* This path is based on the `compatible` string in your driver. */
#define SYSFS_PATH_TEMPLATE "/sys/bus/platform/devices/*.AES_v1.0"

#define MAX_DATA_LEN 64 // 512 bits
#define BLOCK_SIZE 16   // 128 bits

#define COMP_STATE_FINISHED 2
#define DONE_SIGNAL 1

#define NUM_KEY_REG 8

/* success/failure macros */
#define AES_SUCCESS 0
#define AES_FAILURE 1

/* Function Prototypes */
void print_hex(const char *label, const uint8_t *data, int len);
int get_key_len_from_choice(int key_choice, int *out_key_len);
int start_encryption(int key_choice, const uint8_t *key, int key_len,
                     const uint8_t *plaintext, int data_len);

#endif // AES_APP_H