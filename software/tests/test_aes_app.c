#include "aes_app.h"
#include <stdio.h>
#include <string.h>

int main() {
    int passed = 0, failed = 0;
    int key_len;
    uint8_t key[32];
    uint8_t plaintext[MAX_DATA_LEN];

    // Test 1: Valid 128-bit key and 16-byte plaintext
    memset(key, 'A', 16);
    memset(plaintext, 'B', 16);
    if (get_key_len_from_choice(0, &key_len) == AES_SUCCESS &&
        start_encryption(0, key, key_len, plaintext, 16) == AES_SUCCESS) {
        printf("Test 1 PASS\n"); passed++;
    }
    else {
        printf("Test 1 FAIL\n"); failed++;
    }

    // Test 2: Invalid key choice
    if (get_key_len_from_choice(5, &key_len) == AES_FAILURE) {
        printf("Test 2 PASS\n"); passed++;
    }
    else {
        printf("Test 2 FAIL\n"); failed++;
    }

    // Test 3: Key length mismatch
    memset(key, 'X', 8);
    if (start_encryption(0, key, 16, plaintext, 16) == AES_FAILURE) {
        printf("Test 3 PASS\n"); passed++;
    }
    else {
        printf("Test 3 FAIL\n"); failed++;
    }

    // Test 4: Plaintext not a multiple of 16
    memset(key, 'A', 16);
    memset(plaintext, 'B', 15);
    if (start_encryption(0, key, 16, plaintext, 15) == AES_FAILURE) {
        printf("Test 4 PASS\n"); passed++;
    }
    else {
        printf("Test 4 FAIL\n"); failed++;
    }

    // Test 5: 256-bit key and max length plaintext
    memset(key, 'C', 32);
    memset(plaintext, 'D', MAX_DATA_LEN);
    if (get_key_len_from_choice(2, &key_len) == AES_SUCCESS &&
        start_encryption(2, key, key_len, plaintext, MAX_DATA_LEN) == AES_SUCCESS) {
        printf("Test 5 PASS\n"); passed++;
    }
    else {
        printf("Test 5 FAIL\n"); failed++;
    }

    printf("Summary: %d PASS, %d FAIL\n", passed, failed);
    return failed;
}
