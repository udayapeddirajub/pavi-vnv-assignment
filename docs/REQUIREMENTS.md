---------------------------------------------------------------------------------------------------------------------------------
Requirement ID    Parent Req ID    Description
---------------------------------------------------------------------------------------------------------------------------------
SUBSYS-001        SYS-001          The subsystem shall implement a hardware accelerated AES core with a latency of <50 ns per encryption cycle.
SUBSYS-002        SYS-001          The subsystem shall support encryption with 128, 192, and 256 bit-length keys.
SUBSYS-003        SYS-001          The subsystem shall support encryption of plaintext that is always a multiple of 128 bits, up to 512 bits.
---------------------------------------------------------------------------------------------------------------------------------
Verification Mapping
---------------------------------------------------------------------------------------------------------------------------------
Test Bench / Unit Test Name        Type            Coverage Summary                                Implementation Notes                    Status
---------------------------------------------------------------------------------------------------------------------------------
AES_tb.v (aes128_nist)             RTL Test        Verifies 128-bit AES encryption correctness.    Compared ciphertext with NIST reference. PASS
AES_tb.v (aes192_nist)             RTL Test        Verifies 192-bit AES functionality and timing.  Data path correctness and done signal.  PASS
AES_tb.v (aes256_nist)             RTL Test        Verifies 256-bit AES key schedule and result.   Validated NIST reference ciphertext.    PASS
AES_tb.v (edge_disable)            RTL Test        Verifies behavior with enable not asserted.     Ensures no unintended start occurs.     PASS
test_aes_app.c (Test 1)            Unit Test       Valid 128-bit key, 16-byte plaintext test.      Checks key_len retrieval + encryption.  PASS
test_aes_app.c (Test 2)            Unit Test       Invalid key length selection.                   Handles 5 -> AES_FAILURE gracefully.    PASS
test_aes_app.c (Test 3)            Unit Test       Key length mismatch test.                       Detects inconsistency (returns FAIL).   PASS
test_aes_app.c (Test 4)            Unit Test       Plaintext not multiple of 16 bytes.             Validates input validation handling.    PASS
test_aes_app.c (Test 5)            Unit Test       256-bit key, full buffer plaintext.             Confirms AES_SUCCESS at boundary limit. PASS
---------------------------------------------------------------------------------------------------------------------------------
Requirement-wise Verification Summary
---------------------------------------------------------------------------------------------------------------------------------
Requirement ID    Verified By                                   Result   Comments
---------------------------------------------------------------------------------------------------------------------------------
SUBSYS-001        AES_tb.v (128,192,256)                        PASS     Measured <50ns latency / encryption verified at 100 MHz.
SUBSYS-002        AES_tb.v, test_aes_app.c (key choice tests)   PASS     All valid key sizes (128/192/256) passed functional test.
SUBSYS-003        AES_tb.v, test_aes_app.c (Test 4, Test 5)     PASS     128-bit aligned data verified; improper lengths rejected.
---------------------------------------------------------------------------------------------------------------------------------

Traceability Status: COMPLETE
All subsystem requirements are verified successfully through corresponding RTL and software test cases,
and CI automation ensures continuous checking upon each commit.
---------------------------------------------------------------------------------------------------------------------------------
