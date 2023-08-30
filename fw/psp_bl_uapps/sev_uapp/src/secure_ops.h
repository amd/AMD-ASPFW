// Copyright(C) 2017 Advanced Micro Devices, Inc. All rights reserved.

#ifndef SECURE_OPS_H
#define SECURE_OPS_H

/**
 * Constant-time implementation of memcmp(). Use this to validate security-
 * sensitive data.
 *
 * Returns 0 if left == right, 1 if left != right, 2 if error.
 */
int secure_compare(const void *left, const void *right, size_t size);

/**
 * Generic (and Little-Endian) implementation of BNSecureCompare.
 * Use this to validate security-sensitive data.
 * >> 8 because each element is uint8_t

 * Returns 0 if left == right, 1 if left > right, 2 if left < right.
 *
 * Example (returns 1 because the first element is larger):
 * const unsigned char b1[4] = {0, 51, 255, 200};
 * const unsigned char b2[4] = {55, 99, 0, 200};
 */
int secure_array_compare_le(const void *left, const void *right, size_t size);

/**
 * Zero security-sensitive data buffers. This implementation is resistant to
 * dead store elimination by the compiler.
 */
void secure_memzero(void *buffer, size_t size);

#endif /* SECURE_OPS_H */
