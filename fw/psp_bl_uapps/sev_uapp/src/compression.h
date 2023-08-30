// Copyright(C) 2016 Advanced Micro Devices, Inc. All rights reserved.

#ifndef COMPRESSION_H
#define COMPRESSION_H

#include <stddef.h>
#include <stdint.h>

/**
 * Compress into a zlib stream.
 *
 * NOTE: This will need to be implemented in firmware. the CCP does
 * not implement the compression side of the zlib algorithm.
 */
int compression_zlib_compress(const uint8_t *src, size_t src_length,
                              uint8_t *dst, size_t *dst_legnth);

/**
 * Decompress a zlib stream.
 */
int compression_zlib_decompress(const uint8_t *src, size_t src_length,
                                uint8_t *dst, size_t *dst_legnth);

#endif /* COMPRESSION_H */
