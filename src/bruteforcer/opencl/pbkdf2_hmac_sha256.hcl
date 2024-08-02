/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * Copyright (c) 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * cfg->skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 32). So to calculate only
 * byte 33-64 (second chunk) you can say "cfg->outlen=32 cfg->skip_bytes=32"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 32 as opposed to 64.
 */

#ifndef _OPENCL_PBKDF2_HMAC_SHA256_H
#define _OPENCL_PBKDF2_HMAC_SHA256_H

#ifndef HASH_LOOPS
#define HASH_LOOPS 923
#endif

#ifndef PLAINTEXT_LENGTH
#define PLAINTEXT_LENGTH 55
#endif

#include "misc.hcl"

//align everything to at least 4 bytes

#pragma pack(push)
#pragma pack(4)

typedef struct {
	uint32_t rounds;
	uint32_t skip_bytes;
	uint32_t outlen;
} config_t;

typedef struct {
	uint32_t length;
	uint8_t salt[1];
} salt_t;

typedef struct {
	uint32_t ipad[8];
	uint32_t opad[8];
	uint32_t hash[8];
	uint32_t W[8];
	uint32_t rounds;
	uint32_t pass;
} state_t;

typedef struct {
	uint32_t length;
	uint8_t v[PLAINTEXT_LENGTH];
} pass_t;

typedef struct {
	uint32_t hash[8];
} crack_t;

#pragma pack(pop)

#endif
