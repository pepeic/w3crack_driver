/*
 * Copyright 2023 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#define AES_KEY_TYPE
#define AES_SRC_TYPE __global
#define AES_DST_TYPE __global

#include "aes.hcl"

#define POLYVAL_SIZE   16

#define AES_GCMSIV_NONCE_SIZE 12
#define AES_GCMSIV_TAG_SIZE 16
#define AES_GCMSIV_MAX_PLAINTEXT_SIZE (1UL << 36)
#define AES_GCMSIV_MAX_AAD_SIZE (1UL << 36)

#define KEY_AUTH_SIZE 16
#define KEY_ENC_MAX_SIZE 32

#define GET_UINT32_LE(n, b, i) \
	do { \
		(n) = (((uint32_t)(b)[(i) + 0]) << 0) | (((uint32_t)(b)[(i) + 1]) << 8) | \
			(((uint32_t)(b)[(i) + 2]) << 16) | (((uint32_t)(b)[(i) + 3]) << 24); \
	} while (0)

#define PUT_UINT32_LE(n, b, i) \
	do { \
		(b)[(i) + 0] = (uint8_t)((n) >> 0); \
		(b)[(i) + 1] = (uint8_t)((n) >> 8); \
		(b)[(i) + 2] = (uint8_t)((n) >> 16); \
		(b)[(i) + 3] = (uint8_t)((n) >> 24); \
	} while (0)

#define GET_UINT64_LE(n, b, i) \
	do { \
		(n) = (((uint64_t)(b)[(i) + 0]) << 0) | (((uint64_t)(b)[(i) + 1]) << 8) | \
			(((uint64_t)(b)[(i) + 2]) << 16) | (((uint64_t)(b)[(i) + 3]) << 24) | \
			(((uint64_t)(b)[(i) + 4]) << 32) | (((uint64_t)(b)[(i) + 5]) << 40) | \
			(((uint64_t)(b)[(i) + 6]) << 48) | (((uint64_t)(b)[(i) + 7]) << 56); \
	} while (0)

#define PUT_UINT64_LE(n, b, i) \
	do \
	{ \
		(b)[(i) + 0] = (uint8_t)((n) >> 0);  \
		(b)[(i) + 1] = (uint8_t)((n) >> 8);  \
		(b)[(i) + 2] = (uint8_t)((n) >> 16); \
		(b)[(i) + 3] = (uint8_t)((n) >> 24); \
		(b)[(i) + 4] = (uint8_t)((n) >> 32); \
		(b)[(i) + 5] = (uint8_t)((n) >> 40); \
		(b)[(i) + 6] = (uint8_t)((n) >> 48); \
		(b)[(i) + 7] = (uint8_t)((n) >> 56); \
	} while (0)

typedef struct polyval_generic
{
	uint8_t S[POLYVAL_SIZE];
	uint64_t HL[16];
	uint64_t HH[16];
} POLYVAL_CTX;

// 0, P(X), P(X)*X, P(X)*X^2, ...
__constant uint64_t PL[16] =
{
	0x0000000000000000UL, 0x0000000000000001UL, 0x0000000000000003UL,
	0x0000000000000002UL, 0x0000000000000006UL, 0x0000000000000007UL,
	0x0000000000000005UL, 0x0000000000000004UL, 0x000000000000000dUL,
	0x000000000000000cUL, 0x000000000000000eUL, 0x000000000000000fUL,
	0x000000000000000bUL, 0x000000000000000aUL, 0x0000000000000008UL,
	0x0000000000000009UL
};

__constant uint64_t PH[16] =
{
	0x0000000000000000UL, 0xc200000000000000UL, 0x4600000000000000UL,
	0x8400000000000000UL, 0x8c00000000000000UL, 0x4e00000000000000UL,
	0xca00000000000000UL, 0x0800000000000000UL, 0xda00000000000000UL,
	0x1800000000000000UL, 0x9c00000000000000UL, 0x5e00000000000000UL,
	0x5600000000000000UL, 0x9400000000000000UL, 0x1000000000000000UL,
	0xd200000000000000UL
};

// 0, X^-128, X^-127, X^-126, ...
__constant uint64_t XL[16] =
{
	0x0000000000000000UL, 0x0000000000000001UL, 0x0000000000000003UL,
	0x0000000000000002UL, 0x0000000000000007UL, 0x0000000000000006UL,
	0x0000000000000004UL, 0x0000000000000005UL, 0x000000000000000eUL,
	0x000000000000000fUL, 0x000000000000000dUL, 0x000000000000000cUL,
	0x0000000000000009UL, 0x0000000000000008UL, 0x000000000000000aUL,
	0x000000000000000bUL
};

__constant uint64_t XH[16] =
{
	0x0000000000000000UL, 0x9204000000000000UL, 0xe608000000000000UL,
	0x740c000000000000UL, 0x0e10000000000000UL, 0x9c14000000000000UL,
	0xe818000000000000UL, 0x7a1c000000000000UL, 0x1c20000000000000UL,
	0x8e24000000000000UL, 0xfa28000000000000UL, 0x682c000000000000UL,
	0x1230000000000000UL, 0x8034000000000000UL, 0xf438000000000000UL,
	0x663c000000000000UL
};

typedef struct dot_context
{
	uint64_t hl;
	uint64_t hh;
	uint64_t lo;
	uint64_t hi;
	uint8_t rem;
} DOTCTX;

typedef enum aes_gcmsiv_status
{
	AES_GCMSIV_SUCCESS = 0, //< Success.
	AES_GCMSIV_FAILURE = -1, //< Unknown failure.
	AES_GCMSIV_INVALID_TAG = -2, //< Authentication tag cannot match provided data.
} aes_gcmsiv_status_t;

typedef struct key_ctx
{
	uint8_t auth[KEY_AUTH_SIZE];
	size_t auth_sz;
	uint8_t enc[KEY_ENC_MAX_SIZE];
	size_t enc_sz;
} KEY_CTX;

static inline void dot_cc(DOTCTX *dot, const uint8_t *a, __constant const uint64_t bl[16], __constant const uint64_t bh[16])
{
	dot->hl = 0;
	dot->hh = 0;

#pragma unroll
	for (size_t i = 0; i < POLYVAL_SIZE; ++i)
	{
		dot->hi = (a[POLYVAL_SIZE - i - 1] >> 4) & 0x0f;
		dot->lo = (a[POLYVAL_SIZE - i - 1] >> 0) & 0x0f;

		dot->rem = (dot->hh >> 60) & 0x0f;
		dot->hh = ((dot->hh << 4) | (dot->hl >> 60)) ^ PH[dot->rem] ^ bh[dot->hi];
		dot->hl = (dot->hl << 4) ^ PL[dot->rem] ^ bl[dot->hi];

		dot->rem = (dot->hh >> 60) & 0x0f;
		dot->hh = ((dot->hh << 4) | (dot->hl >> 60)) ^ PH[dot->rem] ^ bh[dot->lo];
		dot->hl = (dot->hl << 4) ^ PL[dot->rem] ^ bl[dot->lo];
	}
}

static inline void dot_pp(DOTCTX *dot, const uint8_t *a, const uint64_t bl[16], const uint64_t bh[16])
{
	dot->hl = 0;
	dot->hh = 0;

#pragma unroll
	for (size_t i = 0; i < POLYVAL_SIZE; ++i)
	{
		dot->hi = (a[POLYVAL_SIZE - i - 1] >> 4) & 0x0f;
		dot->lo = (a[POLYVAL_SIZE - i - 1] >> 0) & 0x0f;

		dot->rem = (dot->hh >> 60) & 0x0f;
		dot->hh = ((dot->hh << 4) | (dot->hl >> 60)) ^ PH[dot->rem] ^ bh[dot->hi];
		dot->hl = (dot->hl << 4) ^ PL[dot->rem] ^ bl[dot->hi];

		dot->rem = (dot->hh >> 60) & 0x0f;
		dot->hh = ((dot->hh << 4) | (dot->hl >> 60)) ^ PH[dot->rem] ^ bh[dot->lo];
		dot->hl = (dot->hl << 4) ^ PL[dot->rem] ^ bl[dot->lo];
	}
}

static inline aes_gcmsiv_status_t polyval_start(POLYVAL_CTX *ctx, const uint8_t *key, size_t key_sz)
{
	DOTCTX dot_ctx;

	//Compute H * X^-128
	dot_cc(&dot_ctx, key, XL, XH);

	//Compute table
	ctx->HL[0] = 0;
	ctx->HH[0] = 0;

	ctx->HL[1] = dot_ctx.hl;
	ctx->HH[1] = dot_ctx.hh;

	//Compute HX, HX^2, HX^3
#pragma unroll
	for (size_t i = 2; i < 16; i *= 2)
	{
		dot_ctx.rem = (dot_ctx.hh >> 63) & 0x01;
		dot_ctx.hh = (dot_ctx.hh << 1) ^ (dot_ctx.hl >> 63) ^ PH[dot_ctx.rem];
		dot_ctx.hl = (dot_ctx.hl << 1) ^ PL[dot_ctx.rem];

		ctx->HL[i] = dot_ctx.hl;
		ctx->HH[i] = dot_ctx.hh;

		//Compute HX + H, HX^2 + H, HX^2 + HX, ...
		for (size_t j = 1; j < i; ++j)
		{
			ctx->HL[i + j] = dot_ctx.hl ^ ctx->HL[j];
			ctx->HH[i + j] = dot_ctx.hh ^ ctx->HH[j];
		}
	}

	return AES_GCMSIV_SUCCESS;
}

static inline aes_gcmsiv_status_t polyval_update_c(POLYVAL_CTX *ctx, __constant const uint8_t *data, size_t data_sz)
{
	DOTCTX dot_ctx;

	while (data_sz >= POLYVAL_SIZE)
	{
		//Compute S_{j-1} xor X_j
#pragma unroll
		for (size_t i = 0; i < POLYVAL_SIZE; ++i)
			ctx->S[i] = ctx->S[i] ^ data[i];

		//Compute S_j = (S_{j-1} xor  X_j) * H * X^-128
		dot_pp(&dot_ctx, ctx->S, ctx->HL, ctx->HH);

		//Update tag
		PUT_UINT64_LE(dot_ctx.hl, ctx->S, 0);
		PUT_UINT64_LE(dot_ctx.hh, ctx->S, 8);

		data += POLYVAL_SIZE;
		data_sz -= POLYVAL_SIZE;
	}

	if (data_sz > 0)
	{
		//Compute S_{j-1} xor X_j
		for (size_t i = 0; i < data_sz; ++i)
			ctx->S[i] = ctx->S[i] ^ data[i];

		//Compute S_j = (S_{j-1} xor  X_j) * H * X^-128
		dot_pp(&dot_ctx, ctx->S, ctx->HL, ctx->HH);

		//Update tag
		PUT_UINT64_LE(dot_ctx.hl, ctx->S, 0);
		PUT_UINT64_LE(dot_ctx.hh, ctx->S, 8);
	}

	return AES_GCMSIV_SUCCESS;
}

static inline aes_gcmsiv_status_t polyval_update_g(POLYVAL_CTX *ctx, __global const uint8_t *data, size_t data_sz)
{
	DOTCTX dot_ctx;

	while (data_sz >= POLYVAL_SIZE)
	{
		//Compute S_{j-1} xor X_j
#pragma unroll
		for (size_t i = 0; i < POLYVAL_SIZE; ++i)
			ctx->S[i] = ctx->S[i] ^ data[i];

		//Compute S_j = (S_{j-1} xor  X_j) * H * X^-128
		dot_pp(&dot_ctx, ctx->S, ctx->HL, ctx->HH);

		//Update tag
		PUT_UINT64_LE(dot_ctx.hl, ctx->S, 0);
		PUT_UINT64_LE(dot_ctx.hh, ctx->S, 8);

		data += POLYVAL_SIZE;
		data_sz -= POLYVAL_SIZE;
	}

	if (data_sz > 0)
	{
		//Compute S_{j-1} xor X_j
		for (size_t i = 0; i < data_sz; ++i)
			ctx->S[i] = ctx->S[i] ^ data[i];

		//Compute S_j = (S_{j-1} xor  X_j) * H * X^-128
		dot_pp(&dot_ctx, ctx->S, ctx->HL, ctx->HH);

		//Update tag
		PUT_UINT64_LE(dot_ctx.hl, ctx->S, 0);
		PUT_UINT64_LE(dot_ctx.hh, ctx->S, 8);
	}

	return AES_GCMSIV_SUCCESS;
}

static inline aes_gcmsiv_status_t polyval_update_p(POLYVAL_CTX *ctx, const uint8_t *data, size_t data_sz)
{
	DOTCTX dot_ctx;

	while (data_sz >= POLYVAL_SIZE)
	{
		//Compute S_{j-1} xor X_j
#pragma unroll
		for (size_t i = 0; i < POLYVAL_SIZE; ++i)
			ctx->S[i] = ctx->S[i] ^ data[i];

		//Compute S_j = (S_{j-1} xor  X_j) * H * X^-128
		dot_pp(&dot_ctx, ctx->S, ctx->HL, ctx->HH);

		//Update tag
		PUT_UINT64_LE(dot_ctx.hl, ctx->S, 0);
		PUT_UINT64_LE(dot_ctx.hh, ctx->S, 8);

		data += POLYVAL_SIZE;
		data_sz -= POLYVAL_SIZE;
	}

	if (data_sz > 0)
	{
		//Compute S_{j-1} xor X_j
		for (size_t i = 0; i < data_sz; ++i)
			ctx->S[i] = ctx->S[i] ^ data[i];

		//Compute S_j = (S_{j-1} xor  X_j) * H * X^-128
		dot_pp(&dot_ctx, ctx->S, ctx->HL, ctx->HH);

		//Update tag
		PUT_UINT64_LE(dot_ctx.hl, ctx->S, 0);
		PUT_UINT64_LE(dot_ctx.hh, ctx->S, 8);
	}

	return AES_GCMSIV_SUCCESS;
}

static inline aes_gcmsiv_status_t polyval_finish(POLYVAL_CTX *ctx, __constant const uint8_t *nonce, size_t nonce_sz, uint8_t tag[POLYVAL_SIZE])
{
	for (size_t i = 0; i < nonce_sz; ++i)
		tag[i] = ctx->S[i] ^ nonce[i];

#pragma unroll
	for (size_t i = nonce_sz; i < POLYVAL_SIZE; ++i)
		tag[i] = ctx->S[i];

	return AES_GCMSIV_SUCCESS;
}

static inline void aes_gcmsiv_derive_keys(AES_CTX *ctx, size_t key_sz, __constant const uint8_t *nonce, KEY_CTX *key)
{
	struct
	{
		uint8_t input[AES_BLOCK_SIZE];
		uint8_t output[AES_BLOCK_SIZE];
	} stack;

	//Set keys size
	key->auth_sz = KEY_AUTH_SIZE;
	key->enc_sz = key_sz;

	//Set nonce on the second part of the input block
	memcpy_macro(stack.input + sizeof(uint32_t), nonce, AES_GCMSIV_NONCE_SIZE);

	//Derive message authentication key
	PUT_UINT32_LE(0, stack.input, 0);
	AES_Encrypt_ECB_pp(ctx, stack.input, stack.output, 1);
	memcpy_macro(key->auth, stack.output, 8);

	PUT_UINT32_LE(1, stack.input, 0);
	AES_Encrypt_ECB_pp(ctx, stack.input, stack.output, 1);
	memcpy_macro(key->auth + 8, stack.output, 8);

	//Derive message encryption key
	PUT_UINT32_LE(2, stack.input, 0);
	AES_Encrypt_ECB_pp(ctx, stack.input, stack.output, 1);
	memcpy_macro(key->enc, stack.output, 8);

	PUT_UINT32_LE(3, stack.input, 0);
	AES_Encrypt_ECB_pp(ctx, stack.input, stack.output, 1);
	memcpy_macro(key->enc + 8, stack.output, 8);

	//Finish if AES-128
	if (16 == key_sz)
		return;

	//Continue if AES-256
	PUT_UINT32_LE(4, stack.input, 0);
	AES_Encrypt_ECB_pp(ctx, stack.input, stack.output, 1);
	memcpy_macro(key->enc + 16, stack.output, 8);

	PUT_UINT32_LE(5, stack.input, 0);
	AES_Encrypt_ECB_pp(ctx, stack.input, stack.output, 1);
	memcpy_macro(key->enc + 24, stack.output, 8);
}

static inline void aes_gcmsiv_make_tag(const KEY_CTX *key, __constant const uint8_t *nonce, __global const uint8_t *plain, size_t plain_sz, __constant const uint8_t *aad, size_t aad_sz, uint8_t *tag)
{
	POLYVAL_CTX polyval;
	uint64_t aad_bit_sz;
	uint64_t plain_bit_sz;
	uint8_t length_block[AES_GCMSIV_TAG_SIZE];

	AES_CTX aes;
	memset_macro((uint8_t *)&polyval, 0, sizeof(polyval));

	AES_Setkey(&aes, key->enc, key->enc_sz);

	//Create length block
	aad_bit_sz = ((uint64_t)aad_sz) * 8;
	PUT_UINT64_LE(aad_bit_sz, length_block, 0);

	plain_bit_sz = ((uint64_t)plain_sz) * 8;
	PUT_UINT64_LE(plain_bit_sz, length_block, 8);

	//Generate lookup tables for fast multiplication
	polyval_start(&polyval, key->auth, key->auth_sz);

	//Compute Polyval
	polyval_update_c(&polyval, aad, aad_sz);
	polyval_update_g(&polyval, plain, plain_sz);
	polyval_update_p(&polyval, length_block, sizeof(length_block));

	//Xor result and nonce
	polyval_finish(&polyval, nonce, AES_GCMSIV_NONCE_SIZE, tag);
	tag[15] &= 0x7f;

	//Encrypt result to produce tag
	AES_Encrypt_ECB_pp(&aes, tag, tag, 1);
}

static inline aes_gcmsiv_status_t aes_ctr(AES_CTX *ctx, const uint8_t nonce[AES_BLOCK_SIZE], __global const uint8_t *input, size_t input_sz, __global uint8_t *output)
{
	uint8_t counter_block[AES_BLOCK_SIZE];
	uint32_t counter;
	uint8_t key_stream[AES_BLOCK_SIZE];

	memcpy_macro(counter_block, nonce, sizeof(counter_block));
	GET_UINT32_LE(counter, counter_block, 0);

	while (input_sz >= AES_BLOCK_SIZE)
	{
		AES_Encrypt_ECB_pp(ctx, counter_block, key_stream, 1);

		//Increment counter with wrapping
		counter += 1;
		PUT_UINT32_LE(counter, counter_block, 0);

#pragma unroll
		for (size_t i = 0; i < AES_BLOCK_SIZE; ++i)
			output[i] = input[i] ^ key_stream[i];

		input += AES_BLOCK_SIZE;
		output += AES_BLOCK_SIZE;
		input_sz -= AES_BLOCK_SIZE;
	}

	if (input_sz > 0)
	{
		AES_Encrypt_ECB_pp(ctx, counter_block, key_stream, 1);

		//Increment counter with wrapping
		counter += 1;
		PUT_UINT32_LE(counter, counter_block, 0);

		for (size_t i = 0; i < input_sz; ++i)
			output[i] = input[i] ^ key_stream[i];
	}

	return AES_GCMSIV_SUCCESS;
}

static inline void aes_gcmsiv_aes_ctr(const uint8_t *key, size_t key_sz, __constant const uint8_t tag[AES_GCMSIV_TAG_SIZE], __global const uint8_t *input, size_t input_sz, __global uint8_t *output)
{
	AES_CTX ctx;
	uint8_t nonce[AES_BLOCK_SIZE];
	AES_Setkey(&ctx, key, key_sz);
	memcpy_macro(nonce, tag, sizeof(nonce));
	nonce[sizeof(nonce) - 1] |= 0x80;
	aes_ctr(&ctx, nonce, input, input_sz, output);
}

static inline aes_gcmsiv_status_t aes_gcmsiv_check_tag(const uint8_t lhs[AES_GCMSIV_TAG_SIZE], __constant const uint8_t rhs[AES_GCMSIV_TAG_SIZE])
{
	uint8_t sum = 0;
#pragma unroll
	for (size_t i = 0; i < AES_GCMSIV_TAG_SIZE; ++i)
		sum |= lhs[i] ^ rhs[i];
	return 0 == sum ? AES_GCMSIV_SUCCESS : AES_GCMSIV_INVALID_TAG;
}

__kernel void aes_gcmsiv_decrypt_and_check(__constant const AES_GCM_KEY *key, __constant const AES_SIV *nonce, __constant const AES_GCM_TAG * expected_tag, __constant const AES_AEAD * aad, __global uint8_t * ciphertext, uint cipher_len, __global int * result)
{
	uint idx = get_global_id(0);
	aes_gcmsiv_status_t res;
	KEY_CTX keyctx;
	AES_CTX ctx;
	uint8_t keycopy[32];
	uint keylen = key[idx].key_len;
	__global uint8_t * ctext = ciphertext + (cipher_len * idx);

	memcpy_macro(keycopy, key[idx].key, keylen);

	AES_Setkey(&ctx, keycopy, keylen);
	uint8_t tag[AES_GCMSIV_TAG_SIZE];

	//We need to decrypt the cipher text in order to verify it, we gonna decrypt it in place
	aes_gcmsiv_derive_keys(&ctx, keylen, nonce->iv, &keyctx);
	aes_gcmsiv_aes_ctr(keyctx.enc, keyctx.enc_sz, expected_tag->tag, ctext, cipher_len, ctext);
	aes_gcmsiv_make_tag(&keyctx, nonce->iv, ctext, cipher_len, aad->aead, aad->aead_len, tag);

	//Compare actual tag and expected tag, and nullify plaintext if there is a corruption
	res = aes_gcmsiv_check_tag(tag, expected_tag->tag);
	if (AES_GCMSIV_SUCCESS != res)
	{
		result[idx] = (int) res;
		return;
	}

	result[idx] = (int) AES_GCMSIV_SUCCESS;
}