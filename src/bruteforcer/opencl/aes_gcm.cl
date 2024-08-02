/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "aes.hcl"

#define AES_GET_BE32(byteptr) ((((uint)(byteptr)[0]) << 24) | (((uint)(byteptr)[1]) << 16) | (((uint)(byteptr)[2]) << 8) | (uint)(byteptr)[3])
#define AES_GET_BE64(byteptr) ((((ulong)(byteptr)[0]) << 56) | (((ulong)(byteptr)[1]) << 48) | \
								(((ulong)(byteptr)[2]) << 40) | (((ulong)(byteptr)[3]) << 32) | \
								(((ulong)(byteptr)[4]) << 24) | (((ulong)(byteptr)[5]) << 16) | \
								(((ulong)(byteptr)[6]) << 8) | ((ulong)(byteptr)[7]))

#define AES_PUT_BE32(byteptr,value) \
	do \
	{ \
		(byteptr)[0] = (value) >> 24; \
		(byteptr)[1] = (value) >> 16; \
		(byteptr)[2] = (value) >> 8; \
		(byteptr)[3] = (value) & 0xff; \
	} while (0)

#define AES_PUT_BE64(byteptr,value) \
	do \
	{ \
		(byteptr)[0] = (value) >> 56; \
		(byteptr)[1] = (value) >> 48; \
		(byteptr)[2] = (value) >> 40; \
		(byteptr)[3] = (value) >> 32; \
		(byteptr)[4] = (value) >> 24; \
		(byteptr)[5] = (value) >> 16; \
		(byteptr)[6] = (value) >> 8; \
		(byteptr)[7] = (value) & 0xff; \
	} while (0)

inline void aes_inc32(uchar *block)
{
	uint val;
	val = AES_GET_BE32(block + AES_BLOCK_SIZE - 4);
	val++;
	AES_PUT_BE32(block + AES_BLOCK_SIZE - 4, val);
}

inline void aes_xor_block_pp(uchar *dst, const uchar *src)
{
	uint *d = (uint *) dst;
	uint *s = (uint *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}

inline void aes_xor_block(__global uchar *dst, __constant const uchar *src)
{
	__global uint *d = (__global uint *) dst;
	__constant uint *s = (__constant uint *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}

inline void aes_xor_block_pg(uchar *dst, __constant const uchar *src)
{
	uint *d = (uint *) dst;
	__constant uint *s = (__constant uint *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}

inline void aes_xor_block_gp(__global uchar *dst, const uchar *src)
{
	__global uint *d = (__global uint *) dst;
	uint *s = (uint *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}

inline void aes_shift_right_block(uchar *v)
{
	uint val;

	val = AES_GET_BE32(v + 12);
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	AES_PUT_BE32(v + 12, val);

	val = AES_GET_BE32(v + 8);
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	AES_PUT_BE32(v + 8, val);

	val = AES_GET_BE32(v + 4);
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	AES_PUT_BE32(v + 4, val);

	val = AES_GET_BE32(v);
	val >>= 1;
	AES_PUT_BE32(v, val);
}

/* Multiplication in GF(2^128) */
inline void gcm_gf_mult(const uchar *x, const uchar *y, uchar *z)
{
	uchar v[16];
	int i, j;

	memset_macro(z, 0, 16); /* Z_0 = 0^128 */
	memcpy_macro(v, y, 16); /* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & 1 << (7 - j)) {
				/* Z_(i + 1) = Z_i XOR V_i */
				aes_xor_block_pp(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				aes_shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				aes_shift_right_block(v);
			}
		}
	}
}

inline void gcm_ghash_start(uchar *y)
{
	/* Y_0 = 0^128 */
	memset_macro(y, 0, 16);
}

inline void gcm_ghash(const uchar *h, __constant const uchar *x, size_t xlen, uchar *y)
{
	size_t m, i;
	__constant const uchar *xpos = x;
	uchar tmp[16];

	m = xlen / 16;

	for (i = 0; i < m; i++)
	{
		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		aes_xor_block_pg(y, xpos);
		xpos += 16;

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gcm_gf_mult(y, h, tmp);
		memcpy_macro(y, tmp, 16);
	}

	if (x + xlen > xpos)
	{
		/* Add zero padded last block */
		size_t last = x + xlen - xpos;
		memcpy_macro(tmp, xpos, last);
		memset_macro(tmp + last, 0, sizeof(tmp) - last);

		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		aes_xor_block_pp(y, tmp);

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gcm_gf_mult(y, h, tmp);
		memcpy_macro(y, tmp, 16);
	}

	/* Return Y_m */
}

inline void gcm_ghash_pp(const uchar *h, const uchar *x, size_t xlen, uchar *y)
{
	size_t m, i;
	const uchar *xpos = x;
	uchar tmp[16];

	m = xlen / 16;

	for (i = 0; i < m; i++)
	{
		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		aes_xor_block_pp(y, xpos);
		xpos += 16;

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gcm_gf_mult(y, h, tmp);
		memcpy_macro(y, tmp, 16);
	}

	if (x + xlen > xpos)
	{
		/* Add zero padded last block */
		size_t last = x + xlen - xpos;
		memcpy_macro(tmp, xpos, last);
		memset_macro(tmp + last, 0, sizeof(tmp) - last);

		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		aes_xor_block_pp(y, tmp);

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gcm_gf_mult(y, h, tmp);
		memcpy_macro(y, tmp, 16);
	}

	/* Return Y_m */
}

inline void aes_gctr(AES_CTX *aes, const uchar *icb, __constant uchar *x, size_t xlen, __global uchar *y)
{
	size_t i, n, last;
	uchar cb[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	__constant const uchar *xpos = x;
	__global uchar *ypos = y;

	if (xlen == 0)
		return;

	n = xlen / 16;

	memcpy_macro(cb, icb, AES_BLOCK_SIZE);
	/* Full blocks */
	for (i = 0; i < n; i++)
	{
		AES_Encrypt_ECB_pg(aes, cb, ypos, 1);
		aes_xor_block(ypos, xpos);
		xpos += AES_BLOCK_SIZE;
		ypos += AES_BLOCK_SIZE;
		aes_inc32(cb);
	}

	last = x + xlen - xpos;
	if (last)
	{
		/* Last, partial block */
		AES_Encrypt_ECB_pp(aes, cb, tmp, 1);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ tmp[i];
	}
}

inline void aes_gctr_pg(AES_CTX *aes, const uchar *icb, uchar *x, size_t xlen, __global uchar *y)
{
	size_t i, n, last;
	uchar cb[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	const uchar *xpos = x;
	__global uchar *ypos = y;

	if (xlen == 0)
		return;

	n = xlen / 16;

	memcpy_macro(cb, icb, AES_BLOCK_SIZE);
	/* Full blocks */
	for (i = 0; i < n; i++)
	{
		AES_Encrypt_ECB_pg(aes, cb, ypos, 1);
		aes_xor_block_gp(ypos, xpos);
		xpos += AES_BLOCK_SIZE;
		ypos += AES_BLOCK_SIZE;
		aes_inc32(cb);
	}

	last = x + xlen - xpos;
	if (last)
	{
		/* Last, partial block */
		AES_Encrypt_ECB_pp(aes, cb, tmp, 1);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ tmp[i];
	}
}

inline void aes_gctr_pp(AES_CTX *aes, const uchar *icb, uchar *x, size_t xlen, uchar *y)
{
	size_t i, n, last;
	uchar cb[AES_BLOCK_SIZE], tmp[AES_BLOCK_SIZE];
	const uchar *xpos = x;
	uchar *ypos = y;

	if (xlen == 0) return;

	n = xlen / 16;
	memcpy_macro(cb, icb, AES_BLOCK_SIZE);

	/* Full blocks */
	for (i = 0; i < n; i++)
	{
		AES_Encrypt_ECB_pp(aes, cb, ypos, 1);
		aes_xor_block_pp(ypos, xpos);
		xpos += AES_BLOCK_SIZE;
		ypos += AES_BLOCK_SIZE;
		aes_inc32(cb);
	}

	last = x + xlen - xpos;
	if (last)
	{
		/* Last, partial block */
		AES_Encrypt_ECB_pp(aes, cb, tmp, 1);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ tmp[i];
	}
}

inline int aes_gcm_init_hash_subkey(AES_CTX * ctx, __constant const uchar *key, size_t key_len, uchar *H)
{
	int result = AES_Setkey(ctx, key, key_len);
	if (result != 0) { return result; }

	/* Generate hash subkey H = AES_K(0^128) */
	memset_macro(H, 0, AES_BLOCK_SIZE);
	AES_Encrypt_ECB_pp(ctx, H, H, 1);
	return 0;
}

inline void aes_gcm_prepare_j0(__constant const uchar *iv, size_t iv_len, const uchar *H, uchar *J0)
{
	uchar len_buf[16];

	if (iv_len == 12)
	{
		/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
		memcpy_macro(J0, iv, iv_len);
		memset_macro(J0 + iv_len, 0, AES_BLOCK_SIZE - iv_len);
		J0[AES_BLOCK_SIZE - 1] = 0x01;
	}
	else
	{
		/*
		 * s = 128 * ceil(len(IV)/128) - len(IV)
		 * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		 */
		gcm_ghash_start(J0);
		gcm_ghash(H, iv, iv_len, J0);
		AES_PUT_BE64(len_buf, 0);
		AES_PUT_BE64(len_buf + 8, iv_len * 8);
		gcm_ghash_pp(H, len_buf, sizeof(len_buf), J0);
	}
}

inline void aes_gcm_gctr(AES_CTX *aes, const uchar *J0, __constant uchar *in, size_t len, __global uchar *out)
{
	uchar J0inc[AES_BLOCK_SIZE];

	if (len == 0)
		return;

	memcpy_macro(J0inc, J0, AES_BLOCK_SIZE);
	aes_inc32(J0inc);
	aes_gctr(aes, J0inc, in, len, out);
}

inline void aes_gcm_ghash(const uchar *H, __constant const uchar *aad, size_t aad_len,
			  __constant const uchar *crypt, size_t crypt_len, uchar *S)
{
	uchar len_buf[16];

	/*
	 * u = 128 * ceil[len(C)/128] - len(C)
	 * v = 128 * ceil[len(A)/128] - len(A)
	 * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	gcm_ghash_start(S);
	gcm_ghash(H, aad, aad_len, S);
	gcm_ghash(H, crypt, crypt_len, S);
	AES_PUT_BE64(len_buf, aad_len * 8);
	AES_PUT_BE64(len_buf + 8, crypt_len * 8);
	gcm_ghash_pp(H, len_buf, sizeof(len_buf), S);
}

__kernel void aes_gcm_compute_ghash(__constant const AES_GCM_KEY *key, __constant const AES_IV *iv,
		__constant const uchar *crypt, uint crypt_len,
		__constant const AES_AEAD *aead, __constant const AES_GCM_TAG *tag,
		__global int * res)
{
	uint idx = get_global_id(0);
	uchar H[AES_BLOCK_SIZE];
	uchar J0[AES_BLOCK_SIZE];
	uchar S[16], T[16];
	AES_CTX aes;

	int result = aes_gcm_init_hash_subkey(&aes, key[idx].key, key[idx].key_len, H);
	if (result != 0)
	{
		res[idx] = -1;
		return;
	}

	aes_gcm_prepare_j0(iv->iv, iv->iv_len, H, J0);
	aes_gcm_ghash(H, aead->aead, aead->aead_len, crypt, crypt_len, S);
	aes_gctr_pp(&aes, J0, S, sizeof(S), T);

	if (memcmp_pc(T, tag->tag, 16) != 0)
	{
		res[idx] = -2;
		return;
	}

	res[idx] = 0;
}