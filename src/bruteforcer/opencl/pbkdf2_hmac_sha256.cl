/*
 * This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
 * and Copyright 2014 - 2018 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Now unlimited salt length. (Dec 2017, JimF)
 *
 * skip_bytes means "skip leading output bytes" and can be given in
 * multiples of underlying hash size (in this case 32). So to calculate only
 * byte 33-64 (second chunk) you can say "outlen=32 skip_bytes=32"
 * for a 2x boost. The 1st byte of output array will then be 1st byte of second
 * chunk so its actual size can be 32 as opposed to 64.
 */

#include "device_info.hcl"
#include "misc.hcl"
#include "sha256.hcl"
#include "pbkdf2_hmac_sha256.hcl"

#if SALT_GLOBAL_CONST
#define SALT_MEMORY_TYPE __global const
#else
#define SALT_MEMORY_TYPE __constant
#endif

#if CFG_GLOBAL_CONST
#define CFG_MEMORY_TYPE __global const
#else
#define CFG_MEMORY_TYPE __constant
#endif

#if PLAINTEXT_LENGTH > 64
//outkey must be at least 64 bytes long
inline uint _phsk_key_precompute(__global const uchar * inkey, uint keylen, uchar * outkey)
{
	if (keylen <= 64)
	{
		memcpy_macro(outkey, inkey, keylen);
		return keylen;
	}

	uint i, j, last;
	uint W[16], ctx[8];
	ctx[0] = h[0];
	ctx[1] = h[1];
	ctx[2] = h[2];
	ctx[3] = h[3];
	ctx[4] = h[4];
	ctx[5] = h[5];
	ctx[6] = h[6];
	ctx[7] = h[7];

	i = 0;
	last = keylen;	//this the count of bytes of key put into the final buffer.
	while (i+64 <= keylen)
	{
		//no need to clean. We are using the entire 64 bytes with this block of key
		#pragma unroll
		for (j = 0; j < 64; ++j, ++i)
			PUTCHAR_BE(W, j, inkey[i]);
		last -= 64;
		sha256_block(W, ctx);
	}

	#pragma unroll
	for (j = 0; j < 16; j++)
		W[j] = 0;

	//assertion [i <= keylen < (i+64)], so all remaining key (if any) fits in this block
	for (j = 0; i < keylen; ++j, ++i)
		PUTCHAR_BE(W, j, inkey[i]);

	if (last <= 55)
	{
		PUTCHAR_BE(W, last, 0x80);
		W[15] = keylen << 3;
	}
	else
	{
		//Final limb (no key data put into this one)
		#pragma unroll
		for (j = 0; j < 15; j++)
			W[j] = 0;
		
		if (last >= 64)
			PUTCHAR_BE(W, last - 64, 0x80);
		W[15] = keylen << 3;
	}

	//this is sha256_final for our password.
	sha256_block(W, ctx);
	
	#pragma unroll
	for (j = 0; j < 32; j += 4)
		PUT_UINT32BE(ctx[j >> 2], outkey, j);

	//yes this is not an error, block size of sha256 equals to 64, but digest len to 32
	//we select min of block size and digest len (which is 32 in our case) and use it as a key
	//the actual key size is still 64 bytes and so we will use the whole 64 bytes
	//the key already pre-nullified so it is okay to copy only the part of it and pass it as 32-byte sized to _phsk_preproc
	return 32;
}
#endif

#if PLAINTEXT_LENGTH > 64
inline void _phsk_preproc(const uchar *key, uint keylen, __global uint *state, uint padding)
#else
inline void _phsk_preproc(__global const uchar *key, uint keylen, __global uint *state, uint padding)
#endif
{
	uint j, t;
	uint W[16];
	uint A = h[0];
	uint B = h[1];
	uint C = h[2];
	uint D = h[3];
	uint E = h[4];
	uint F = h[5];
	uint G = h[6];
	uint H = h[7];

	#pragma unroll
	for (j = 0; j < 16; j++)
		W[j] = padding;

	for (j = 0; j < keylen; j++)
		XORCHAR_BE(W, j, key[j]);

	SHA256(A, B, C, D, E, F, G, H, W);

	state[0] = A + h[0];
	state[1] = B + h[1];
	state[2] = C + h[2];
	state[3] = D + h[3];
	state[4] = E + h[4];
	state[5] = F + h[5];
	state[6] = G + h[6];
	state[7] = H + h[7];
}

inline void _phsk_hmac_sha256(__global uint *output,
							__global uint *ipad_state,
							__global uint *opad_state,
							SALT_MEMORY_TYPE uchar *salt,
							uint saltlen,
							uint add)
{
	uint i, j, last;
	uint W[16], ctx[8];
	uchar addc[4];
	PUT_UINT32(add, addc, 0);

	// Code now handles ANY length salt!
	// switched to use sha256_block ctx model
	#pragma unroll
	for (j = 0; j < 8; j++)
		ctx[j] = ipad_state[j];

	i = 0;
	last = saltlen;	// this the count of bytes of salt put into the final buffer.
	while (i+64 <= saltlen)
	{
		// no need to clean. We are using the entire 64 bytes with this block of salt
		#pragma unroll
		for (j = 0; j < 64; ++j, ++i)
			PUTCHAR_BE(W, j, salt[i]);
		last -= 64;
		sha256_block(W, ctx);
	}
	//
	// ok, either this is the last limb, OR we have this one, and have to make 1 more.
	//
	// Fully blank out the buffer (dont skip element 15 len 61-63 wont clean buffer)
	#pragma unroll
	for (j = 0; j < 16; j++)
		W[j] = 0;

	// assertion [i <= saltlen < (i+64)], so all remaining salt (if any) fits in this block
	for (j = 0; i < saltlen; ++j, ++i)
		PUTCHAR_BE(W, j, salt[i]);

	if (last <= 51)
	{
		// this is last limb, everything fits
		PUTCHAR_BE(W, last + 0, addc[3]);
		PUTCHAR_BE(W, last + 1, addc[2]);
		PUTCHAR_BE(W, last + 2, addc[1]);
		PUTCHAR_BE(W, last + 3, addc[0]);
		PUTCHAR_BE(W, last + 4, 0x80);
		W[15] = (64 + saltlen + 4) << 3;
	}
	else
	{
		// do the last limb with salt data, then 1 more buffer, since this one
		// the salt + add number did NOT fit into this buffer.
		if (last < 61)
		{
			PUTCHAR_BE(W, last + 0, addc[3]);
			PUTCHAR_BE(W, last + 1, addc[2]);
			PUTCHAR_BE(W, last + 2, addc[1]);
			PUTCHAR_BE(W, last + 3, addc[0]);
		}

		if (last < 60)
			PUTCHAR_BE(W, last + 4, 0x80);
		sha256_block(W, ctx);

		// Final limb (no salt data put into this one)
		#pragma unroll
		for (j = 0; j < 15; j++)
			W[j] = 0;

		//not sure this one is correct tho, however we never exceed this limit anyways...
		if (last >= 61) PUTCHAR_BE(W, last - 61, addc[0]);
		if (last >= 62) PUTCHAR_BE(W, last - 62, addc[1]);
		if (last >= 63) PUTCHAR_BE(W, last - 63, addc[2]);
		if (last >= 64) PUTCHAR_BE(W, last - 64, addc[3]);
		
		if (last >= 60)
			PUTCHAR_BE(W, last - 60, 0x80);
		W[15] = (64 + saltlen + 4) << 3;
	}

	// this is sha256_final for our salt.add-word.
	sha256_block(W, ctx);

	#pragma unroll
	for (j = 0; j < 8; j++)
		W[j] = ctx[j];
	
	W[8] = 0x80000000;
	W[15] = 0x300;

	#pragma unroll
	for (j = 0; j < 8; j++)
		ctx[j] = opad_state[j];
	
	sha256_block_zeros(W, ctx);

	#pragma unroll
	for (j = 0; j < 8; j++)
		output[j] = ctx[j];
}

__kernel void pbkdf2_sha256_loop(__global state_t *state)
{
	uint idx = get_global_id(0);
	uint i, round, rounds = state[idx].rounds;
	uint W[16];
	uint ipad_state[8];
	uint opad_state[8];
	uint tmp_out[8];

	#pragma unroll
	for (i = 0; i < 8; i++)
	{
		W[i] = state[idx].W[i];
		ipad_state[i] = state[idx].ipad[i];
		opad_state[i] = state[idx].opad[i];
		tmp_out[i] = state[idx].hash[i];
	}

	for (round = 0; round < MIN(rounds,HASH_LOOPS); round++)
	{
		uint A, B, C, D, E, F, G, H, t;

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];
		F = ipad_state[5];
		G = ipad_state[6];
		H = ipad_state[7];

		W[8] = 0x80000000;
		W[15] = 0x300;

		SHA256_ZEROS(A, B, C, D, E, F, G, H, W);

		W[0] = A + ipad_state[0];
		W[1] = B + ipad_state[1];
		W[2] = C + ipad_state[2];
		W[3] = D + ipad_state[3];
		W[4] = E + ipad_state[4];
		W[5] = F + ipad_state[5];
		W[6] = G + ipad_state[6];
		W[7] = H + ipad_state[7];
		W[8] = 0x80000000;
		W[15] = 0x300;

		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];
		F = opad_state[5];
		G = opad_state[6];
		H = opad_state[7];

		SHA256_ZEROS(A, B, C, D, E, F, G, H, W);

		W[0] = A += opad_state[0];
		W[1] = B += opad_state[1];
		W[2] = C += opad_state[2];
		W[3] = D += opad_state[3];
		W[4] = E += opad_state[4];
		W[5] = F += opad_state[5];
		W[6] = G += opad_state[6];
		W[7] = H += opad_state[7];

		tmp_out[0] ^= A;
		tmp_out[1] ^= B;
		tmp_out[2] ^= C;
		tmp_out[3] ^= D;
		tmp_out[4] ^= E;
		tmp_out[5] ^= F;
		tmp_out[6] ^= G;
		tmp_out[7] ^= H;
	}

	state[idx].rounds = rounds - HASH_LOOPS;

	#pragma unroll
	for (i = 0; i < 8; i++)
	{
		state[idx].hash[i] = tmp_out[i];
		state[idx].W[i] = W[i];
	}
}

__kernel void pbkdf2_sha256_init(__global const pass_t *inbuffer,
									SALT_MEMORY_TYPE salt_t *salt_,
									CFG_MEMORY_TYPE config_t *cfg,
									__global state_t *state_)
{
	uint idx = get_global_id(0);
	uint i;
	uint pass = cfg->skip_bytes / 32;

	__global state_t * state = state_ + idx;
	state->rounds = cfg->rounds - 1;

#if SALT_PER_IDX
	//the salt length must be the same for all salts, this is required
	//the arguments are not aligned so the sizes must be exact
	SALT_MEMORY_TYPE salt_t * salt = (SALT_MEMORY_TYPE salt_t *)(((SALT_MEMORY_TYPE uchar *)salt_) + (idx * (4 + salt_->length)));
#else
	SALT_MEMORY_TYPE salt_t * salt = salt_;
#endif

#if PLAINTEXT_LENGTH > 64
	uint8_t key[64];
	memset_macro(key, 0, 64);
	uint keylen = _phsk_key_precompute(inbuffer[idx].v, inbuffer[idx].length, key);
	_phsk_preproc(key, keylen, state->ipad, 0x36363636);
	_phsk_preproc(key, keylen, state->opad, 0x5c5c5c5c);
#else
	_phsk_preproc(inbuffer[idx].v, inbuffer[idx].length, state->ipad, 0x36363636);
	_phsk_preproc(inbuffer[idx].v, inbuffer[idx].length, state->opad, 0x5c5c5c5c);
#endif
	_phsk_hmac_sha256(state->hash, state->ipad, state->opad, salt->salt, salt->length, pass + 1);

	#pragma unroll
	for (i = 0; i < 8; i++)
		state->W[i] = state->hash[i];

	state->pass = pass;
}

__kernel void pbkdf2_sha256_final(__global crack_t *out,
									SALT_MEMORY_TYPE salt_t *salt_,
									CFG_MEMORY_TYPE config_t *cfg,
									__global state_t *state)
{
	uint idx = get_global_id(0);
	uint i;
	uint base = (state[idx].pass - cfg->skip_bytes / 32) * 8;

#if SALT_PER_IDX
	//the salt length must be the same for all salts, this is required
	//the arguments are not aligned so the sizes must be exact
	SALT_MEMORY_TYPE salt_t * salt = (SALT_MEMORY_TYPE salt_t *)(((SALT_MEMORY_TYPE uchar *)salt_) + (idx * (4 + salt_->length)));
#else
	SALT_MEMORY_TYPE salt_t * salt = salt_;
#endif

	//First/next 32 bytes of output
	#pragma unroll
	for (i = 0; i < 8; i++)
		out[idx].hash[i] = SWAP32(state[idx].hash[i]);

	uint pass = ++state[idx].pass;

	//Was this the last pass? If not, prepare for next one
	if (4 * base + 32 < cfg->outlen)
	{
		_phsk_hmac_sha256(state[idx].hash, state[idx].ipad, state[idx].opad,
							salt->salt, salt->length, pass + 1);

		#pragma unroll
		for (i = 0; i < 8; i++)
			state[idx].W[i] = state[idx].hash[i];

		state[idx].rounds = cfg->rounds - 1;
	}
}
