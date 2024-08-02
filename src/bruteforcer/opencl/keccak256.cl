#include "misc.hcl"

#define SPH_C64(x) ((ulong)(x))
#define BLOCK_LEN 136
#define BLOCK_ITERS (BLOCK_LEN >> 3)
#define DELIM 1

typedef struct
{
	uchar buf[BLOCK_LEN];
	ulong state[25];
	size_t ptr;
} keccak256_context;

__constant ulong RC[] =
{
	SPH_C64(0x0000000000000001L), SPH_C64(0x0000000000008082L),
	SPH_C64(0x800000000000808AL), SPH_C64(0x8000000080008000L),
	SPH_C64(0x000000000000808BL), SPH_C64(0x0000000080000001L),
	SPH_C64(0x8000000080008081L), SPH_C64(0x8000000000008009L),
	SPH_C64(0x000000000000008AL), SPH_C64(0x0000000000000088L),
	SPH_C64(0x0000000080008009L), SPH_C64(0x000000008000000AL),
	SPH_C64(0x000000008000808BL), SPH_C64(0x800000000000008BL),
	SPH_C64(0x8000000000008089L), SPH_C64(0x8000000000008003L),
	SPH_C64(0x8000000000008002L), SPH_C64(0x8000000000000080L),
	SPH_C64(0x000000000000800AL), SPH_C64(0x800000008000000AL),
	SPH_C64(0x8000000080008081L), SPH_C64(0x8000000000008080L),
	SPH_C64(0x0000000080000001L), SPH_C64(0x8000000080008008L)
};

#define a00 (kc->state[0])
#define a10 (kc->state[1])
#define a20 (kc->state[2])
#define a30 (kc->state[3])
#define a40 (kc->state[4])
#define a01 (kc->state[5])
#define a11 (kc->state[6])
#define a21 (kc->state[7])
#define a31 (kc->state[8])
#define a41 (kc->state[9])
#define a02 (kc->state[10])
#define a12 (kc->state[11])
#define a22 (kc->state[12])
#define a32 (kc->state[13])
#define a42 (kc->state[14])
#define a03 (kc->state[15])
#define a13 (kc->state[16])
#define a23 (kc->state[17])
#define a33 (kc->state[18])
#define a43 (kc->state[19])
#define a04 (kc->state[20])
#define a14 (kc->state[21])
#define a24 (kc->state[22])
#define a34 (kc->state[23])
#define a44 (kc->state[24])

static inline ulong dec64le_aligned(const void * src)
{
	return (ulong)(((const uchar *)src)[0])
		| ((ulong)(((const uchar *)src)[1]) << 8)
		| ((ulong)(((const uchar *)src)[2]) << 16)
		| ((ulong)(((const uchar *)src)[3]) << 24)
		| ((ulong)(((const uchar *)src)[4]) << 32)
		| ((ulong)(((const uchar *)src)[5]) << 40)
		| ((ulong)(((const uchar *)src)[6]) << 48)
		| ((ulong)(((const uchar *)src)[7]) << 56);
}

static inline ulong dec64le_aligned_c(__global const void * src)
{
	return (ulong)(((__global const uchar *)src)[0])
		| ((ulong)(((__global const uchar *)src)[1]) << 8)
		| ((ulong)(((__global const uchar *)src)[2]) << 16)
		| ((ulong)(((__global const uchar *)src)[3]) << 24)
		| ((ulong)(((__global const uchar *)src)[4]) << 32)
		| ((ulong)(((__global const uchar *)src)[5]) << 40)
		| ((ulong)(((__global const uchar *)src)[6]) << 48)
		| ((ulong)(((__global const uchar *)src)[7]) << 56);
}

#define enc64le_aligned(dst,value) do \
{ \
	ulong val = (ulong)value; \
	((uchar *)(dst))[0] = val; \
	((uchar *)(dst))[1] = (val >> 8); \
	((uchar *)(dst))[2] = (val >> 16); \
	((uchar *)(dst))[3] = (val >> 24); \
	((uchar *)(dst))[4] = (val >> 32); \
	((uchar *)(dst))[5] = (val >> 40); \
	((uchar *)(dst))[6] = (val >> 48); \
	((uchar *)(dst))[7] = (val >> 56); \
} while(0)

#define SPH_T64(x)	((x) & SPH_C64(0xFFFFFFFFFFFFFFFF))
#define SPH_ROTL64(x, n)   SPH_T64(((x) << (n)) | ((x) >> (64 - (n))))
#define SPH_ROTR64(x, n)   SPH_ROTL64(x, (64 - (n)))
#define DECL64(x)		ulong x
#define MOV64(d, s)	  (d = s)
#define XOR64(d, a, b)   (d = a ^ b)
#define AND64(d, a, b)   (d = a & b)
#define OR64(d, a, b)	(d = a | b)
#define NOT64(d, s)	  (d = SPH_T64(~s))
#define ROL64(d, v, n)   (d = SPH_ROTL64(v, n))
#define XOR64_IOTA	   XOR64


#define TH_ELT(t, c0, c1, c2, c3, c4, d0, d1, d2, d3, d4)   { \
		DECL64(tt0); \
		DECL64(tt1); \
		DECL64(tt2); \
		DECL64(tt3); \
		XOR64(tt0, d0, d1); \
		XOR64(tt1, d2, d3); \
		XOR64(tt0, tt0, d4); \
		XOR64(tt0, tt0, tt1); \
		ROL64(tt0, tt0, 1); \
		XOR64(tt2, c0, c1); \
		XOR64(tt3, c2, c3); \
		XOR64(tt0, tt0, c4); \
		XOR64(tt2, tt2, tt3); \
		XOR64(t, tt0, tt2); \
	}

#define THETA(b00, b01, b02, b03, b04, b10, b11, b12, b13, b14, \
	b20, b21, b22, b23, b24, b30, b31, b32, b33, b34, \
	b40, b41, b42, b43, b44) \
	{ \
		DECL64(t0); \
		DECL64(t1); \
		DECL64(t2); \
		DECL64(t3); \
		DECL64(t4); \
		TH_ELT(t0, b40, b41, b42, b43, b44, b10, b11, b12, b13, b14); \
		TH_ELT(t1, b00, b01, b02, b03, b04, b20, b21, b22, b23, b24); \
		TH_ELT(t2, b10, b11, b12, b13, b14, b30, b31, b32, b33, b34); \
		TH_ELT(t3, b20, b21, b22, b23, b24, b40, b41, b42, b43, b44); \
		TH_ELT(t4, b30, b31, b32, b33, b34, b00, b01, b02, b03, b04); \
		XOR64(b00, b00, t0); \
		XOR64(b01, b01, t0); \
		XOR64(b02, b02, t0); \
		XOR64(b03, b03, t0); \
		XOR64(b04, b04, t0); \
		XOR64(b10, b10, t1); \
		XOR64(b11, b11, t1); \
		XOR64(b12, b12, t1); \
		XOR64(b13, b13, t1); \
		XOR64(b14, b14, t1); \
		XOR64(b20, b20, t2); \
		XOR64(b21, b21, t2); \
		XOR64(b22, b22, t2); \
		XOR64(b23, b23, t2); \
		XOR64(b24, b24, t2); \
		XOR64(b30, b30, t3); \
		XOR64(b31, b31, t3); \
		XOR64(b32, b32, t3); \
		XOR64(b33, b33, t3); \
		XOR64(b34, b34, t3); \
		XOR64(b40, b40, t4); \
		XOR64(b41, b41, t4); \
		XOR64(b42, b42, t4); \
		XOR64(b43, b43, t4); \
		XOR64(b44, b44, t4); \
	}

#define RHO(b00, b01, b02, b03, b04, b10, b11, b12, b13, b14, \
	b20, b21, b22, b23, b24, b30, b31, b32, b33, b34, \
	b40, b41, b42, b43, b44) \
	{ \
		/* ROL64(b00, b00,  0); */ \
		ROL64(b01, b01, 36); \
		ROL64(b02, b02,  3); \
		ROL64(b03, b03, 41); \
		ROL64(b04, b04, 18); \
		ROL64(b10, b10,  1); \
		ROL64(b11, b11, 44); \
		ROL64(b12, b12, 10); \
		ROL64(b13, b13, 45); \
		ROL64(b14, b14,  2); \
		ROL64(b20, b20, 62); \
		ROL64(b21, b21,  6); \
		ROL64(b22, b22, 43); \
		ROL64(b23, b23, 15); \
		ROL64(b24, b24, 61); \
		ROL64(b30, b30, 28); \
		ROL64(b31, b31, 55); \
		ROL64(b32, b32, 25); \
		ROL64(b33, b33, 21); \
		ROL64(b34, b34, 56); \
		ROL64(b40, b40, 27); \
		ROL64(b41, b41, 20); \
		ROL64(b42, b42, 39); \
		ROL64(b43, b43,  8); \
		ROL64(b44, b44, 14); \
	}

/*
 * The KHI macro integrates the "lane complement" optimization. On input,
 * some words are complemented:
 *	a00 a01 a02 a04 a13 a20 a21 a22 a30 a33 a34 a43
 * On output, the following words are complemented:
 *	a04 a10 a20 a22 a23 a31
 *
 * The (implicit) permutation and the theta expansion will bring back
 * the input mask for the next round.
 */

#define KHI_XO(d, a, b, c)   { \
		DECL64(kt); \
		OR64(kt, b, c); \
		XOR64(d, a, kt); \
	}

#define KHI_XA(d, a, b, c)   { \
		DECL64(kt); \
		AND64(kt, b, c); \
		XOR64(d, a, kt); \
	}

#define KHI(b00, b01, b02, b03, b04, b10, b11, b12, b13, b14, \
	b20, b21, b22, b23, b24, b30, b31, b32, b33, b34, \
	b40, b41, b42, b43, b44) \
	{ \
		DECL64(c0); \
		DECL64(c1); \
		DECL64(c2); \
		DECL64(c3); \
		DECL64(c4); \
		DECL64(bnn); \
		NOT64(bnn, b20); \
		KHI_XO(c0, b00, b10, b20); \
		KHI_XO(c1, b10, bnn, b30); \
		KHI_XA(c2, b20, b30, b40); \
		KHI_XO(c3, b30, b40, b00); \
		KHI_XA(c4, b40, b00, b10); \
		MOV64(b00, c0); \
		MOV64(b10, c1); \
		MOV64(b20, c2); \
		MOV64(b30, c3); \
		MOV64(b40, c4); \
		NOT64(bnn, b41); \
		KHI_XO(c0, b01, b11, b21); \
		KHI_XA(c1, b11, b21, b31); \
		KHI_XO(c2, b21, b31, bnn); \
		KHI_XO(c3, b31, b41, b01); \
		KHI_XA(c4, b41, b01, b11); \
		MOV64(b01, c0); \
		MOV64(b11, c1); \
		MOV64(b21, c2); \
		MOV64(b31, c3); \
		MOV64(b41, c4); \
		NOT64(bnn, b32); \
		KHI_XO(c0, b02, b12, b22); \
		KHI_XA(c1, b12, b22, b32); \
		KHI_XA(c2, b22, bnn, b42); \
		KHI_XO(c3, bnn, b42, b02); \
		KHI_XA(c4, b42, b02, b12); \
		MOV64(b02, c0); \
		MOV64(b12, c1); \
		MOV64(b22, c2); \
		MOV64(b32, c3); \
		MOV64(b42, c4); \
		NOT64(bnn, b33); \
		KHI_XA(c0, b03, b13, b23); \
		KHI_XO(c1, b13, b23, b33); \
		KHI_XO(c2, b23, bnn, b43); \
		KHI_XA(c3, bnn, b43, b03); \
		KHI_XO(c4, b43, b03, b13); \
		MOV64(b03, c0); \
		MOV64(b13, c1); \
		MOV64(b23, c2); \
		MOV64(b33, c3); \
		MOV64(b43, c4); \
		NOT64(bnn, b14); \
		KHI_XA(c0, b04, bnn, b24); \
		KHI_XO(c1, bnn, b24, b34); \
		KHI_XA(c2, b24, b34, b44); \
		KHI_XO(c3, b34, b44, b04); \
		KHI_XA(c4, b44, b04, b14); \
		MOV64(b04, c0); \
		MOV64(b14, c1); \
		MOV64(b24, c2); \
		MOV64(b34, c3); \
		MOV64(b44, c4); \
	}

#define IOTA(r)   XOR64_IOTA(a00, a00, r)

#define KF_ROUND(k)   { \
		THETA ( a00, a01, a02, a03, a04, a10, a11, a12, a13, a14, a20, a21, \
				  a22, a23, a24, a30, a31, a32, a33, a34, a40, a41, a42, a43, a44 ); \
		RHO ( a00, a01, a02, a03, a04, a10, a11, a12, a13, a14, a20, a21, \
				  a22, a23, a24, a30, a31, a32, a33, a34, a40, a41, a42, a43, a44 ); \
		KHI ( a00, a30, a10, a40, a20, a11, a41, a21, a01, a31, a22, a02, \
				  a32, a12, a42, a33, a13, a43, a23, a03, a44, a24, a04, a34, a14 ); \
		IOTA(k); \
	}

#define P1_TO_P0   { \
		DECL64(t); \
		MOV64(t, a01); \
		MOV64(a01, a30); \
		MOV64(a30, a33); \
		MOV64(a33, a23); \
		MOV64(a23, a12); \
		MOV64(a12, a21); \
		MOV64(a21, a02); \
		MOV64(a02, a10); \
		MOV64(a10, a11); \
		MOV64(a11, a41); \
		MOV64(a41, a24); \
		MOV64(a24, a42); \
		MOV64(a42, a04); \
		MOV64(a04, a20); \
		MOV64(a20, a22); \
		MOV64(a22, a32); \
		MOV64(a32, a43); \
		MOV64(a43, a34); \
		MOV64(a34, a03); \
		MOV64(a03, a40); \
		MOV64(a40, a44); \
		MOV64(a44, a14); \
		MOV64(a14, a31); \
		MOV64(a31, a13); \
		MOV64(a13, t); \
	}

inline static void keccak256_init(keccak256_context * kc)
{
#pragma unroll
	for (int i = 0; i < 25; i++)
		kc->state[i] = 0;

#pragma unroll
	for (int i = 0; i < BLOCK_LEN; i++)
		kc->buf[i] = 0;
	
	//the lane complement
	kc->state[1] = SPH_C64(0xFFFFFFFFFFFFFFFFL);
	kc->state[2] = SPH_C64(0xFFFFFFFFFFFFFFFFL);
	kc->state[8] = SPH_C64(0xFFFFFFFFFFFFFFFFL);
	kc->state[12] = SPH_C64(0xFFFFFFFFFFFFFFFFL);
	kc->state[17] = SPH_C64(0xFFFFFFFFFFFFFFFFL);
	kc->state[20] = SPH_C64(0xFFFFFFFFFFFFFFFFL);

	kc->ptr = 0;
}

inline static void keccak256_update(keccak256_context * kc, __global const void * data, size_t data_len)
{
	size_t tmplen = min(BLOCK_LEN - kc->ptr, data_len);
	size_t i, j;
	uchar * buf = kc->buf;
	__global const uchar * input = (__global const uchar *)data;

#pragma unroll
	for (i = kc->ptr, j = 0; j < tmplen; i++, j++)
		buf[i] = input[j];

	if (kc->ptr + tmplen < BLOCK_LEN)
	{
		kc->ptr += tmplen;
		return;
	}

#pragma unroll
	for (j = 0; j < BLOCK_ITERS; j++)
		kc->state[j] ^= dec64le_aligned(buf + (j << 3));

	//keccak-f1600 rounds for the block
#pragma unroll
	for (j = 0; j < 24; j++)
	{
		KF_ROUND(RC[j]);
		P1_TO_P0;
	}

	//if there's remaining data present, then continue
	size_t newlen = data_len - tmplen;
	size_t blocks = newlen / BLOCK_LEN;
	input = input + tmplen;
	if (blocks != 0)
	{
		//process full blocks now
		for (i = 0; i < blocks; i++)
		{
#pragma unroll
			for (j = 0; j < BLOCK_ITERS; j++)
				kc->state[j] ^= dec64le_aligned_c(input + (j << 3));

#pragma unroll
			for (j = 0; j < 24; j++)
			{
				KF_ROUND(RC[j]);
				P1_TO_P0;
			}

			input = input + BLOCK_LEN;
		}
	}

	size_t remaining = newlen % BLOCK_LEN;
	for (i = 0; i < remaining; i++)
		buf[i] = input[i];
	kc->ptr = remaining;
}

inline static void keccak256_finalize(keccak256_context * kc, void * digest)
{
	uchar * buf = kc->buf;
	uchar remaining[8];

	size_t optimized_iters = kc->ptr >> 3;
	size_t remaining_iters = kc->ptr - (optimized_iters << 3);

	ulong * state = kc->state;
	for (size_t j = 0; j < optimized_iters; j++)
		state[j] ^= dec64le_aligned(buf + (j << 3));
	
	if (remaining_iters != 0)
	{
		buf += kc->ptr - remaining_iters;
		enc64le_aligned(remaining, state[optimized_iters]);
		for (size_t j = 0; j < remaining_iters; j++)
			remaining[j] ^= buf[j];
		state[optimized_iters] = dec64le_aligned(remaining);
	}

	XORCHAR_64(state, kc->ptr, DELIM);
	XORCHAR_64(state, BLOCK_LEN - 1, 0x80);

#pragma unroll
	for (int j = 0; j < 24; j++)
	{
		KF_ROUND(RC[j]);
		P1_TO_P0;
	}

	//finalize the lane complement
	state[1] = ~state[1];
	state[2] = ~state[2];
	state[8] = ~state[8];
	state[12] = ~state[12];
	state[17] = ~state[17];
	state[20] = ~state[20];

	//output the digest now
#pragma unroll
	for (int j = 0; j < 32; j += 8)
		enc64le_aligned(((uchar *)digest) + j, state[j >> 3]);
}

__kernel void keccak256(__global const uchar * in, uint insize, __global void * digest)
{
	uint idx = get_global_id(0);

	ulong hash[4];
	keccak256_context ctx_keccak;
	keccak256_init(&ctx_keccak);
	keccak256_update(&ctx_keccak, in + (idx * insize), insize);
	keccak256_finalize(&ctx_keccak, hash);

	__global ulong * outdig = ((__global ulong *)digest) + (idx * 4);

#pragma unroll
	for (int i = 0; i < 4; i++)
		outdig[i] = hash[i];
}
