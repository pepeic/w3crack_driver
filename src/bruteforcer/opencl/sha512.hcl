#include "sha2_shared.hcl"

#ifndef SHA512_DIGEST_LENGTH
#define SHA512_DIGEST_LENGTH 64
#endif

#define SHA512_LUT3 HAVE_LUT3_64

/*
 * These macros are the same as for SHA-256 but we might end up with
 * different ones being most effective as current GPU's aren't native 64-bit.
 */
#undef Maj
#undef Ch

#if SHA512_LUT3
#define Ch(x, y, z) lut3_64(x, y, z, 0xca)
#elif USE_BITSELECT
#define Ch(x, y, z) bitselect(z, y, x)
#elif HAVE_ANDNOT
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#endif

#if SHA512_LUT3
#define Maj(x, y, z) lut3_64(x, y, z, 0xe8)
#elif USE_BITSELECT
#define Maj(x, y, z) bitselect(x, y, z ^ x)
#elif 0 /* Wei Dai's trick, but we let the compiler cache/reuse or not */
#define Maj(x, y, z) (y ^ ((x ^ y) & (y ^ z)))
#elif 0 /* Explicit caching/reuse of common subexpression between rounds */
#define Maj(x, y, z) (y ^ ((x_xor_y = x ^ y) & y_xor_z))
#define CACHEXY uint x_xor_y, y_xor_z = S[(65 - i) % 8] ^ S[(66 - i) % 8];
#define CACHEYZ y_xor_z = x_xor_y;
#elif 0
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#else
#define Maj(x, y, z) ((x & y) | (z & (x | y)))
#endif

#ifndef CACHEXY
#define CACHEXY
#define CACHEYZ
#endif

__constant ulong K[] = {
	0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL,
	0xe9b5dba58189dbbcUL, 0x3956c25bf348b538UL, 0x59f111f1b605d019UL,
	0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL, 0xd807aa98a3030242UL,
	0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
	0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL,
	0xc19bf174cf692694UL, 0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL,
	0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL, 0x2de92c6f592b0275UL,
	0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
	0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL,
	0xbf597fc7beef0ee4UL, 0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL,
	0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL,
	0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
	0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL,
	0x92722c851482353bUL, 0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL,
	0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL, 0xd192e819d6ef5218UL,
	0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
	0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL,
	0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL,
	0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL,
	0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
	0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL,
	0xc67178f2e372532bUL, 0xca273eceea26619cUL, 0xd186b8c721c0c207UL,
	0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL, 0x06f067aa72176fbaUL,
	0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
	0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL,
	0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL,
	0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

#if 0 && SHA512_LUT3
/* LOP3.LUT alternative - does no good */
#define Sigma0_64(x) lut3_64(ror64(x, 28), ror64(x, 34), ror64(x, 39), 0x96)
#define Sigma1_64(x) lut3_64(ror64(x, 14), ror64(x, 18), ror64(x, 41), 0x96)
#elif 0
/*
 * These Sigma alternatives are derived from "Fast SHA-256 Implementations
 * on Intel Architecture Processors" whitepaper by Intel (rewritten here
 * for SHA-512 by magnum). They were intended for use with destructive rotate
 * (minimizing register copies) but might be better or worse on different
 * hardware for other reasons.
 */
#define Sigma0_64(x) (ror64(ror64(ror64(x, 5) ^ x, 6) ^ x, 28))
#define Sigma1_64(x) (ror64(ror64(ror64(x, 23) ^ x, 4) ^ x, 14))
#else
/* Original SHA-2 function */
#define Sigma0_64(x) (ror64(x, 28) ^ ror64(x, 34) ^ ror64(x, 39))
#define Sigma1_64(x) (ror64(x, 14) ^ ror64(x, 18) ^ ror64(x, 41))
#endif

#if 0 && SHA512_LUT3
/* LOP3.LUT alternative - does no good */
#define sigma0_64(x) lut3_64(ror64(x, 1), ror64(x, 8), (x >> 7), 0x96)
#define sigma1_64(x) lut3_64(ror64(x, 19), ror64(x, 61), (x >> 6), 0x96)
#elif 0
/*
 * These sigma alternatives are from "Fast SHA-512 Implementations on Intel
 * Architecture Processors" whitepaper by Intel. They were intended for use
 * with destructive shifts (minimizing register copies) but might be better
 * or worse on different hardware for other reasons. They will likely always
 * be a regression when we have 64-bit hardware rotate instructions - but
 * that probably doesn't exist for current GPU's as of now since they're all
 * 32-bit (and may not even have 32-bit rotate for that matter).
 */
#define sigma0_64(x) ((((((x >> 1) ^ x) >> 6) ^ x) >> 1) ^ (((x << 7) ^ x) << 56))
#define sigma1_64(x) ((((((x >> 42) ^ x) >> 13) ^ x) >> 6) ^ (((x << 42) ^ x) << 3))
#else
/* Original SHA-2 function */
#define sigma0_64(x) (ror64(x, 1)  ^ ror64(x, 8) ^ (x >> 7))
#define sigma1_64(x) (ror64(x, 19) ^ ror64(x, 61) ^ (x >> 6))
#endif

#define SHA2_INIT_A	0x6a09e667f3bcc908UL
#define SHA2_INIT_B	0xbb67ae8584caa73bUL
#define SHA2_INIT_C	0x3c6ef372fe94f82bUL
#define SHA2_INIT_D	0xa54ff53a5f1d36f1UL
#define SHA2_INIT_E	0x510e527fade682d1UL
#define SHA2_INIT_F	0x9b05688c2b3e6c1fUL
#define SHA2_INIT_G	0x1f83d9abfb41bd6bUL
#define SHA2_INIT_H	0x5be0cd19137e2179UL

#define ROUND512_A(a, b, c, d, e, f, g, h, ki, wi)	\
	t = (ki) + (wi) + (h) + Sigma1_64(e) + Ch((e), (f), (g)); \
	d += (t); h = (t) + Sigma0_64(a) + Maj((a), (b), (c));

#define ROUND512_Z(a, b, c, d, e, f, g, h, ki)	\
	t = (ki) + (h) + Sigma1_64(e) + Ch((e), (f), (g)); \
	d += (t); h = (t) + Sigma0_64(a) + Maj((a), (b), (c));

#define ROUND512_B(a, b, c, d, e, f, g, h, ki, wi, wj, wk, wl, wm)	  \
	wi = sigma1_64(wj) + sigma0_64(wk) + wl + wm; \
	t = (ki) + (wi) + (h) + Sigma1_64(e) + Ch((e), (f), (g)); \
	d += (t); h = (t) + Sigma0_64(a) + Maj((a), (b), (c));

#define SHA512_16to31(A,B,C,D,E,F,G,H,W) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[16],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[17],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[18],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[19],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[20],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[21],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[22],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[23],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[24],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[25],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[26],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[27],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[28],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[29],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[30],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[31],W[15],  W[13],W[0],W[15],W[8])
#define SHA512_32to79_unrolled(A,B,C,D,E,F,G,H,W) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[32],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[33],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[34],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[35],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[36],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[37],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[38],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[39],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[40],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[41],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[42],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[43],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[44],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[45],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[46],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[47],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[48],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[49],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[50],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[51],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[52],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[53],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[54],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[55],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[56],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[57],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[58],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[59],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[60],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[61],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[62],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[63],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[64],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[65],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[66],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[67],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[68],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[69],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[70],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[71],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[72],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[73],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[74],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[75],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[76],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[77],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[78],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[79],W[15],  W[13],W[0],W[15],W[8])
#define SHA512_16to79(A,B,C,D,E,F,G,H,W) \
	SHA512_16to31(A,B,C,D,E,F,G,H,W) \
	SHA512_32to79_unrolled(A,B,C,D,E,F,G,H,W)

#if nvidia_sm_3x(DEVICE_INFO)
#define SHA512_32to79 SHA512_32to79_unrolled
#else
#define SHA512_32to79(A,B,C,D,E,F,G,H,W) \
	for (uint i = 32; i <= 64; i += 16) { \
		ROUND512_B(A,B,C,D,E,F,G,H,K[i],W[0],  W[14],W[1],W[0],W[9]) \
		ROUND512_B(H,A,B,C,D,E,F,G,K[i+1],W[1],  W[15],W[2],W[1],W[10]) \
		ROUND512_B(G,H,A,B,C,D,E,F,K[i+2],W[2],  W[0],W[3],W[2],W[11]) \
		ROUND512_B(F,G,H,A,B,C,D,E,K[i+3],W[3],  W[1],W[4],W[3],W[12]) \
		ROUND512_B(E,F,G,H,A,B,C,D,K[i+4],W[4],  W[2],W[5],W[4],W[13]) \
		ROUND512_B(D,E,F,G,H,A,B,C,K[i+5],W[5],  W[3],W[6],W[5],W[14]) \
		ROUND512_B(C,D,E,F,G,H,A,B,K[i+6],W[6],  W[4],W[7],W[6],W[15]) \
		ROUND512_B(B,C,D,E,F,G,H,A,K[i+7],W[7],  W[5],W[8],W[7],W[0]) \
		ROUND512_B(A,B,C,D,E,F,G,H,K[i+8],W[8],  W[6],W[9],W[8],W[1]) \
		ROUND512_B(H,A,B,C,D,E,F,G,K[i+9],W[9],  W[7],W[10],W[9],W[2]) \
		ROUND512_B(G,H,A,B,C,D,E,F,K[i+10],W[10],  W[8],W[11],W[10],W[3]) \
		ROUND512_B(F,G,H,A,B,C,D,E,K[i+11],W[11],  W[9],W[12],W[11],W[4]) \
		ROUND512_B(E,F,G,H,A,B,C,D,K[i+12],W[12],  W[10],W[13],W[12],W[5]) \
		ROUND512_B(D,E,F,G,H,A,B,C,K[i+13],W[13],  W[11],W[14],W[13],W[6]) \
		ROUND512_B(C,D,E,F,G,H,A,B,K[i+14],W[14],  W[12],W[15],W[14],W[7]) \
		ROUND512_B(B,C,D,E,F,G,H,A,K[i+15],W[15],  W[13],W[0],W[15],W[8]) \
	}
#endif

#define SHA512(A, B, C, D, E, F, G, H, W)	  \
	ROUND512_A(A,B,C,D,E,F,G,H,K[0],W[0]) \
	ROUND512_A(H,A,B,C,D,E,F,G,K[1],W[1]) \
	ROUND512_A(G,H,A,B,C,D,E,F,K[2],W[2]) \
	ROUND512_A(F,G,H,A,B,C,D,E,K[3],W[3]) \
	ROUND512_A(E,F,G,H,A,B,C,D,K[4],W[4]) \
	ROUND512_A(D,E,F,G,H,A,B,C,K[5],W[5]) \
	ROUND512_A(C,D,E,F,G,H,A,B,K[6],W[6]) \
	ROUND512_A(B,C,D,E,F,G,H,A,K[7],W[7]) \
	ROUND512_A(A,B,C,D,E,F,G,H,K[8],W[8]) \
	ROUND512_A(H,A,B,C,D,E,F,G,K[9],W[9]) \
	ROUND512_A(G,H,A,B,C,D,E,F,K[10],W[10]) \
	ROUND512_A(F,G,H,A,B,C,D,E,K[11],W[11]) \
	ROUND512_A(E,F,G,H,A,B,C,D,K[12],W[12]) \
	ROUND512_A(D,E,F,G,H,A,B,C,K[13],W[13]) \
	ROUND512_A(C,D,E,F,G,H,A,B,K[14],W[14]) \
	ROUND512_A(B,C,D,E,F,G,H,A,K[15],W[15]) \
	SHA512_16to79(A,B,C,D,E,F,G,H,W)

//W[9]-W[14] are zeros
#define SHA512_ZEROS(A, B, C, D, E, F, G, H, W)	  \
	ROUND512_A(A,B,C,D,E,F,G,H,K[0],W[0]) \
	ROUND512_A(H,A,B,C,D,E,F,G,K[1],W[1]) \
	ROUND512_A(G,H,A,B,C,D,E,F,K[2],W[2]) \
	ROUND512_A(F,G,H,A,B,C,D,E,K[3],W[3]) \
	ROUND512_A(E,F,G,H,A,B,C,D,K[4],W[4]) \
	ROUND512_A(D,E,F,G,H,A,B,C,K[5],W[5]) \
	ROUND512_A(C,D,E,F,G,H,A,B,K[6],W[6]) \
	ROUND512_A(B,C,D,E,F,G,H,A,K[7],W[7]) \
	ROUND512_A(A,B,C,D,E,F,G,H,K[8],W[8]) \
	ROUND512_Z(H,A,B,C,D,E,F,G,K[9]) \
	ROUND512_Z(G,H,A,B,C,D,E,F,K[10]) \
	ROUND512_Z(F,G,H,A,B,C,D,E,K[11]) \
	ROUND512_Z(E,F,G,H,A,B,C,D,K[12]) \
	ROUND512_Z(D,E,F,G,H,A,B,C,K[13]) \
	ROUND512_Z(C,D,E,F,G,H,A,B,K[14]) \
	ROUND512_A(B,C,D,E,F,G,H,A,K[15],W[15]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[16],W[0],  0UL,W[1],W[0],0UL) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[17],W[1],  W[15],W[2],W[1],0UL) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[18],W[2],  W[0],W[3],W[2],0UL) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[19],W[3],  W[1],W[4],W[3],0UL) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[20],W[4],  W[2],W[5],W[4],0UL) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[21],W[5],  W[3],W[6],W[5],0UL) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[22],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[23],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND512_B(A,B,C,D,E,F,G,H,K[24],W[8],  W[6],0UL,W[8],W[1]) \
	ROUND512_B(H,A,B,C,D,E,F,G,K[25],W[9],  W[7],0UL,0UL,W[2]) \
	ROUND512_B(G,H,A,B,C,D,E,F,K[26],W[10],  W[8],0UL,0UL,W[3]) \
	ROUND512_B(F,G,H,A,B,C,D,E,K[27],W[11],  W[9],0UL,0UL,W[4]) \
	ROUND512_B(E,F,G,H,A,B,C,D,K[28],W[12],  W[10],0UL,0UL,W[5]) \
	ROUND512_B(D,E,F,G,H,A,B,C,K[29],W[13],  W[11],0UL,0UL,W[6]) \
	ROUND512_B(C,D,E,F,G,H,A,B,K[30],W[14],  W[12],W[15],0UL,W[7]) \
	ROUND512_B(B,C,D,E,F,G,H,A,K[31],W[15],  W[13],W[0],W[15],W[8]) \
	SHA512_32to79(A,B,C,D,E,F,G,H,W)

#ifdef SCALAR
#define sha512_single_s		sha512_single
#else

/* Raw'n'lean single-block SHA-512, no context[tm] */
inline void sha512_single_s(ulong *W, ulong *output)
{
	ulong A, B, C, D, E, F, G, H, t;

	A = SHA2_INIT_A;
	B = SHA2_INIT_B;
	C = SHA2_INIT_C;
	D = SHA2_INIT_D;
	E = SHA2_INIT_E;
	F = SHA2_INIT_F;
	G = SHA2_INIT_G;
	H = SHA2_INIT_H;

	SHA512(A, B, C, D, E, F, G, H, W)

	output[0] = A + SHA2_INIT_A;
	output[1] = B + SHA2_INIT_B;
	output[2] = C + SHA2_INIT_C;
	output[3] = D + SHA2_INIT_D;
	output[4] = E + SHA2_INIT_E;
	output[5] = F + SHA2_INIT_F;
	output[6] = G + SHA2_INIT_G;
	output[7] = H + SHA2_INIT_H;
}
#endif

#define sha512_block(pad, ctx)\
 {	  \
	ulong A, B, C, D, E, F, G, H, t; \
	A = (ctx)[0]; \
	B = (ctx)[1]; \
	C = (ctx)[2]; \
	D = (ctx)[3]; \
	E = (ctx)[4]; \
	F = (ctx)[5]; \
	G = (ctx)[6]; \
	H = (ctx)[7]; \
	SHA512(A, B, C, D, E, F, G, H, pad); \
	(ctx)[0] += A; \
	(ctx)[1] += B; \
	(ctx)[2] += C; \
	(ctx)[3] += D; \
	(ctx)[4] += E; \
	(ctx)[5] += F; \
	(ctx)[6] += G; \
	(ctx)[7] += H; \
}

/* Raw'n'lean single-block SHA-512, no context[tm] */
inline void sha512_single(MAYBE_VECTOR_ULONG *W, MAYBE_VECTOR_ULONG *output)
{
	MAYBE_VECTOR_ULONG A, B, C, D, E, F, G, H, t;

	A = SHA2_INIT_A;
	B = SHA2_INIT_B;
	C = SHA2_INIT_C;
	D = SHA2_INIT_D;
	E = SHA2_INIT_E;
	F = SHA2_INIT_F;
	G = SHA2_INIT_G;
	H = SHA2_INIT_H;

	SHA512(A, B, C, D, E, F, G, H, W)

	output[0] = A + SHA2_INIT_A;
	output[1] = B + SHA2_INIT_B;
	output[2] = C + SHA2_INIT_C;
	output[3] = D + SHA2_INIT_D;
	output[4] = E + SHA2_INIT_E;
	output[5] = F + SHA2_INIT_F;
	output[6] = G + SHA2_INIT_G;
	output[7] = H + SHA2_INIT_H;
}

inline void sha512_single_zeros(MAYBE_VECTOR_ULONG *W,
								MAYBE_VECTOR_ULONG *output)
{
	MAYBE_VECTOR_ULONG A, B, C, D, E, F, G, H, t;

	A = SHA2_INIT_A;
	B = SHA2_INIT_B;
	C = SHA2_INIT_C;
	D = SHA2_INIT_D;
	E = SHA2_INIT_E;
	F = SHA2_INIT_F;
	G = SHA2_INIT_G;
	H = SHA2_INIT_H;

	SHA512_ZEROS(A, B, C, D, E, F, G, H, W)

	output[0] = A + SHA2_INIT_A;
	output[1] = B + SHA2_INIT_B;
	output[2] = C + SHA2_INIT_C;
	output[3] = D + SHA2_INIT_D;
	output[4] = E + SHA2_INIT_E;
	output[5] = F + SHA2_INIT_F;
	output[6] = G + SHA2_INIT_G;
	output[7] = H + SHA2_INIT_H;
}