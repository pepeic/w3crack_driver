#include "sha2_shared.hcl"

#ifndef SHA256_DIGEST_LENGTH
#define SHA256_DIGEST_LENGTH 32
#endif

#define SHA256_LUT3 HAVE_LUT3

#if SHA256_LUT3
#define Ch(x, y, z) lut3(x, y, z, 0xca)
#elif USE_BITSELECT
#define Ch(x, y, z) bitselect(z, y, x)
#elif HAVE_ANDNOT
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#else
#define Ch(x, y, z) (z ^ (x & (y ^ z)))
#endif

#if SHA256_LUT3
#define Maj(x, y, z) lut3(x, y, z, 0xe8)
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

#define ror ror32

__constant uint h[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

__constant uint k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#if 0 && SHA256_LUT3
/* LOP3.LUT alternative - does no good */
#define Sigma0(x) lut3(ror(x, 2), ror(x, 13), ror(x, 22), 0x96)
#define Sigma1(x) lut3(ror(x, 6), ror(x, 11), ror(x, 25), 0x96)
#elif gpu_nvidia(DEVICE_INFO)
/*
 * These Sigma alternatives are from "Fast SHA-256 Implementations on Intel
 * Architecture Processors" whitepaper by Intel. They were intended for use
 * with destructive rotate (minimizing register copies) but might be better
 * or worse on different hardware for other reasons.
 */
#define Sigma0(x) (ror(ror(ror(x, 9) ^ x, 11) ^ x, 2))
#define Sigma1(x) (ror(ror(ror(x, 14) ^ x, 5) ^ x, 6))
#else
/* Original SHA-2 function */
#define Sigma0(x) (ror(x, 2) ^ ror(x, 13) ^ ror(x, 22))
#define Sigma1(x) (ror(x, 6) ^ ror(x, 11) ^ ror(x, 25))
#endif

#if 0 && SHA256_LUT3
/* LOP3.LUT alternative - does no good */
#define sigma0(x) lut3(ror(x, 7), ror(x, 18), (x >> 3), 0x96)
#define sigma1(x) lut3(ror(x, 17), ror(x, 19), (x >> 10), 0x96)
#elif 0
/*
 * These sigma alternatives are derived from "Fast SHA-512 Implementations
 * on Intel Architecture Processors" whitepaper by Intel (rewritten here
 * for SHA-256 by magnum). They were intended for use with destructive shifts
 * (minimizing register copies) but might be better or worse on different
 * hardware for other reasons. They will likely always be a regression when
 * we have hardware rotate instructions.
 */
#define sigma0(x) ((((((x >> 11) ^ x) >> 4) ^ x) >> 3) ^ (((x << 11) ^ x) << 14))
#define sigma1(x) ((((((x >> 2) ^ x) >> 7) ^ x) >> 10) ^ (((x << 2) ^ x) << 13))
#else
/* Original SHA-2 function */
#define sigma0(x) (ror(x, 7) ^ ror(x, 18) ^ (x >> 3))
#define sigma1(x) (ror(x, 17) ^ ror(x, 19) ^ (x >> 10))
#endif

#define ROUND_A(a,b,c,d,e,f,g,h,ki,wi)	  \
	{ \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

#define ROUND_Z(a,b,c,d,e,f,g,h,ki)	  \
	{ \
		t = (ki) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

#define ROUND_B(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj) + sigma0(wk) + wl + wm; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//0110
#define ROUND_I(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma0(wk) + wl; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//1110
#define ROUND_J(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj) + sigma0(wk) + wl; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//1011
#define ROUND_K(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj) + wl + wm; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//1001
#define ROUND_L(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj)+ wm; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

//1101
#define ROUND_M(a,b,c,d,e,f,g,h,ki,wi,wj,wk,wl,wm)	  \
	{ \
		wi = sigma1(wj) + sigma0(wk) + wm; \
		t = (ki) + (wi) + (h) + Sigma1(e) + Ch((e),(f),(g)); \
		d += (t); h = (t) + Sigma0(a) + Maj((a), (b), (c)); \
	}

#define SHA256_16to31(A,B,C,D,E,F,G,H,W) \
	ROUND_B(A,B,C,D,E,F,G,H,k[16],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[17],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[18],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[19],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[20],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[21],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[22],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[23],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[24],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[25],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[26],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[27],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[28],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[29],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[30],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[31],W[15],  W[13],W[0],W[15],W[8])
#define SHA256_32to63_unrolled(A,B,C,D,E,F,G,H,W) \
	ROUND_B(A,B,C,D,E,F,G,H,k[32],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[33],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[34],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[35],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[36],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[37],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[38],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[39],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[40],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[41],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[42],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[43],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[44],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[45],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[46],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[47],W[15],  W[13],W[0],W[15],W[8]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[48],W[0],  W[14],W[1],W[0],W[9]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[49],W[1],  W[15],W[2],W[1],W[10]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[50],W[2],  W[0],W[3],W[2],W[11]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[51],W[3],  W[1],W[4],W[3],W[12]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[52],W[4],  W[2],W[5],W[4],W[13]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[53],W[5],  W[3],W[6],W[5],W[14]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[54],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[55],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_B(A,B,C,D,E,F,G,H,k[56],W[8],  W[6],W[9],W[8],W[1]) \
	ROUND_B(H,A,B,C,D,E,F,G,k[57],W[9],  W[7],W[10],W[9],W[2]) \
	ROUND_B(G,H,A,B,C,D,E,F,k[58],W[10],  W[8],W[11],W[10],W[3]) \
	ROUND_B(F,G,H,A,B,C,D,E,k[59],W[11],  W[9],W[12],W[11],W[4]) \
	ROUND_B(E,F,G,H,A,B,C,D,k[60],W[12],  W[10],W[13],W[12],W[5]) \
	ROUND_B(D,E,F,G,H,A,B,C,k[61],W[13],  W[11],W[14],W[13],W[6]) \
	ROUND_B(C,D,E,F,G,H,A,B,k[62],W[14],  W[12],W[15],W[14],W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[63],W[15],  W[13],W[0],W[15],W[8])
#define SHA256_16to63(A,B,C,D,E,F,G,H,W) \
	SHA256_16to31(A,B,C,D,E,F,G,H,W) \
	SHA256_32to63_unrolled(A,B,C,D,E,F,G,H,W)
#if nvidia_sm_3x(DEVICE_INFO)
#define SHA256_32to63 SHA256_32to63_unrolled
#else
#define SHA256_32to63(A,B,C,D,E,F,G,H,W) \
	for (uint i = 32; i <= 48; i += 16) { \
		ROUND_B(A,B,C,D,E,F,G,H,k[i],W[0],  W[14],W[1],W[0],W[9]) \
		ROUND_B(H,A,B,C,D,E,F,G,k[i+1],W[1],  W[15],W[2],W[1],W[10]) \
		ROUND_B(G,H,A,B,C,D,E,F,k[i+2],W[2],  W[0],W[3],W[2],W[11]) \
		ROUND_B(F,G,H,A,B,C,D,E,k[i+3],W[3],  W[1],W[4],W[3],W[12]) \
		ROUND_B(E,F,G,H,A,B,C,D,k[i+4],W[4],  W[2],W[5],W[4],W[13]) \
		ROUND_B(D,E,F,G,H,A,B,C,k[i+5],W[5],  W[3],W[6],W[5],W[14]) \
		ROUND_B(C,D,E,F,G,H,A,B,k[i+6],W[6],  W[4],W[7],W[6],W[15]) \
		ROUND_B(B,C,D,E,F,G,H,A,k[i+7],W[7],  W[5],W[8],W[7],W[0]) \
		ROUND_B(A,B,C,D,E,F,G,H,k[i+8],W[8],  W[6],W[9],W[8],W[1]) \
		ROUND_B(H,A,B,C,D,E,F,G,k[i+9],W[9],  W[7],W[10],W[9],W[2]) \
		ROUND_B(G,H,A,B,C,D,E,F,k[i+10],W[10],  W[8],W[11],W[10],W[3]) \
		ROUND_B(F,G,H,A,B,C,D,E,k[i+11],W[11],  W[9],W[12],W[11],W[4]) \
		ROUND_B(E,F,G,H,A,B,C,D,k[i+12],W[12],  W[10],W[13],W[12],W[5]) \
		ROUND_B(D,E,F,G,H,A,B,C,k[i+13],W[13],  W[11],W[14],W[13],W[6]) \
		ROUND_B(C,D,E,F,G,H,A,B,k[i+14],W[14],  W[12],W[15],W[14],W[7]) \
		ROUND_B(B,C,D,E,F,G,H,A,k[i+15],W[15],  W[13],W[0],W[15],W[8]) \
	}
#endif

#define SHA256(A,B,C,D,E,F,G,H,W)	  \
	ROUND_A(A,B,C,D,E,F,G,H,k[0],W[0]); \
	ROUND_A(H,A,B,C,D,E,F,G,k[1],W[1]); \
	ROUND_A(G,H,A,B,C,D,E,F,k[2],W[2]); \
	ROUND_A(F,G,H,A,B,C,D,E,k[3],W[3]); \
	ROUND_A(E,F,G,H,A,B,C,D,k[4],W[4]); \
	ROUND_A(D,E,F,G,H,A,B,C,k[5],W[5]); \
	ROUND_A(C,D,E,F,G,H,A,B,k[6],W[6]); \
	ROUND_A(B,C,D,E,F,G,H,A,k[7],W[7]); \
	ROUND_A(A,B,C,D,E,F,G,H,k[8],W[8]); \
	ROUND_A(H,A,B,C,D,E,F,G,k[9],W[9]); \
	ROUND_A(G,H,A,B,C,D,E,F,k[10],W[10]); \
	ROUND_A(F,G,H,A,B,C,D,E,k[11],W[11]); \
	ROUND_A(E,F,G,H,A,B,C,D,k[12],W[12]); \
	ROUND_A(D,E,F,G,H,A,B,C,k[13],W[13]); \
	ROUND_A(C,D,E,F,G,H,A,B,k[14],W[14]); \
	ROUND_A(B,C,D,E,F,G,H,A,k[15],W[15]); \
	SHA256_16to63(A,B,C,D,E,F,G,H,W)

//W[9]-W[14] are zeros
#define SHA256_ZEROS(A,B,C,D,E,F,G,H,W)	  \
	ROUND_A(A,B,C,D,E,F,G,H,k[0],W[0]); \
	ROUND_A(H,A,B,C,D,E,F,G,k[1],W[1]); \
	ROUND_A(G,H,A,B,C,D,E,F,k[2],W[2]); \
	ROUND_A(F,G,H,A,B,C,D,E,k[3],W[3]); \
	ROUND_A(E,F,G,H,A,B,C,D,k[4],W[4]); \
	ROUND_A(D,E,F,G,H,A,B,C,k[5],W[5]); \
	ROUND_A(C,D,E,F,G,H,A,B,k[6],W[6]); \
	ROUND_A(B,C,D,E,F,G,H,A,k[7],W[7]); \
	ROUND_A(A,B,C,D,E,F,G,H,k[8],W[8]); \
	ROUND_Z(H,A,B,C,D,E,F,G,k[9]); \
	ROUND_Z(G,H,A,B,C,D,E,F,k[10]); \
	ROUND_Z(F,G,H,A,B,C,D,E,k[11]); \
	ROUND_Z(E,F,G,H,A,B,C,D,k[12]); \
	ROUND_Z(D,E,F,G,H,A,B,C,k[13]); \
	ROUND_Z(C,D,E,F,G,H,A,B,k[14]); \
	ROUND_A(B,C,D,E,F,G,H,A,k[15],W[15]); \
	ROUND_I(A,B,C,D,E,F,G,H,k[16],W[0],  0,W[1],W[0],0) \
	ROUND_J(H,A,B,C,D,E,F,G,k[17],W[1],  W[15],W[2],W[1],0) \
	ROUND_J(G,H,A,B,C,D,E,F,k[18],W[2],  W[0],W[3],W[2],0) \
	ROUND_J(F,G,H,A,B,C,D,E,k[19],W[3],  W[1],W[4],W[3],0) \
	ROUND_J(E,F,G,H,A,B,C,D,k[20],W[4],  W[2],W[5],W[4],0) \
	ROUND_J(D,E,F,G,H,A,B,C,k[21],W[5],  W[3],W[6],W[5],0) \
	ROUND_B(C,D,E,F,G,H,A,B,k[22],W[6],  W[4],W[7],W[6],W[15]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[23],W[7],  W[5],W[8],W[7],W[0]) \
	ROUND_K(A,B,C,D,E,F,G,H,k[24],W[8],  W[6],0,W[8],W[1]) \
	ROUND_L(H,A,B,C,D,E,F,G,k[25],W[9],  W[7],0,0,W[2]) \
	ROUND_L(G,H,A,B,C,D,E,F,k[26],W[10],  W[8],0,0,W[3]) \
	ROUND_L(F,G,H,A,B,C,D,E,k[27],W[11],  W[9],0,0,W[4]) \
	ROUND_L(E,F,G,H,A,B,C,D,k[28],W[12],  W[10],0,0,W[5]) \
	ROUND_L(D,E,F,G,H,A,B,C,k[29],W[13],  W[11],0,0,W[6]) \
	ROUND_M(C,D,E,F,G,H,A,B,k[30],W[14],  W[12],W[15],0,W[7]) \
	ROUND_B(B,C,D,E,F,G,H,A,k[31],W[15],  W[13],W[0],W[15],W[8]) \
	SHA256_32to63(A,B,C,D,E,F,G,H,W)

#define sha256_init(ctx)	  \
	{ \
		uint i; \
		for (i = 0; i < 8; i++) \
			(ctx)[i] = h[i]; \
	}

#define sha256_block(pad, ctx)\
 {	  \
	uint A, B, C, D, E, F, G, H, t; \
	A = (ctx)[0]; \
	B = (ctx)[1]; \
	C = (ctx)[2]; \
	D = (ctx)[3]; \
	E = (ctx)[4]; \
	F = (ctx)[5]; \
	G = (ctx)[6]; \
	H = (ctx)[7]; \
	SHA256(A,B,C,D,E,F,G,H,pad); \
	(ctx)[0] += A; \
	(ctx)[1] += B; \
	(ctx)[2] += C; \
	(ctx)[3] += D; \
	(ctx)[4] += E; \
	(ctx)[5] += F; \
	(ctx)[6] += G; \
	(ctx)[7] += H; \
}

#define sha256_block_zeros(pad, ctx)\
 {	  \
	uint A, B, C, D, E, F, G, H, t; \
	A = (ctx)[0]; \
	B = (ctx)[1]; \
	C = (ctx)[2]; \
	D = (ctx)[3]; \
	E = (ctx)[4]; \
	F = (ctx)[5]; \
	G = (ctx)[6]; \
	H = (ctx)[7]; \
	SHA256_ZEROS(A,B,C,D,E,F,G,H,pad); \
	(ctx)[0] += A; \
	(ctx)[1] += B; \
	(ctx)[2] += C; \
	(ctx)[3] += D; \
	(ctx)[4] += E; \
	(ctx)[5] += F; \
	(ctx)[6] += G; \
	(ctx)[7] += H; \
}

#define sha256_single_zeros(pad, ctx)\
 {	  \
	uint A, B, C, D, E, F, G, H, t; \
	A = h[0]; \
	B = h[1]; \
	C = h[2]; \
	D = h[3]; \
	E = h[4]; \
	F = h[5]; \
	G = h[6]; \
	H = h[7]; \
	SHA256_ZEROS(A,B,C,D,E,F,G,H,pad); \
	(ctx)[0] = h[0] + A; \
	(ctx)[1] = h[1] + B; \
	(ctx)[2] = h[2] + C; \
	(ctx)[3] = h[3] + D; \
	(ctx)[4] = h[4] + E; \
	(ctx)[5] = h[5] + F; \
	(ctx)[6] = h[6] + G; \
	(ctx)[7] = h[7] + H; \
}