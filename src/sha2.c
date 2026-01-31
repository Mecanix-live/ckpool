/*
 * SHA-256 Implementation with Hardware Acceleration
 * ================================================
 *
 * This module provides two optimized SHA-256 implementations:
 *
 * 1. SHA-NI (SHA New Instructions) Hardware Accelerated
 *	- Uses Intel SHA Extensions (available since Intel Goldmont in 2016,
 *	  mainstream since Ice Lake 2019).
 *	- AMD support since Zen microarchitecture (2017).
 *	- Delivers ~3-5x faster performance than software implementations.
 *
 * 2. OpenSSL EVP (Optimized Software Fallback)
 *	- Uses OpenSSL's heavily optimized implementation.
 *	- Includes assembly optimizations for x86, ARM, and other platforms.
 *	- Provides constant-time execution to prevent timing attacks.
 *	- Used when SHA-NI is not available.
 *
 * The implementation automatically selects the best available method at runtime.
 * For maximum performance, ensure your CPU supports SHA-NI instructions!!
 *
 *  Created on: Jul 6, 2025
 *	  Author: mecanix
 */

#include "sha2.h"
#include <string.h>
#include <openssl/evp.h>

#if defined(__x86_64__) || defined(__i386__)
#include <immintrin.h>
#include <cpuid.h>

static int supports_sha_ni() {
    unsigned int eax, ebx, ecx, edx;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1 << 29)); // SHA-NI bit
}
#endif

const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const uint32_t sha256_h0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

//typedef struct {
//    union {
//        sha256_ctx native_ctx;
//        EVP_MD_CTX *evp_ctx;
//    };
//    int use_sha_ni;
//} sha256_runtime_ctx;


#if defined(__x86_64__) || defined(__i386__)

	void sha256_transf(sha256_ctx *ctx, const unsigned char *message, unsigned int block_nb) {

		// SHA-NI
		__m128i state0, state1;
		__m128i msg, tmp;
		__m128i tmsg0, tmsg1, tmsg2, tmsg3;
		__m128i abef_save, cdgh_save;
		const __m128i mask = _mm_set_epi64x(0x0c0d0e0f08090a0bull, 0x0405060700010203ull);

		tmp = _mm_set_epi32(ctx->h[3], ctx->h[2], ctx->h[1], ctx->h[0]);
		state1 = _mm_set_epi32(ctx->h[7], ctx->h[6], ctx->h[5], ctx->h[4]);

		tmp = _mm_shuffle_epi32(tmp, 0xb1);
		state1 = _mm_shuffle_epi32(state1, 0x1b);
		state0 = _mm_alignr_epi8(tmp, state1, 8);
		state1 = _mm_blend_epi16(state1, tmp, 0xf0);

		const __m128i *input = (const __m128i*)message;

		while (block_nb--) {

			abef_save = state0;
			cdgh_save = state1;

			msg = _mm_loadu_si128(input + 0);
			tmsg0 = _mm_shuffle_epi8(msg, mask);
			msg = _mm_add_epi32(tmsg0, _mm_set_epi64x(0xe9b5dba5b5c0fbcfull, 0x71374491428a2f98ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

			tmsg1 = _mm_loadu_si128(input + 1);
			tmsg1 = _mm_shuffle_epi8(tmsg1, mask);
			msg = _mm_add_epi32(tmsg1, _mm_set_epi64x(0xab1c5ed5923f82a4ull, 0x59f111f13956c25bull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg0 = _mm_sha256msg1_epu32(tmsg0, tmsg1);

			tmsg2 = _mm_loadu_si128(input + 2);
			tmsg2 = _mm_shuffle_epi8(tmsg2, mask);
			msg = _mm_add_epi32(tmsg2, _mm_set_epi64x(0x550c7dc3243185beull, 0x12835b01d807aa98ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg1 = _mm_sha256msg1_epu32(tmsg1, tmsg2);

			tmsg3 = _mm_loadu_si128(input + 3);
			tmsg3 = _mm_shuffle_epi8(tmsg3, mask);
			msg = _mm_add_epi32(tmsg3, _mm_set_epi64x(0xc19bf1749bdc06a7ull, 0x80deb1fe72be5d74ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg3, tmsg2, 4);
			tmsg0 = _mm_add_epi32(tmsg0, tmp);
			tmsg0 = _mm_sha256msg2_epu32(tmsg0, tmsg3);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg2 = _mm_sha256msg1_epu32(tmsg2, tmsg3);

			msg = _mm_add_epi32(tmsg0, _mm_set_epi64x(0x240ca1cc0fc19dc6ull, 0xefbe4786e49b69c1ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg0, tmsg3, 4);
			tmsg1 = _mm_add_epi32(tmsg1, tmp);
			tmsg1 = _mm_sha256msg2_epu32(tmsg1, tmsg0);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg3 = _mm_sha256msg1_epu32(tmsg3, tmsg0);

			msg = _mm_add_epi32(tmsg1, _mm_set_epi64x(0x76f988da5cb0a9dcull, 0x4a7484aa2de92c6full));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg1, tmsg0, 4);
			tmsg2 = _mm_add_epi32(tmsg2, tmp);
			tmsg2 = _mm_sha256msg2_epu32(tmsg2, tmsg1);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg0 = _mm_sha256msg1_epu32(tmsg0, tmsg1);

			msg = _mm_add_epi32(tmsg2, _mm_set_epi64x(0xbf597fc7b00327c8ull, 0xa831c66d983e5152ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg2, tmsg1, 4);
			tmsg3 = _mm_add_epi32(tmsg3, tmp);
			tmsg3 = _mm_sha256msg2_epu32(tmsg3, tmsg2);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg1 = _mm_sha256msg1_epu32(tmsg1, tmsg2);

			msg = _mm_add_epi32(tmsg3, _mm_set_epi64x(0x1429296706ca6351ull, 0xd5a79147c6e00bf3ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg3, tmsg2, 4);
			tmsg0 = _mm_add_epi32(tmsg0, tmp);
			tmsg0 = _mm_sha256msg2_epu32(tmsg0, tmsg3);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg2 = _mm_sha256msg1_epu32(tmsg2, tmsg3);

			msg = _mm_add_epi32(tmsg0, _mm_set_epi64x(0x53380d134d2c6dfcull, 0x2e1b213827b70a85ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg0, tmsg3, 4);
			tmsg1 = _mm_add_epi32(tmsg1, tmp);
			tmsg1 = _mm_sha256msg2_epu32(tmsg1, tmsg0);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg3 = _mm_sha256msg1_epu32(tmsg3, tmsg0);

			msg = _mm_add_epi32(tmsg1, _mm_set_epi64x(0x92722c8581c2c92eull, 0x766a0abb650a7354ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg1, tmsg0, 4);
			tmsg2 = _mm_add_epi32(tmsg2, tmp);
			tmsg2 = _mm_sha256msg2_epu32(tmsg2, tmsg1);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg0 = _mm_sha256msg1_epu32(tmsg0, tmsg1);

			msg = _mm_add_epi32(tmsg2, _mm_set_epi64x(0xc76c51a3c24b8b70ull, 0xa81a664ba2bfe8a1ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg2, tmsg1, 4);
			tmsg3 = _mm_add_epi32(tmsg3, tmp);
			tmsg3 = _mm_sha256msg2_epu32(tmsg3, tmsg2);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg1 = _mm_sha256msg1_epu32(tmsg1, tmsg2);

			msg = _mm_add_epi32(tmsg3, _mm_set_epi64x(0x106aa070f40e3585ull, 0xd6990624d192e819ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg3, tmsg2, 4);
			tmsg0 = _mm_add_epi32(tmsg0, tmp);
			tmsg0 = _mm_sha256msg2_epu32(tmsg0, tmsg3);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg2 = _mm_sha256msg1_epu32(tmsg2, tmsg3);

			msg = _mm_add_epi32(tmsg0, _mm_set_epi64x(0x34b0bcb52748774cull, 0x1e376c0819a4c116ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg0, tmsg3, 4);
			tmsg1 = _mm_add_epi32(tmsg1, tmp);
			tmsg1 = _mm_sha256msg2_epu32(tmsg1, tmsg0);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
			tmsg3 = _mm_sha256msg1_epu32(tmsg3, tmsg0);

			msg = _mm_add_epi32(tmsg1, _mm_set_epi64x(0x682e6ff35b9cca4full, 0x4ed8aa4a391c0cb3ull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg1, tmsg0, 4);
			tmsg2 = _mm_add_epi32(tmsg2, tmp);
			tmsg2 = _mm_sha256msg2_epu32(tmsg2, tmsg1);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

			msg = _mm_add_epi32(tmsg2, _mm_set_epi64x(0x8cc7020884c87814ull, 0x78a5636f748f82eeull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			tmp = _mm_alignr_epi8(tmsg2, tmsg1, 4);
			tmsg3 = _mm_add_epi32(tmsg3, tmp);
			tmsg3 = _mm_sha256msg2_epu32(tmsg3, tmsg2);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

			msg = _mm_add_epi32(tmsg3, _mm_set_epi64x(0xc67178f2bef9a3f7ull, 0xa4506ceb90befffaull));
			state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
			msg = _mm_shuffle_epi32(msg, 0x0e);
			state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

			state0 = _mm_add_epi32(state0, abef_save);
			state1 = _mm_add_epi32(state1, cdgh_save);

			input += 4;
		}

		tmp = _mm_shuffle_epi32(state0, 0x1b);
		state1 = _mm_shuffle_epi32(state1, 0xb1);
		state0 = _mm_blend_epi16(tmp, state1, 0xf0);
		state1 = _mm_alignr_epi8(state1, tmp, 8);

		ctx->h[0] = _mm_extract_epi32(state0, 0);
		ctx->h[1] = _mm_extract_epi32(state0, 1);
		ctx->h[2] = _mm_extract_epi32(state0, 2);
		ctx->h[3] = _mm_extract_epi32(state0, 3);
		ctx->h[4] = _mm_extract_epi32(state1, 0);
		ctx->h[5] = _mm_extract_epi32(state1, 1);
		ctx->h[6] = _mm_extract_epi32(state1, 2);
		ctx->h[7] = _mm_extract_epi32(state1, 3);
	}
#endif


void sha256_init(sha256_ctx *ctx) {
#if defined(__x86_64__) || defined(__i386__)
	if (supports_sha_ni()) {
		// Use the native part of the union
		memcpy(&ctx->h, sha256_h0, sizeof(sha256_h0));
		ctx->len = 0;
		ctx->tot_len = 0;
		ctx->use_sha_ni = 1;  // Use the new field
		return;
	}
#endif

	// Use OpenSSL
	ctx->evp_ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx->evp_ctx, EVP_sha256(), NULL);
	ctx->use_sha_ni = 0;  // Use the new field
}

void sha256_update(sha256_ctx *ctx, const unsigned char *message, unsigned int len) {
	if (ctx->use_sha_ni) {  // Use the new field
#if defined(__x86_64__) || defined(__i386__)
		// SHA-NI implementation
		unsigned int block_nb;
		unsigned int new_len, rem_len, tmp_len;
		const unsigned char *shifted_message;

		tmp_len = 64 - ctx->len;
		rem_len = len < tmp_len ? len : tmp_len;

		memcpy(&ctx->block[ctx->len], message, rem_len);

		if (ctx->len + len < 64) {
			ctx->len += len;
			return;
		}

		new_len = len - rem_len;
		block_nb = new_len / 64;
		shifted_message = message + rem_len;

		sha256_transf(ctx, ctx->block, 1);
		sha256_transf(ctx, shifted_message, block_nb);

		rem_len = new_len % 64;
		memcpy(ctx->block, &shifted_message[block_nb * 64], rem_len);

		ctx->len = rem_len;
		ctx->tot_len += (block_nb + 1) * 64;
#endif
	} else {
		// OpenSSL implementation
		EVP_DigestUpdate(ctx->evp_ctx, message, len);
	}
}

void sha256_final(sha256_ctx *ctx, unsigned char *digest) {
	if (ctx->use_sha_ni) {  // Use the new field
#if defined(__x86_64__) || defined(__i386__)
		// SHA-NI finalization
		unsigned int block_nb;
		unsigned int pm_len;
		uint64_t len_bits;

		block_nb = (1 + ((64 - 9) < (ctx->len % 64)));
		pm_len = block_nb * 64;

		memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
		ctx->block[ctx->len] = 0x80;

		len_bits = ((uint64_t)ctx->tot_len + ctx->len) * 8;
		for (int i = 0; i < 8; i++) {
			ctx->block[pm_len - 8 + i] = (len_bits >> (56 - i*8)) & 0xff;
		}

		sha256_transf(ctx, ctx->block, block_nb);

		for (int i = 0; i < 8; i++) {
			digest[i*4+0] = (ctx->h[i] >> 24) & 0xff;
			digest[i*4+1] = (ctx->h[i] >> 16) & 0xff;
			digest[i*4+2] = (ctx->h[i] >> 8) & 0xff;
			digest[i*4+3] = ctx->h[i] & 0xff;
		}
#endif
	} else {
		// OpenSSL finalization
		unsigned int digest_len;
		EVP_DigestFinal_ex(ctx->evp_ctx, digest, &digest_len);
		EVP_MD_CTX_free(ctx->evp_ctx);
	}
}

void sha256(const unsigned char *message, unsigned int len, unsigned char *digest) {
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, message, len);
	sha256_final(&ctx, digest);
}
