
#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>
#include "config.h"

#define SHA256_DIGEST_SIZE (256 / 8)
#define SHA256_BLOCK_SIZE  (512 / 8)

#define SHFR(x, n)	(x >> n)
#define ROTR(x, n)	((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define CH(x, y, z)   ((x & y) ^ (~x & z))
#define MAJ(x, y, z)  ((x & y) ^ (x & z) ^ (y & z))

#define SHA256_F1(x)  (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SHA256_F2(x)  (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SHA256_F3(x)  (ROTR(x,  7) ^ ROTR(x, 18) ^ SHFR(x,  3))
#define SHA256_F4(x)  (ROTR(x, 17) ^ ROTR(x, 19) ^ SHFR(x, 10))

typedef struct {
	union {
		struct {
			void *evp_ctx;
			uint8_t _evp_padding[64];
		};

		struct {
			unsigned int tot_len;
			unsigned int len;
			unsigned char block[2 * SHA256_BLOCK_SIZE];
			uint32_t h[8];
		};
	};
	int use_sha_ni; // 1 = use SHA-NI, 0 = use OpenSSL
} sha256_ctx;

extern const uint32_t sha256_k[64];
extern const uint32_t sha256_h0[8];

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *message, unsigned int len);
void sha256_final(sha256_ctx *ctx, unsigned char *digest);
void sha256(const unsigned char *message, unsigned int len, unsigned char *digest);
void sha256_transf(sha256_ctx *ctx, const unsigned char *message, unsigned int block_nb);

#endif /* SHA2_H */
