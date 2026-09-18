// ABI on entry:
// RCX = pointer to encrypted data
// RDX = number of bytes
// R8  = pointer to 32-byte ChaCha20 key
// R9  = pointer to 12-byte nonce
// [RSP+0x28] = initial block counter 

#include <stdint.h>

static uint32_t load32(const unsigned char* p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store32(unsigned char* p, uint32_t v) {
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static uint32_t rotl32(uint32_t v, unsigned n) {
    return (v << n) | (v >> (32u - n));
}

#define QR(a, b, c, d) do { \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = rotl32((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = rotl32((b), 7);  \
} while (0)
// say dude, "duuuuuuuuuuuuuuude"
void chacha20_decrypt_runtime(unsigned char* data, unsigned long long len,
                              const unsigned char* key,
                              const unsigned char* nonce,
                              uint32_t counter) {
    static const uint32_t sigma[4] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
    };
    uint32_t state[16];
    uint32_t block[16];
    unsigned char stream[64];

    state[0] = sigma[0]; state[1] = sigma[1];
    state[2] = sigma[2]; state[3] = sigma[3];
    for (unsigned i = 0; i < 8; ++i)
        state[4 + i] = load32(key + i * 4);
    state[12] = counter;
    state[13] = load32(nonce + 0);
    state[14] = load32(nonce + 4);
    state[15] = load32(nonce + 8);

    while (len != 0) {
        for (unsigned i = 0; i < 16; ++i) block[i] = state[i];
        for (unsigned round = 0; round < 10; ++round) {
            QR(block[0], block[4], block[8],  block[12]);
            QR(block[1], block[5], block[9],  block[13]);
            QR(block[2], block[6], block[10], block[14]);
            QR(block[3], block[7], block[11], block[15]);
            QR(block[0], block[5], block[10], block[15]);
            QR(block[1], block[6], block[11], block[12]);
            QR(block[2], block[7], block[8],  block[13]);
            QR(block[3], block[4], block[9],  block[14]);
        }
        for (unsigned i = 0; i < 16; ++i)
            store32(stream + i * 4, block[i] + state[i]);

        unsigned long long take = len < 64 ? len : 64;
        for (unsigned long long i = 0; i < take; ++i)
            data[i] ^= stream[i];
        data += take;
        len -= take;
        ++state[12];
    }
}
