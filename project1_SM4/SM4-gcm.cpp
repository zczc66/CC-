#include <iostream>
#include <cstring>
#include <vector>
#include <cstdint>
#include<chrono>
using namespace std;


static const unsigned long SboxTable[16][16] = {
    {0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
    {0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
    {0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
    {0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
    {0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
    {0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
    {0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
    {0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
    {0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
    {0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
    {0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
    {0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
    {0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
    {0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
    {0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
    {0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
};

unsigned long sm4Sbox(unsigned long in) {
    return SboxTable[(in >> 4) & 0x0F][in & 0x0F];
}

inline unsigned long L(unsigned long x) {
    return x ^ ((x << 2) | (x >> (32 - 2)))
        ^ ((x << 10) | (x >> (32 - 10)))
        ^ ((x << 18) | (x >> (32 - 18)))
        ^ ((x << 24) | (x >> (32 - 24)));
}


unsigned long T(unsigned long x) {
    unsigned long b = 0;
    for (int i = 0; i < 4; i++) {
        b = (b << 8) | sm4Sbox((x >> ((3 - i) * 8)) & 0xFF);
    }
    return L(b);
}

static const unsigned long FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

static const unsigned long CK[32] = {
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

void key_expansion(unsigned long MK[4], unsigned long rk[32]) {
    unsigned long K[36];
    for (int i = 0; i < 4; i++)
        K[i] = MK[i] ^ FK[i];
    for (int i = 0; i < 32; i++) {
        unsigned long tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        unsigned long b = 0;
        for (int j = 0; j < 4; j++)
            b = (b << 8) | sm4Sbox((tmp >> ((3 - j) * 8)) & 0xFF);
        unsigned long L_ = b ^ (b << 13 | b >> (32 - 13)) ^ (b << 23 | b >> (32 - 23));
        rk[i] = K[i] ^ L_;
        K[i + 4] = rk[i];
    }
}

void sm4_encrypt_block(const uint8_t input[16], const uint8_t key[16], uint8_t output[16]) {
    unsigned long X[36], rk[32], MK[4];
    for (int i = 0; i < 4; i++)
        MK[i] = ((uint32_t)key[i * 4] << 24) | ((uint32_t)key[i * 4 + 1] << 16) |
        ((uint32_t)key[i * 4 + 2] << 8) | key[i * 4 + 3];
    key_expansion(MK, rk);
    for (int i = 0; i < 4; i++)
        X[i] = ((uint32_t)input[i * 4] << 24) | ((uint32_t)input[i * 4 + 1] << 16) |
        ((uint32_t)input[i * 4 + 2] << 8) | input[i * 4 + 3];
    for (int i = 0; i < 32; i++)
        X[i + 4] = X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
    for (int i = 0; i < 4; i++) {
        output[i * 4] = (X[35 - i] >> 24) & 0xFF;
        output[i * 4 + 1] = (X[35 - i] >> 16) & 0xFF;
        output[i * 4 + 2] = (X[35 - i] >> 8) & 0xFF;
        output[i * 4 + 3] = X[35 - i] & 0xFF;
    }
}

// CTR 模式加解密
void increment_counter(uint8_t counter[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++counter[i]) break;
    }
}

void sm4_ctr_crypt(const uint8_t key[16], uint8_t counter[16], const uint8_t* input, uint8_t* output, size_t length) {
    uint8_t block[16];
    size_t blocks = (length + 15) / 16;
    for (size_t i = 0; i < blocks; ++i) {
        sm4_encrypt_block(counter, key, block);
        size_t offset = i * 16;
        size_t block_len = std::min(size_t(16), length - offset);
        for (size_t j = 0; j < block_len; ++j)
            output[offset + j] = input[offset + j] ^ block[j];
        increment_counter(counter);
    }
}


void galois_multiply(uint8_t* X, const uint8_t* Y) {
    uint8_t Z[16] = { 0 };
    uint8_t V[16];
    memcpy(V, Y, 16);

    for (int i = 0; i < 128; ++i) {
        int bit = (X[i / 8] >> (7 - (i % 8))) & 1;
        if (bit)
            for (int j = 0; j < 16; ++j) Z[j] ^= V[j];

        uint8_t lsb = V[15] & 1;
        for (int j = 15; j > 0; --j) V[j] = (V[j] >> 1) | ((V[j - 1] & 1) << 7);
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xe1;
    }
    memcpy(X, Z, 16);
}

void ghash(const uint8_t H[16], const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len, uint8_t tag[16]) {
    uint8_t Y[16] = { 0 };

    for (size_t i = 0; i < aad_len; i += 16) {
        uint8_t block[16] = { 0 };
        size_t len = std::min(size_t(16), aad_len - i);
        memcpy(block, aad + i, len);
        for (int j = 0; j < 16; ++j) Y[j] ^= block[j];
        galois_multiply(Y, H);
    }

    for (size_t i = 0; i < ct_len; i += 16) {
        uint8_t block[16] = { 0 };
        size_t len = std::min(size_t(16), ct_len - i);
        memcpy(block, ciphertext + i, len);
        for (int j = 0; j < 16; ++j) Y[j] ^= block[j];
        galois_multiply(Y, H);
    }

    uint8_t len_block[16] = { 0 };
    uint64_t aad_bits = aad_len * 8;
    uint64_t ct_bits = ct_len * 8;
    for (int i = 0; i < 8; ++i) len_block[7 - i] = (aad_bits >> (i * 8)) & 0xFF;
    for (int i = 0; i < 8; ++i) len_block[15 - i] = (ct_bits >> (i * 8)) & 0xFF;

    for (int j = 0; j < 16; ++j) Y[j] ^= len_block[j];
    galois_multiply(Y, H);
    memcpy(tag, Y, 16);
}


// SM4-GCM
void sm4_gcm_encrypt(const uint8_t key[16], const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext, uint8_t tag[16]) {
    uint8_t counter[16] = { 0 };
    memcpy(counter, iv, 12);
    counter[15] = 1;

    sm4_ctr_crypt(key, counter, plaintext, ciphertext, pt_len);

    uint8_t H[16] = { 0 }, J0[16] = { 0 }, S[16];
    sm4_encrypt_block(H, key, H);
    memcpy(J0, iv, 12); J0[15] = 1;
    ghash(H, aad, aad_len, ciphertext, pt_len, S);

    uint8_t E_J0[16];
    sm4_encrypt_block(J0, key, E_J0);
    for (int i = 0; i < 16; ++i) tag[i] = S[i] ^ E_J0[i];
}

bool sm4_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[16], uint8_t* plaintext) {
    uint8_t counter[16] = { 0 };
    memcpy(counter, iv, 12);
    counter[15] = 1;

    sm4_ctr_crypt(key, counter, ciphertext, plaintext, ct_len);

    uint8_t H[16] = { 0 }, J0[16] = { 0 }, S[16];
    sm4_encrypt_block(H, key, H);
    memcpy(J0, iv, 12); J0[15] = 1;
    ghash(H, aad, aad_len, ciphertext, ct_len, S);

    uint8_t E_J0[16], T[16];
    sm4_encrypt_block(J0, key, E_J0);
    for (int i = 0; i < 16; ++i) T[i] = S[i] ^ E_J0[i];

    return memcmp(T, tag, 16) == 0;
}

int main() {
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98,
        0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[12] = {
        0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef,
        0x00, 0x00, 0x00, 0x01
    };

    uint8_t aad[16] = {
        0xa1, 0xa2, 0xa3, 0xa4,
        0xa5, 0xa6, 0xa7, 0xa8,
        0xa9, 0xaa, 0xab, 0xac,
        0xad, 0xae, 0xaf, 0xb0
    };

    uint8_t plaintext[32] = {
        0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c,
        0x6d, 0x6e, 0x6f, 0x70,
        0x71, 0x72, 0x73, 0x74,
        0x75, 0x76, 0x77, 0x78,
        0x79, 0x7a, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35
    };

    uint8_t ciphertext[32] = { 0 }, decrypted[32] = { 0 }, tag[16] = { 0 };

    // 开始计时
    auto start = chrono::high_resolution_clock::now();

    sm4_gcm_encrypt(key, iv, aad, sizeof(aad), plaintext, 4, ciphertext, tag);

    // 结束计时
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::nanoseconds>(end - start).count();

    cout << "Ciphertext: ";
    for (int i = 0; i < 4; ++i) printf("%02x", ciphertext[i]);
    cout << "\nTag: ";
    for (int i = 0; i < 16; ++i) printf("%02x", tag[i]);
    cout << "\n";

    cout << "GCM encryption time: " << duration << " ns" << endl;

    bool ok = sm4_gcm_decrypt(key, iv, aad, sizeof(aad), ciphertext, 4, tag, decrypted);
    cout << (ok ? "Decryption OK" : "Decryption FAILED") << endl;

    return 0;
}
