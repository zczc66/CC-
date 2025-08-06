#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>
#include <chrono>
#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>
using namespace std;
#define MAX_LEN (2 << 12)
#define rol(x,j) (((x) << (j)) | ((x) >> (32-(j))))
#define P0(x) ((x) ^ rol((x), 9) ^ rol((x), 17))
#define P1(x) ((x) ^ rol((x), 15) ^ rol((x), 23))
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

static inline __m128i _m128i_left(__m128i a, int k) {
    k &= 31;
    return _mm_or_si128(_mm_slli_epi32(a, k), _mm_srli_epi32(a, 32 - k));
}

static inline __m128i _m128i_P1_simd(__m128i X) {
    return _mm_xor_si128(_mm_xor_si128(X, _m128i_left(X, 15)), _m128i_left(X, 23));
}

static inline uint32_t byte_swap32(uint32_t x) {
    return ((x & 0xff000000) >> 24) |
        ((x & 0x00ff0000) >> 8) |
        ((x & 0x0000ff00) << 8) |
        ((x & 0x000000ff) << 24);
}

#define UNROLL_LOOP_16_0(STATEMENT) \
    STATEMENT(0);  STATEMENT(1);  STATEMENT(2);  STATEMENT(3); \
    STATEMENT(4);  STATEMENT(5);  STATEMENT(6);  STATEMENT(7); \
    STATEMENT(8);  STATEMENT(9);  STATEMENT(10); STATEMENT(11); \
    STATEMENT(12); STATEMENT(13); STATEMENT(14); STATEMENT(15);

#define UNROLL_LOOP_4_16(STATEMENT) \
    STATEMENT(4); STATEMENT(5); STATEMENT(6); STATEMENT(7); \
    STATEMENT(8); STATEMENT(9); STATEMENT(10); STATEMENT(11); \
    STATEMENT(12); STATEMENT(13); STATEMENT(14); STATEMENT(15); \
    STATEMENT(16);

#define BYTE_SWAP_W(i) W[i] = byte_swap32(BB[i]);

#define UPDATE_W(j) \
    do { \
        W[(j << 2)] = P1(W[(j << 2) - 16] ^ W[(j << 2) - 9] ^ rol(W[(j << 2) - 3], 15)) \
            ^ rol(W[(j << 2) - 13], 7) ^ W[(j << 2) - 6]; \
        w16 = _mm_setr_epi32(W[(j << 2) - 16], W[(j << 2) - 15], W[(j << 2) - 14], W[(j << 2) - 13]); \
        w9  = _mm_setr_epi32(W[(j << 2) - 9],  W[(j << 2) - 8],  W[(j << 2) - 7],  W[(j << 2) - 6]); \
        w13 = _mm_setr_epi32(W[(j << 2) - 13], W[(j << 2) - 12], W[(j << 2) - 11], W[(j << 2) - 10]); \
        w3  = _mm_setr_epi32(W[(j << 2) - 3],  W[(j << 2) - 2],  W[(j << 2) - 1],  W[(j << 2)]); \
        w6  = _mm_setr_epi32(W[(j << 2) - 6],  W[(j << 2) - 5],  W[(j << 2) - 4],  W[(j << 2) - 3]); \
        w16_or_w9 = _mm_xor_si128(w16, w9); \
        rsl_w3 = _m128i_left(w3, 15); \
        rsl_w13 = _m128i_left(w13, 7); \
        w16_or_w9_or_rsl_w3 = _mm_xor_si128(w16_or_w9, rsl_w3); \
        rsl_w13_or_w6 = _mm_xor_si128(rsl_w13, w6); \
        P = _m128i_P1_simd(w16_or_w9_or_rsl_w3); \
        re = _mm_xor_si128(P, rsl_w13_or_w6); \
        memcpy(&W[(j << 2)], &re, 16); \
    } while (0)

uint32_t IV[8] = {
    0x7380166f,
    0x4914b2b9,
    0x172442d7,
    0xda8a0600,
    0xa96f30bc,
    0x163138aa,
    0xe38dee4d,
    0xb0fb0e4e
};

char plaintext_after_stuffing[MAX_LEN] = { 0 };

uint32_t bit_stuffing(uint8_t* plaintext, size_t len) {
    uint64_t bit_len = len * 8;
    uint32_t k = ((bit_len % 512) < 448) ? 1 : 2;
    uint32_t final_len = (((len >> 6) + k) << 6);

    memcpy(plaintext_after_stuffing, plaintext, len);
    plaintext_after_stuffing[len] = 0x80;

    for (uint32_t i = len + 1; i + 8 <= final_len; i += 8) {
        *(uint64_t*)(plaintext_after_stuffing + i) = 0;
    }

    uint64_t bit_len_be = __builtin_bswap64(bit_len);
    memcpy(plaintext_after_stuffing + final_len - 8, &bit_len_be, 8);

    return final_len;
}

void CF_for_simd(uint32_t* V, const uint32_t* BB) {  // 改参数类型
    uint32_t W[68];
    uint32_t W_t[64];
    __m128i w16, w9, w13, w3, w6, w16_or_w9, rsl_w3, rsl_w13, w16_or_w9_or_rsl_w3, rsl_w13_or_w6, P, re;
    uint32_t temp, SS1, SS2, TT1, TT2;

    UNROLL_LOOP_16_0(BYTE_SWAP_W);
    UNROLL_LOOP_4_16(UPDATE_W);

    for (int i = 0; i < 64; i++) {
        W_t[i] = W[i] ^ W[i + 4];
    }

    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t T = (j < 16) ? 0x79cc4519 : 0x7a879d8a;
        temp = rol(A, 12) + E + rol(T, j);
        SS1 = rol(temp, 7);
        SS2 = SS1 ^ rol(A, 12);
        if (j < 16) {
            TT1 = FF0(A, B, C) + D + SS2 + W_t[j];
            TT2 = GG0(E, F, G) + H + SS1 + W[j];
        }
        else {
            TT1 = FF1(A, B, C) + D + SS2 + W_t[j];
            TT2 = GG1(E, F, G) + H + SS1 + W[j];
        }
        D = C;
        C = rol(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rol(F, 19);
        F = E;
        E = P0(TT2);
    }

    for (int i = 0; i < 8; i++) {
        V[i] ^= (i == 0) ? A : (i == 1) ? B : (i == 2) ? C : (i == 3) ? D :
            (i == 4) ? E : (i == 5) ? F : (i == 6) ? G : H;
    }
}

void sm3_simd(uint8_t* plaintext, uint32_t* hash_val, size_t len) {
    uint32_t padded_len = bit_stuffing(plaintext, len);
    uint32_t V[8];
    memcpy(V, IV, sizeof(IV));

    for (uint32_t i = 0; i < padded_len; i += 64) {
        CF_for_simd(V, (uint32_t*)(plaintext_after_stuffing + i));
    }

    for (int i = 0; i < 8; i++) {
        hash_val[i] = byte_swap32(V[i]);
    }
}

static void dump_buf(uint8_t* hash, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    uint8_t plaintext[MAX_LEN] = "abc";
    uint32_t hash_val[8];
    auto start = chrono::high_resolution_clock::now();
    sm3_simd(plaintext, hash_val, strlen((char*)plaintext));
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double, milli> duration = end - start;
    dump_buf((uint8_t*)hash_val, 32);
    cout << "Time taken: " << duration.count() << " ms" << endl;

    return 0;
}
