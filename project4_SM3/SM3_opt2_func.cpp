#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <chrono>
using namespace std;

typedef uint32_t u32;
typedef uint8_t u8;
typedef uint64_t u64;

u32 T[64];

void init_T() {
    for (int i = 0; i < 64; ++i)
        T[i] = (i < 16) ? 0x79CC4519 : 0x7A879D8A;
}

inline u32 left_rotate(u32 x, u32 n) {
    return (x << n) | (x >> (32 - n));
}

inline u32 P0(u32 x) {
    return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
}

inline u32 P1(u32 x) {
    return x ^ left_rotate(x, 15) ^ left_rotate(x, 23);
}

#define FF(j, x, y, z) ((j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z)))
#define GG(j, x, y, z) ((j < 16) ? (x ^ y ^ z) : ((x & y) | ((~x) & z)))

void compression(u32* V, const u8* block) {
    u32 W[68], W1[64];

    // ÏûÏ¢À©Õ¹
    for (int i = 0; i < 16; ++i)
        W[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) | (block[4 * i + 2] << 8) | block[4 * i + 3];

    for (int i = 16; i < 68; ++i) {
        u32 tmp = W[i - 16] ^ W[i - 9] ^ left_rotate(W[i - 3], 15);
        W[i] = P1(tmp) ^ left_rotate(W[i - 13], 7) ^ W[i - 6];
    }

    for (int i = 0; i < 64; ++i)
        W1[i] = W[i] ^ W[i + 4];

    u32 A = V[0], Bv = V[1], C = V[2], D = V[3];
    u32 E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; ++j) {
        u32 SS1 = left_rotate((left_rotate(A, 12) + E + left_rotate(T[j], j % 32)) & 0xFFFFFFFF, 7);
        u32 SS2 = SS1 ^ left_rotate(A, 12);
        u32 TT1 = (FF(j, A, Bv, C) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        u32 TT2 = (GG(j, E, F, G) + H + SS1 + W[j]) & 0xFFFFFFFF;

        D = C;
        C = left_rotate(Bv, 9);
        Bv = A;
        A = TT1;
        H = G;
        G = left_rotate(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= Bv; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

void sm3(const u8* msg, size_t len, u8* hash) {
    u64 total_len = len * 8;
    size_t padded_len = ((len + 9 + 63) / 64) * 64;
    vector<u8> M(padded_len, 0);
    memcpy(M.data(), msg, len);
    M[len] = 0x80;

    for (int i = 0; i < 8; ++i)
        M[padded_len - 1 - i] = (u8)(total_len >> (i * 8));

    u32 V[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };
    init_T();

    for (size_t i = 0; i < padded_len; i += 64)
        compression(V, M.data() + i);

    for (int i = 0; i < 8; ++i) {
        hash[4 * i] = V[i] >> 24;
        hash[4 * i + 1] = V[i] >> 16;
        hash[4 * i + 2] = V[i] >> 8;
        hash[4 * i + 3] = V[i];
    }
}

int main() {
    const char* input = "abc";
    u8 hash[32];

    auto start = chrono::high_resolution_clock::now();
    sm3((const u8*)input, strlen(input), hash);
    auto end = chrono::high_resolution_clock::now();

    cout << "SM3(\"" << input << "\") = ";
    for (int i = 0; i < 32; ++i)
        cout << hex << setw(2) << setfill('0') << (int)hash[i];
    cout << endl;

    chrono::duration<double> duration = end - start;
    cout << "Time: " << duration.count() * 1000 << " ms" << endl;

    return 0;
}
