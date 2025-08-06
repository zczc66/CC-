#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <chrono>

using namespace std;

typedef uint32_t u32;
typedef uint8_t u8;

// ------------------ 宏定义优化部分 ------------------
#define rol(x,j) (((x) << (j)) | ((x) >> (32 - (j))))
#define P0(x) ((x) ^ rol((x), 9) ^ rol((x), 17))
#define P1(x) ((x) ^ rol((x), 15) ^ rol((x), 23))
#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG0(x,y,z) ((x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x)&(y)) | ((~(x)) & (z)))
// ----------------------------------------------------

// 常量表
u32 T[64];
void init_T() {
    for (int i = 0; i < 64; ++i)
        T[i] = (i < 16) ? 0x79CC4519 : 0x7A879D8A;
}

// 将字符串转换为字节数组
vector<u8> string_to_bytes(const string& str) {
    return vector<u8>(str.begin(), str.end());
}

// 消息填充
vector<u8> message_padding(const vector<u8>& msg) {
    size_t len = msg.size() * 8;
    vector<u8> padded = msg;

    padded.push_back(0x80);
    while ((padded.size() * 8) % 512 != 448)
        padded.push_back(0x00);

    for (int i = 7; i >= 0; --i)
        padded.push_back((u8)((len >> (i * 8)) & 0xFF));

    return padded;
}

// 消息扩展
void message_expansion(const u8* block, u32 W[68], u32 W1[64]) {
    for (int i = 0; i < 16; ++i) {
        W[i] = (block[4 * i] << 24) |
            (block[4 * i + 1] << 16) |
            (block[4 * i + 2] << 8) |
            (block[4 * i + 3]);
    }

    for (int i = 16; i < 68; ++i)
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ rol(W[i - 3], 15)) ^ rol(W[i - 13], 7) ^ W[i - 6];

    for (int i = 0; i < 64; ++i)
        W1[i] = W[i] ^ W[i + 4];
}

// 压缩函数
void compression(u32 V[8], const u8* block) {
    u32 W[68], W1[64];
    message_expansion(block, W, W1);

    u32 A = V[0], B = V[1], C = V[2], D = V[3];
    u32 E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; ++j) {
        u32 SS1 = rol((rol(A, 12) + E + rol(T[j], j % 32)) & 0xFFFFFFFF, 7);
        u32 SS2 = SS1 ^ rol(A, 12);
        u32 TT1 = ((j < 16 ? FF0(A, B, C) : FF1(A, B, C)) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        u32 TT2 = ((j < 16 ? GG0(E, F, G) : GG1(E, F, G)) + H + SS1 + W[j]) & 0xFFFFFFFF;

        D = C;
        C = rol(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rol(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// 主函数
vector<u8> sm3_hash(const string& input) {
    init_T();

    u32 V[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };

    vector<u8> msg_bytes = string_to_bytes(input);
    vector<u8> padded = message_padding(msg_bytes);

    size_t block_count = padded.size() / 64;
    for (size_t i = 0; i < block_count; ++i)
        compression(V, &padded[i * 64]);

    vector<u8> hash_result;
    for (int i = 0; i < 8; ++i) {
        hash_result.push_back((V[i] >> 24) & 0xFF);
        hash_result.push_back((V[i] >> 16) & 0xFF);
        hash_result.push_back((V[i] >> 8) & 0xFF);
        hash_result.push_back(V[i] & 0xFF);
    }

    return hash_result;
}

int main() {
    string input = "abc";

    auto start = chrono::high_resolution_clock::now();

    vector<u8> hash = sm3_hash(input);

    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double, milli> duration = end - start;

    cout << "SM3(\"" << input << "\") = ";
    for (u8 byte : hash)
        cout << hex << setw(2) << setfill('0') << (int)byte;
    cout << endl;

    cout << "Time taken: " << duration.count() << " ms" << endl;

    return 0;
}
