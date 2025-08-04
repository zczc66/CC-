#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <chrono>

using namespace std;

typedef uint32_t u32;
typedef uint8_t u8;

// 常量表

static const u32 T[64] = {
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x79CC4519,0x79CC4519,0x79CC4519,0x79CC4519,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A,
    0x7A879D8A,0x7A879D8A,0x7A879D8A,0x7A879D8A
};

// 左旋
inline u32 left_rotate(u32 x, u32 n) {
    return (x << n) | (x >> (32 - n));
}

// 置换函数
inline u32 P0(u32 x) {
    return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
}

inline u32 P1(u32 x) {
    return x ^ left_rotate(x, 15) ^ left_rotate(x, 23);
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

    for (int i = 16; i < 68; ++i) {
        u32 tmp = P1(W[i - 16] ^ W[i - 9] ^ left_rotate(W[i - 3], 15));
        W[i] = tmp ^ left_rotate(W[i - 13], 7) ^ W[i - 6];
    }

    for (int i = 0; i < 64; ++i) {
        W1[i] = W[i] ^ W[i + 4];
    }
}

// 压缩轮次宏展开
#define COMPRESS_ROUND(j, A, B, C, D, E, F, G, H, W, W1) { \
    u32 SS1 = left_rotate((left_rotate(A, 12) + E + left_rotate(T[j], j % 32)) & 0xFFFFFFFF, 7); \
    u32 SS2 = SS1 ^ left_rotate(A, 12); \
    u32 TT1 = (((j < 16) ? (A ^ B ^ C) : ((A & B) | (A & C) | (B & C))) + D + SS2 + W1[j]) & 0xFFFFFFFF; \
    u32 TT2 = (((j < 16) ? (E ^ F ^ G) : ((E & F) | (~E & G))) + H + SS1 + W[j]) & 0xFFFFFFFF; \
    D = C; C = left_rotate(B, 9); B = A; A = TT1; \
    H = G; G = left_rotate(F, 19); F = E; E = P0(TT2); \
}

// 压缩函数
void compression(u32 V[8], const u8* block) {
    u32 W[68], W1[64];
    message_expansion(block, W, W1);

    u32 A = V[0], B = V[1], C = V[2], D = V[3];
    u32 E = V[4], F = V[5], G = V[6], H = V[7];

    // 展开所有64轮
    COMPRESS_ROUND(0, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(1, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(2, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(3, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(4, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(5, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(6, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(7, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(8, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(9, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(10, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(11, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(12, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(13, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(14, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(15, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(16, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(17, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(18, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(19, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(20, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(21, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(22, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(23, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(24, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(25, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(26, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(27, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(28, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(29, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(30, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(31, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(32, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(33, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(34, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(35, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(36, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(37, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(38, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(39, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(40, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(41, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(42, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(43, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(44, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(45, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(46, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(47, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(48, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(49, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(50, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(51, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(52, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(53, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(54, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(55, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(56, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(57, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(58, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(59, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(60, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(61, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(62, A, B, C, D, E, F, G, H, W, W1);
    COMPRESS_ROUND(63, A, B, C, D, E, F, G, H, W, W1);

    // 更新向量
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// SM3主函数
vector<u8> sm3_hash(const string& input) {

    u32 V[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };

    vector<u8> msg_bytes = string_to_bytes(input);
    vector<u8> padded = message_padding(msg_bytes);
    size_t block_count = padded.size() / 64;

    for (size_t i = 0; i < block_count; ++i) {
        compression(V, &padded[i * 64]);
    }

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
