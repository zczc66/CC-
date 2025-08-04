#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>

using namespace std;

typedef uint32_t u32;
typedef uint8_t u8;

// 常量表
u32 T[64];

void init_T() {
    for (int i = 0; i < 64; ++i) {
        T[i] = (i < 16) ? 0x79CC4519 : 0x7A879D8A;
    }
}

// 左旋
u32 left_rotate(u32 x, u32 n) {
    return (x << n) | (x >> (32 - n));
}

// 布尔函数
u32 FF(u32 x, u32 y, u32 z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

u32 GG(u32 x, u32 y, u32 z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (~x & z));
}

// 置换函数
u32 P0(u32 x) {
    return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
}

u32 P1(u32 x) {
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

    // 追加 '1' bit
    padded.push_back(0x80);

    // 追加 '0' bits
    while ((padded.size() * 8) % 512 != 448)
        padded.push_back(0x00);

    // 添加64位长度
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

// 压缩函数
void compression(u32 V[8], const u8* block) {
    u32 W[68], W1[64];
    message_expansion(block, W, W1);

    u32 A = V[0], B = V[1], C = V[2], D = V[3];
    u32 E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; ++j) {
        u32 SS1 = left_rotate((left_rotate(A, 12) + E + left_rotate(T[j], j % 32)) & 0xFFFFFFFF, 7);
        u32 SS2 = SS1 ^ left_rotate(A, 12);
        u32 TT1 = (FF(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        u32 TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;

        D = C;
        C = left_rotate(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = left_rotate(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// SM3主函数
vector<u8> sm3_hash(const string& input) {
    init_T();

    // 初始IV
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

// 主函数
int main() {
    string input = "abc";
    vector<u8> hash = sm3_hash(input);

    cout << "SM3(\"abc\") = ";
    for (u8 byte : hash)
        cout << hex << setw(2) << setfill('0') << (int)byte;
    cout << endl;

    return 0;
}
