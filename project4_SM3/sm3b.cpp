#include <iostream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <cassert>

using namespace std;

typedef uint32_t u32;
typedef uint8_t u8;

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

inline u32 ROTL(u32 x, u32 n) {
    return (x << n) | (x >> (32 - n));
}

inline u32 FF(u32 x, u32 y, u32 z, int j) {
    if (j >= 0 && j <= 15) return x ^ y ^ z;
    else return (x & y) | (x & z) | (y & z);
}

inline u32 GG(u32 x, u32 y, u32 z, int j) {
    if (j >= 0 && j <= 15) return x ^ y ^ z;
    else return (x & y) | ((~x) & z);
}

inline u32 P0(u32 x) {
    return x ^ ROTL(x, 9) ^ ROTL(x, 17);
}

inline u32 P1(u32 x) {
    return x ^ ROTL(x, 15) ^ ROTL(x, 23);
}

void sm3_compress(u32 V[8], const u8 block[64]) {
    u32 W[68], W1[64];
    for (int i = 0; i < 16; i++) {
        W[i] = (block[i * 4 + 0] << 24) |
               (block[i * 4 + 1] << 16) |
               (block[i * 4 + 2] << 8) |
               (block[i * 4 + 3]);
    }
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
    }
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    u32 A = V[0], B = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j++) {
        u32 SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)) & 0xFFFFFFFF, 7);
        u32 SS2 = SS1 ^ ROTL(A, 12);
        u32 TT1 = (FF(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        u32 TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

vector<u8> sm3_padding(size_t msg_len_bytes) {
    uint64_t msg_len_bits = msg_len_bytes * 8;
    vector<u8> padding;

    // 1. 填充0x80
    padding.push_back(0x80);

    // 2. 填充0x00，直到消息长度（含padding）对64取余为56（即512位 - 64位长度）
    size_t pad_zero_len = (56 - (msg_len_bytes + 1) % 64) % 64;
    padding.insert(padding.end(), pad_zero_len, 0x00);


    for (int i = 7; i >= 0; i--) {
        padding.push_back((msg_len_bits >> (8 * i)) & 0xFF);
    }
    return padding;
}

vector<u8> sm3_hash_from_iv(const vector<u8>& msg, u32 iv[8], size_t prev_msg_len_bits) {

    u32 V[8];
    memcpy(V, iv, sizeof(u32) * 8);

    size_t total_msg_len_bytes = (prev_msg_len_bits / 8) + msg.size();

    vector<u8> data(msg);

    vector<u8> pad = sm3_padding(total_msg_len_bytes);
    data.insert(data.end(), pad.begin(), pad.end());

    assert(data.size() % 64 == 0);

    for (size_t i = 0; i < data.size(); i += 64) {
        sm3_compress(V, &data[i]);
    }

    vector<u8> hash(32);
    for (int i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (V[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (V[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (V[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = (V[i]) & 0xFF;
    }
    return hash;
}

vector<u8> sm3_hash(const vector<u8>& msg) {

    u32 IV[8] = {
        0x7380166F,0x4914B2B9,0x172442D7,0xDA8A0600,
        0xA96F30BC,0x163138AA,0xE38DEE4D,0xB0FB0E4E
    };

    size_t msg_len_bytes = msg.size();

    // 消息填充
    vector<u8> data(msg);
    vector<u8> pad = sm3_padding(msg_len_bytes);
    data.insert(data.end(), pad.begin(), pad.end());

    // 压缩
    for (size_t i = 0; i < data.size(); i += 64) {
        sm3_compress(IV, &data[i]);
    }

    // 输出
    vector<u8> hash(32);
    for (int i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (IV[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (IV[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (IV[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = (IV[i]) & 0xFF;
    }
    return hash;
}

void print_hash(const vector<u8>& hash) {
    for (auto c : hash) {
        cout << hex << setw(2) << setfill('0') << (int)c;
    }
    cout << dec << endl;
}

int main() {
    string original_msg = "abc";
    string append_msg = "def";

    vector<u8> orig_bytes(original_msg.begin(), original_msg.end());
    vector<u8> append_bytes(append_msg.begin(), append_msg.end());

    // 1. 计算原始消息哈希Hash(M)
    vector<u8> hash_orig = sm3_hash(orig_bytes);

    cout << "Hash(original_msg): ";
    print_hash(hash_orig);

    // 2. 从hash转换为IV（内部状态）
    u32 iv[8];
    for (int i = 0; i < 8; i++) {
        iv[i] = (hash_orig[4 * i] << 24) |
                (hash_orig[4 * i + 1] << 16) |
                (hash_orig[4 * i + 2] << 8) |
                (hash_orig[4 * i + 3]);
    }

    // 3. 构造伪造消息 = original_msg + padding(original_msg) + append_msg
    vector<u8> padding_orig = sm3_padding(orig_bytes.size());

    vector<u8> forged_msg = orig_bytes;
    forged_msg.insert(forged_msg.end(), padding_orig.begin(), padding_orig.end());
    forged_msg.insert(forged_msg.end(), append_bytes.begin(), append_bytes.end());

    // 4. 计算长度扩展攻击哈希，即从Hash(M)开始，继续压缩append_msg部分
    // append_msg的消息长度是伪造消息长度，不包括后续填充，prev_msg_len_bits为(原始消息长度 + padding长度)*8
    size_t prev_len_bits = (orig_bytes.size() + padding_orig.size()) * 8;

    vector<u8> extended_hash = sm3_hash_from_iv(append_bytes, iv, prev_len_bits);

    cout << "Hash(M || padding(M) || append_msg) from extended state: ";
    print_hash(extended_hash);

    // 5. 验证
    vector<u8> direct_hash = sm3_hash(forged_msg);

    cout << "Direct hash of forged_msg: ";
    print_hash(direct_hash);

    //比较两个hash
    if (extended_hash == direct_hash) {
        cout << "Length extension attack verified: hashes match." << endl;
    } else {
        cout << "Length extension attack failed: hashes differ." << endl;
    }

    return 0;
}

