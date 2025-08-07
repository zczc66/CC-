#include <iostream>
#include <chrono>
#include <emmintrin.h>    // SSE2
#include <tmmintrin.h>    // SSSE3
#include <wmmintrin.h>    // AES-NI

using namespace std;

// 你原来的 L 变换保持不变
unsigned long L(unsigned long x) {
    return x ^ (x << 2 | x >> (32 - 2)) ^ (x << 10 | x >> (32 - 10)) ^ (x << 18 | x >> (32 - 18)) ^ (x << 24 | x >> (32 - 24));
}
#define MulMatrix(x, higherMask, lowerMask) \
    (_mm_xor_si128(_mm_shuffle_epi8(lowerMask, _mm_and_si128(x, _mm_set1_epi32(0x0f0f0f0f))), \
                    _mm_shuffle_epi8(higherMask, _mm_and_si128(_mm_srli_epi16(x, 4), _mm_set1_epi32(0x0f0f0f0f)))))

inline static __m128i MulMatrixToAES(__m128i x) {
    __m128i higherMask = _mm_set_epi8(0x22, 0x58, 0x1a, 0x60, 0x02, 0x78, 0x3a, 0x40, 0x62, 0x18,
        0x5a, 0x20, 0x42, 0x38, 0x7a, 0x00);
    __m128i lowerMask = _mm_set_epi8(0xe2, 0x28, 0x95, 0x5f, 0x69, 0xa3, 0x1e, 0xd4, 0x36, 0xfc,
        0x41, 0x8b, 0xbd, 0x77, 0xca, 0x00);
    return MulMatrix(x, higherMask, lowerMask);
}

inline static __m128i MulMatrixBack(__m128i x) {
    __m128i higherMask = _mm_set_epi8(0x14, 0x07, 0xc6, 0xd5, 0x6c, 0x7f, 0xbe, 0xad, 0xb9, 0xaa,
        0x6b, 0x78, 0xc1, 0xd2, 0x13, 0x00);
    __m128i lowerMask = _mm_set_epi8(0xd8, 0xb8, 0xfa, 0x9a, 0xc5, 0xa5, 0xe7, 0x87, 0x5f, 0x3f,
        0x7d, 0x1d, 0x42, 0x22, 0x60, 0x00);
    return MulMatrix(x, higherMask, lowerMask);
}

// 用AES-NI硬件S盒替代SM4的S盒
inline static __m128i SM4_SBox_TO_AES(__m128i x) {
    // 输入字节置换
    __m128i mask = _mm_set_epi8(3, 6, 9, 12, 15, 2, 5, 8,
        11, 14, 1, 4, 7, 10, 13, 0);
    x = _mm_shuffle_epi8(x, mask);

    // 线性变换到AES S盒输入域，示例异或常量
    x = _mm_xor_si128(MulMatrixToAES(x), _mm_set1_epi8(0x23));

    // AES-NI 硬件S盒调用
    x = _mm_aesenclast_si128(x, _mm_setzero_si128());

    // 逆线性变换
    x = _mm_xor_si128(MulMatrixBack(x), _mm_set1_epi8(0x3B));

    return x;
}

// 并行S盒，输入是一个32位整数，输出32位整数
unsigned long sm4Sbox_SIMD(unsigned long in) {
    // 把32位整数装入128位向量最低32位，其他位清零
    __m128i input = _mm_cvtsi32_si128(in);
    // 扩展32位到128位，保持输入四字节（比如4个字节作为4个输入S盒）
    input = _mm_shuffle_epi8(input, _mm_set_epi8(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
        0x80, 0x80, 0x80, 0x80, 3, 2, 1, 0));

    __m128i output = SM4_SBox_TO_AES(input);

    // 提取低32位输出
    unsigned long res = _mm_cvtsi128_si32(output);

    return res;
}

// 新T变换，用SIMD加速的S盒代替
unsigned long T(unsigned long x) {
    unsigned long b = sm4Sbox_SIMD(x);
    return L(b);
}

// 其余部分保持你原来代码不变

// 系统参数
static const unsigned long FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
// 固定参数 CK
static const unsigned long CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

void key_expansion(unsigned long MK[4], unsigned long rk[32]) {
    unsigned long K[36];
    for (int i = 0; i < 4; i++)
        K[i] = MK[i] ^ FK[i];

    for (int i = 0; i < 32; i++) {
        unsigned long tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        unsigned long b = sm4Sbox_SIMD(tmp);
        unsigned long L = b ^ (b << 13 | b >> (32 - 13)) ^ (b << 23 | b >> (32 - 23));
        rk[i] = K[i] ^ L;
        K[i + 4] = rk[i];
    }
}

unsigned long round_operate(int i, unsigned long* X, unsigned long* rk) {
    return X[i] ^ T(X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i]);
}

void sm4_enc(unsigned long MK[4], unsigned long X[36]) {
    cout << hex;
    cout << "Plaintext:" << endl;
    cout << X[0] << " " << X[1] << " " << X[2] << " " << X[3] << endl;

    cout << hex;
    cout << "Key:" << endl;
    cout << MK[0] << " " << MK[1] << " " << MK[2] << " " << MK[3] << endl;

    unsigned long rk[32];
    key_expansion(MK, rk);

    for (int i = 0; i < 32; i++) {
        unsigned long tmp = round_operate(i, X, rk);
        X[4 + i] = tmp;
    }

    cout << hex;
    cout << "Ciphertext:" << endl;
    cout << X[35] << " " << X[34] << " " << X[33] << " " << X[32] << endl;
}

void sm4_dec(unsigned long MK[4], unsigned long X[36]) {
    cout << hex;
    cout << "Ciphertext:" << endl;
    cout << X[0] << " " << X[1] << " " << X[2] << " " << X[3] << endl;

    unsigned long rk[32];
    key_expansion(MK, rk);

    //反转轮密钥
    for (int i = 0; i < 16; i++) swap(rk[i], rk[31 - i]);

    unsigned long tmpX[36] = { 0 };
    for (int i = 0; i < 4; i++) tmpX[i] = X[i];

    for (int i = 0; i < 32; i++) {
        tmpX[i + 4] = round_operate(i, tmpX, rk);
    }

    cout << "Decrypted Plaintext:" << endl;
    cout << tmpX[35] << " " << tmpX[34] << " " << tmpX[33] << " " << tmpX[32] << endl;
}

int main() {
    unsigned long MK[4] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };//加密密钥
    unsigned long X[36] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };//明文
    unsigned long C[36] = { 0x681edf34, 0xd206965e, 0x86b3e94f, 0x536e4246 };//密文

    auto start = chrono::high_resolution_clock::now();
    sm4_enc(MK, X);
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start).count();
    cout << "加密耗时：" << duration << " 微秒" << endl;

    auto start2 = chrono::high_resolution_clock::now();
    sm4_dec(MK, C);
    auto end2 = chrono::high_resolution_clock::now();
    auto duration2 = chrono::duration_cast<chrono::microseconds>(end2 - start2).count();
    cout << "解密耗时：" << duration2 << " 微秒" << endl;

    return 0;
}