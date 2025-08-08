#!/usr/bin/env python3
# sm2_sm3_gmssl_k_leak_poc.py
# PoC: 使用 gmssl 的 SM3 实现的 SM2 k 泄露 / k 重用 恢复私钥 /跨算法（ECDSA+SM2）复用 k 和 d 导致私钥泄露 PoC

import struct
import secrets
from gmssl import sm3, func

# --------------------- SM2 曲线参数 (GM/T 0003.5) ---------------------
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

O = None  # 点在无穷远表示

# --------------------- 基本数论与椭圆运算（仿射） ---------------------
def inv_mod(x, m):
    x = x % m
    if x == 0:
        raise ZeroDivisionError("Inverse does not exist")
    return pow(x, -1, m)

def point_add(P, Q):
    if P is O:
        return Q
    if Q is O:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return O
    if P != Q:
        lam = ((y2 - y1) * inv_mod(x2 - x1, p)) % p
    else:
        if y1 == 0:
            return O
        lam = ((3 * x1 * x1 + a) * inv_mod(2 * y1, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mul(k, P):
    if k % n == 0 or P is O:
        return O
    if k < 0:
        return scalar_mul(-k, (P[0], (-P[1]) % p))
    R = O
    N = P
    while k:
        if k & 1:
            R = point_add(R, N)
        N = point_add(N, N)
        k >>= 1
    return R

# --------------------- SM3 ---------------------
def sm3_hash_bytes(msg_bytes: bytes) -> bytes:
    hexstr = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
    return bytes.fromhex(hexstr)

def hash_e_sm3_to_int(msg_bytes: bytes) -> int:
    return int.from_bytes(sm3_hash_bytes(msg_bytes), 'big') % n

# --------------------- SM2 辅助：计算 ZA ---------------------
def int_to_bytes_fixed(x: int, length: int) -> bytes:
    return x.to_bytes(length, 'big')

def compute_ZA(ID_A: bytes, PA):
    entl = (len(ID_A) * 8) & 0xFFFF
    entl_bytes = struct.pack('>H', entl)
    zb = (
        entl_bytes +
        ID_A +
        int_to_bytes_fixed(a, 32) +
        int_to_bytes_fixed(b, 32) +
        int_to_bytes_fixed(Gx, 32) +
        int_to_bytes_fixed(Gy, 32) +
        int_to_bytes_fixed(PA[0], 32) +
        int_to_bytes_fixed(PA[1], 32)
    )
    return sm3_hash_bytes(zb)

# --------------------- SM2 签名 / 验签 ---------------------
def keygen():
    d = secrets.randbelow(n - 1) + 1
    P = scalar_mul(d, (Gx, Gy))
    return d, P

def sign_sm2(dA: int, ZA_and_M_bytes: bytes, k: int = None):
    e = hash_e_sm3_to_int(ZA_and_M_bytes)
    if k is None:
        k = secrets.randbelow(n - 1) + 1
    R_point = scalar_mul(k, (Gx, Gy))
    if R_point is O:
        raise ValueError("Bad k produced point at infinity")
    x1 = R_point[0] % n
    r = (e + x1) % n
    if r == 0 or (r + k) % n == 0:
        return sign_sm2(dA, ZA_and_M_bytes, None)
    inv_1_plus_d = inv_mod(1 + dA, n)
    s = (inv_1_plus_d * (k - r * dA)) % n
    if s == 0:
        return sign_sm2(dA, ZA_and_M_bytes, None)
    return (r, s, k, e)

def verify_sm2(PA, ZA_and_M_bytes: bytes, sig):
    r, s = sig
    e = hash_e_sm3_to_int(ZA_and_M_bytes)
    t = (r + s) % n
    if t == 0:
        return False
    P = point_add(scalar_mul(s, (Gx, Gy)), scalar_mul(t, PA))
    if P is O:
        return False
    x1 = P[0] % n
    R = (e + x1) % n
    return R == r

def recover_d_from_k(r: int, s: int, k: int) -> int:
    denom = (s + r) % n
    inv = inv_mod(denom, n)
    d = (inv * ((k - s) % n)) % n
    return d

# --------------------- PoC 演示：单次 k 泄露 ---------------------
def demo_single_k_leak():
    print("== PoC: 单次 k 泄露 恢复私钥（gmssl SM3 版本）==")
    dA, PA = keygen()
    ID_A = b'1234567812345678'
    ZA = compute_ZA(ID_A, PA)
    M = b"Hello SM2 with SM3 (gmssl) PoC"
    to_sign = ZA + M
    r, s, k, e = sign_sm2(dA, to_sign)
    print(f"[用户A] 私钥 dA = {hex(dA)}")
    print(f"[用户A] 签名 (r, s) = ({hex(r)}, {hex(s)})")
    print(f"[用户A] 泄露的 k = {hex(k)}")
    d_rec = recover_d_from_k(r, s, k)
    print("恢复是否成功：", d_rec == dA)

# --------------------- PoC 演示：k 重用 两个不同消息 ---------------------
def demo_k_reuse_two_sigs():
    print("\n== PoC: k 重用 两个不同消息 恢复私钥（gmssl SM3 版本）==")
    dA, PA = keygen()
    ID_A = b'1234567812345678'
    ZA = compute_ZA(ID_A, PA)
    M1 = b"Message one"
    M2 = b"Another message"
    k_shared = secrets.randbelow(n - 1) + 1
    r1, s1, k1, e1 = sign_sm2(dA, ZA + M1, k=k_shared)
    r2, s2, k2, e2 = sign_sm2(dA, ZA + M2, k=k_shared)
    print(f"[用户A] 私钥 dA = {hex(dA)}")
    print(f"共享 k = {hex(k_shared)}")
    d_rec1 = recover_d_from_k(r1, s1, k_shared)
    print("已知 k 时恢复是否成功：", d_rec1 == dA)

# --------------------- PoC 演示：不同用户重用同一 k ---------------------
def demo_k_reuse_different_users():
    print("\n== PoC: 不同用户重用同一 k 恢复各自私钥 ==")
    # 用户A
    dA, PA = keygen()
    ID_A = b'UserA-1234'
    ZA_A = compute_ZA(ID_A, PA)
    M_A = b"UserA's message"
    # 用户B
    dB, PB = keygen()
    ID_B = b'UserB-5678'
    ZA_B = compute_ZA(ID_B, PB)
    M_B = b"UserB's message"
    # 共享同一个 k
    k_shared = secrets.randbelow(n - 1) + 1
    rA, sA, _, _ = sign_sm2(dA, ZA_A + M_A, k=k_shared)
    rB, sB, _, _ = sign_sm2(dB, ZA_B + M_B, k=k_shared)
    # 分别恢复私钥
    dA_rec = recover_d_from_k(rA, sA, k_shared)
    dB_rec = recover_d_from_k(rB, sB, k_shared)
    print(f"[用户A] 原私钥 = {hex(dA)}  恢复 = {hex(dA_rec)}  成功? {dA_rec == dA}")
    print(f"[用户B] 原私钥 = {hex(dB)}  恢复 = {hex(dB_rec)}  成功? {dB_rec == dB}")

# --------------------- ECDSA 简易签名 ---------------------
def hash_msg_to_int(msg: bytes) -> int:
    # 这里也用 SM3 哈希，转成整数
    return int.from_bytes(sm3_hash_bytes(msg), 'big') % n

def sign_ecdsa(d: int, msg: bytes, k: int):
    e = hash_msg_to_int(msg)
    R = scalar_mul(k, (Gx, Gy))
    if R is O:
        raise ValueError("Bad k")
    r = R[0] % n
    if r == 0:
        raise ValueError("r=0")
    k_inv = inv_mod(k, n)
    s = (k_inv * (e + d * r)) % n
    if s == 0:
        raise ValueError("s=0")
    return (r, s, e)

def verify_ecdsa(P, msg: bytes, sig):
    r, s = sig
    if r <= 0 or r >= n or s <= 0 or s >= n:
        return False
    e = hash_msg_to_int(msg)
    w = inv_mod(s, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    point = point_add(scalar_mul(u1, (Gx, Gy)), scalar_mul(u2, P))
    if point is O:
        return False
    x1 = point[0] % n
    return x1 == r

# --------------------- 跨算法攻击恢复私钥 ---------------------
def recover_d_from_ecdsa_sm2(r1, s1, e1, r2, s2):
    # 根据公式：
    # s1^{-1} * (e1 + d r1) = s2 * (1 + d) + d r2
    # 两边乘 s1:
    # e1 + d r1 = s1 s2 + s1 s2 d + s1 r2 d
    # 整理:
    # e1 - s1 s2 = d (s1 s2 + s1 r2 - r1)
    # d = (e1 - s1 s2) * inv(s1 s2 + s1 r2 - r1) mod n
    numerator = (e1 - s1 * s2) % n
    denominator = (s1 * s2 + s1 * r2 - r1) % n
    denom_inv = inv_mod(denominator, n)
    d = (numerator * denom_inv) % n
    return d

# --------------------- PoC 演示：跨算法同 d 和 k 导致私钥泄露 ---------------------
def demo_cross_algorithm_attack():
    print("\n== PoC: 跨算法同 d 和 k 导致私钥泄露 ==")
    # 用户密钥和公钥
    d, P = keygen()
    print(f"[用户] 私钥 d = {hex(d)}")

    # 共享随机数 k
    k = secrets.randbelow(n - 1) + 1
    print(f"[用户] 共享随机数 k = {hex(k)}")

    # 消息
    M_ecdsa = b"Message signed by ECDSA"
    M_sm2 = b"Message signed by SM2"

    # ECDSA 签名
    r1, s1, e1 = sign_ecdsa(d, M_ecdsa, k)
    print(f"ECDSA 签名: r1={hex(r1)}, s1={hex(s1)}, e1={hex(e1)}")

    # SM2 签名
    ID_A = b'User-ID-12345678'
    ZA = compute_ZA(ID_A, P)
    to_sign_sm2 = ZA + M_sm2
    r2, s2, k2, e2 = sign_sm2(d, to_sign_sm2, k=k)
    print(f"SM2 签名: r2={hex(r2)}, s2={hex(s2)}, e2={hex(e2)}")

    # 恢复私钥
    d_rec = recover_d_from_ecdsa_sm2(r1, s1, e1, r2, s2)
    print(f"恢复的私钥 d = {hex(d_rec)}")
    print("恢复成功？", d_rec == d)

if __name__ == "__main__":
    demo_single_k_leak()
    demo_k_reuse_two_sigs()
    demo_k_reuse_different_users()
    demo_cross_algorithm_attack()

