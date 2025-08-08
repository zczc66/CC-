#!/usr/bin/env python3
# sm2_forge_signature_poc.py
# PoC: 伪造ECDSA/SM2数字签名示例（无私钥伪造）
# 结合SM2曲线参数，实现伪造签名和验证

import secrets

# --------------------- SM2 曲线参数 (GM/T 0003.5) ---------------------
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123

O = None  # 无穷远点

# --------------------- 基本数论与椭圆曲线点运算 ---------------------
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

# --------------------- 密钥生成 ---------------------
def keygen():
    d = secrets.randbelow(n - 1) + 1
    P = scalar_mul(d, (Gx, Gy))
    return d, P

# --------------------- 伪造ECDSA/SM2签名 ---------------------
def forge_signature(P):
    """
    无私钥伪造签名
    
    选择随机 u, v，计算:
        R = uG + vP
        r = R.x mod n
        s = r * v^{-1} mod n
        e = r * u * v^{-1} mod n
    
    返回 (r, s, e)
    """
    while True:
        u = secrets.randbelow(n - 1) + 1
        v = secrets.randbelow(n - 1) + 1

        R = point_add(scalar_mul(u, (Gx, Gy)), scalar_mul(v, P))
        if R is O:
            continue
        r = R[0] % n
        if r == 0:
            continue
        v_inv = inv_mod(v, n)
        s = (r * v_inv) % n
        if s == 0:
            continue
        e = (r * u * v_inv) % n
        return (r, s, e)

# --------------------- 验证签名 ---------------------
def verify_signature(P, r, s, e):
    """
    验证签名是否有效
    """
    if not (1 <= r < n and 1 <= s < n):
        return False
    w = inv_mod(s, n)
    u1 = (e * w) % n
    u2 = (r * w) % n
    R = point_add(scalar_mul(u1, (Gx, Gy)), scalar_mul(u2, P))
    if R is O:
        return False
    x1 = R[0] % n
    return x1 == r

# --------------------- 测试主程序 ---------------------
if __name__ == "__main__":
    print("=== SM2/ECDSA伪造签名示例 ===")
    d, P = keygen()
    print(f"生成测试密钥对：私钥 d = {hex(d)}")
    print(f"公钥 P = ({hex(P[0])}, {hex(P[1])})")

    r, s, e = forge_signature(P)
    print(f"\n伪造签名结果：")
    print(f"r = {hex(r)}")
    print(f"s = {hex(s)}")
    print(f"消息哈希 e = {hex(e)}")

    valid = verify_signature(P, r, s, e)
    print("\n伪造签名验签结果：", "成功" if valid else "失败")

