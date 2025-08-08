import hashlib
import random
import time
from gmssl import sm3, func
# ------------------ 椭圆曲线参数 ------------------
p  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
a  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
b  = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
n  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
Gx = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
Gy = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
G = (Gx, Gy)

# ------------------ 雅可比坐标优化 ------------------
def inverse_mod(k, p):
    return pow(k, -1, p)

def to_jacobian(P):
    x, y = P
    return (x, y, 1)

def from_jacobian(P):
    X, Y, Z = P
    if Z == 0:
        return (0, 0)
    Z_inv = inverse_mod(Z, p)
    Z_inv2 = (Z_inv * Z_inv) % p
    Z_inv3 = (Z_inv2 * Z_inv) % p
    x = (X * Z_inv2) % p
    y = (Y * Z_inv3) % p
    return (x, y)

def jacobian_double(P):
    X1, Y1, Z1 = P
    if Y1 == 0 or Z1 == 0:
        return (0, 1, 0)  # 无穷远点雅可比坐标表示
    A = (X1 * X1) % p
    B = (Y1 * Y1) % p
    C = (B * B) % p
    D = (2 * ((X1 + B) * (X1 + B) - A - C)) % p
    E = (3 * A) % p
    F = (E * E) % p
    X3 = (F - 2 * D) % p
    Y3 = (E * (D - X3) - 8 * C) % p
    Z3 = (2 * Y1 * Z1) % p
    return (X3, Y3, Z3)

def jacobian_add(P, Q):
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q

    if Z1 == 0:
        return (X2, Y2, Z2)
    if Z2 == 0:
        return (X1, Y1, Z1)

    Z1Z1 = (Z1 * Z1) % p
    Z2Z2 = (Z2 * Z2) % p
    U1 = (X1 * Z2Z2) % p
    U2 = (X2 * Z1Z1) % p
    S1 = (Y1 * Z2 * Z2Z2) % p
    S2 = (Y2 * Z1 * Z1Z1) % p

    if U1 == U2:
        if S1 != S2:
            return (0, 1, 0)  # 无穷远点
        else:
            return jacobian_double(P)

    H = (U2 - U1) % p
    I = (2 * H) % p
    I = (I * I) % p
    J = (H * I) % p
    RR = (2 * (S2 - S1)) % p
    V = (U1 * I) % p

    X3 = (RR * RR - J - 2 * V) % p
    Y3 = (RR * (V - X3) - 2 * S1 * J) % p
    Z3 = ((Z1 + Z2) * (Z1 + Z2) - Z1Z1 - Z2Z2) * H % p

    return (X3, Y3, Z3)


def scalar_mult(k, P):
    R = (0, 1, 0)  # 无穷远点的雅可比坐标表示
    P_j = to_jacobian(P)
    for i in bin(k)[2:]:
        R = jacobian_double(R)
        if i == '1':
            R = jacobian_add(R, P_j)
    return from_jacobian(R)

# ------------------ 字节串处理 ------------------
def int_to_bytes(x: int, size=32) -> bytes:
    return x.to_bytes(size, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

# ------------------ KDF ------------------
def KDF(Z: bytes, klen: int) -> bytes:
    ct = 1
    v = 256
    Ha = b''
    for _ in range((klen + v - 1) // v):
        msg = Z + ct.to_bytes(4, 'big')
        Ha += bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(msg)))
        ct += 1
    return Ha[:klen // 8]

# ------------------ 计算ZA ------------------
def calc_ZA(ID: bytes, a, b, Gx, Gy, Px, Py):
    entl = len(ID) * 8
    ENTL = entl.to_bytes(2, 'big')
    a_bytes = a.to_bytes(32, 'big')
    b_bytes = b.to_bytes(32, 'big')
    Gx_bytes = Gx.to_bytes(32, 'big')
    Gy_bytes = Gy.to_bytes(32, 'big')
    Px_bytes = Px.to_bytes(32, 'big')
    Py_bytes = Py.to_bytes(32, 'big')
    data = ENTL + ID + a_bytes + b_bytes + Gx_bytes + Gy_bytes + Px_bytes + Py_bytes
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))

# ------------------ 密钥生成 ------------------
def generate_keypair():
    d = random.randint(1, n - 2)
    P = scalar_mult(d, G)
    return d, P

# ------------------ 加密 ------------------
def sm2_encrypt(message: bytes, pubkey):
    k = random.randint(1, n - 1)
    C1 = scalar_mult(k, G)
    S = scalar_mult(k, pubkey)
    x2, y2 = S
    t = KDF(int_to_bytes(x2) + int_to_bytes(y2), len(message) * 8)
    if int.from_bytes(t, 'big') == 0:
        raise ValueError("KDF derived all-zero key")
    C2 = bytes([m ^ t[i] for i, m in enumerate(message)])
    C3 = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(int_to_bytes(x2) + message + int_to_bytes(y2))))
    return C1, C2, C3

# ------------------ 解密 ------------------
def sm2_decrypt(C1, C2, C3, privkey):
    S = scalar_mult(privkey, C1)
    x2, y2 = S
    t = KDF(int_to_bytes(x2) + int_to_bytes(y2), len(C2) * 8)
    if int.from_bytes(t, 'big') == 0:
        raise ValueError("KDF derived all-zero key")
    M = bytes([c ^ t[i] for i, c in enumerate(C2)])
    u = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(int_to_bytes(x2) + M + int_to_bytes(y2))))
    if u != C3:
        raise ValueError("Decryption failed")
    return M

# ------------------ 签名 ------------------
def sm2_sign(message: bytes, privkey, ID=b'1234567812345678'):
    Px, Py = scalar_mult(privkey, G)
    ZA = calc_ZA(ID, a, b, Gx, Gy, Px, Py)
    e = int.from_bytes(bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(ZA + message))), 'big') % n

    while True:
        k = random.randint(1, n - 1)
        x1, y1 = scalar_mult(k, G)
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod(1 + privkey, n) * (k - r * privkey)) % n
        if s != 0:
            return (r, s)

# ------------------ 验签 ------------------
def sm2_verify(message: bytes, signature, pubkey, ID=b'1234567812345678'):
    r, s = signature
    if not (1 <= r < n and 1 <= s < n):
        return False

    Px, Py = pubkey
    ZA = calc_ZA(ID, a, b, Gx, Gy, Px, Py)
    e = int.from_bytes(bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(ZA + message))), 'big') % n

    t = (r + s) % n
    if t == 0:
        return False

    P1 = scalar_mult(s, G)
    P2 = scalar_mult(t, pubkey)

    sum_jacobian = jacobian_add(to_jacobian(P1), to_jacobian(P2))
    x1, _ = from_jacobian(sum_jacobian)

    R = (e + x1) % n

    return R == r


# ------------------ 主程序 ------------------
if __name__ == "__main__":
    msg = b"Hello, this is a message encrypted using SM2."
    print("原文消息:", msg)

    privkey, pubkey = generate_keypair()
    print("私钥:", hex(privkey))
    print("公钥:")
    print("x =", hex(pubkey[0]))
    print("y =", hex(pubkey[1]))

    # 加密解密测试
    start = time.perf_counter()
    C1, C2, C3 = sm2_encrypt(msg, pubkey)
    enc_time = time.perf_counter() - start
    print(f"加密时间: {enc_time:.6f} 秒")
    
    start = time.perf_counter()
    decrypted = sm2_decrypt(C1, C2, C3, privkey)
    print("\n解密结果:", decrypted.decode())
    dec_time = time.perf_counter() - start
    print(f"解密时间: {dec_time:.6f} 秒")
    
    # 签名验证测试
    start = time.perf_counter()
    signature = sm2_sign(msg, privkey)
    sign_time = time.perf_counter() - start
    print(f"\n签名r: {hex(signature[0])}")
    print(f"签名s: {hex(signature[1])}")
    print(f"签名时间: {sign_time:.6f} 秒")
    
    start = time.perf_counter()
    verify_result = sm2_verify(msg, signature, pubkey)
    verify_time = time.perf_counter() - start
    print(f"验签时间: {verify_time:.6f} 秒")
    print(f"验证结果: {'成功' if {verify_result} else '失败'}")