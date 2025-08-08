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

# ------------------ ECC 基础运算 ------------------

def inverse_mod(k, p):
    return pow(k, -1, p)

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * inverse_mod(2 * y1, p) % p
    else:
        lam = (y2 - y1) * inverse_mod(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    R = None
    while k:
        if k & 1:
            R = point_add(R, P)
        P = point_add(P, P)
        k >>= 1
    return R

# ------------------ 固定点 G 的预计算加速 ------------------

G_TABLE = []

def precompute_G_table():
    global G_TABLE
    G_TABLE = []
    P = G
    for _ in range(256):
        G_TABLE.append(P)
        P = point_add(P, P)

def fixed_scalar_mult(k):
    R = None
    for i in range(256):
        if (k >> i) & 1:
            R = point_add(R, G_TABLE[i])
    return R

# ------------------ 字节转换 ------------------

def int_to_bytes(x: int, size=32) -> bytes:
    return x.to_bytes(size, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

# ------------------ KDF 密钥派生函数 ------------------

def KDF(Z: bytes, klen: int) -> bytes:
    ct = 1
    v = 256
    Ha = b''
    for _ in range((klen + v - 1) // v):
        msg = Z + ct.to_bytes(4, 'big')
        digest_hex = sm3.sm3_hash(func.bytes_to_list(msg))
        Ha += bytes.fromhex(digest_hex)
        ct += 1
    return Ha[:klen // 8]

# ------------------ 密钥生成 ------------------

def generate_keypair():
    d = random.randint(1, n - 2)
    P = fixed_scalar_mult(d)
    return d, P

# ------------------ 加密函数 ------------------

def sm2_encrypt(message: bytes, pubkey):
    k = random.randint(1, n - 1)
    C1 = fixed_scalar_mult(k)
    S = scalar_mult(k, pubkey)
    x2, y2 = S
    x2_bytes = int_to_bytes(x2)
    y2_bytes = int_to_bytes(y2)
    t = KDF(x2_bytes + y2_bytes, len(message) * 8)
    if int.from_bytes(t, 'big') == 0:
        raise ValueError("KDF derived all-zero key, aborting")
    C2 = bytes([m ^ t[i] for i, m in enumerate(message)])
    C3 = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(x2_bytes + message + y2_bytes)))
    return C1, C2, C3

# ------------------ 解密函数 ------------------

def sm2_decrypt(C1, C2, C3, privkey):
    S = scalar_mult(privkey, C1)
    x2, y2 = S
    x2_bytes = int_to_bytes(x2)
    y2_bytes = int_to_bytes(y2)
    t = KDF(x2_bytes + y2_bytes, len(C2) * 8)
    if int.from_bytes(t, 'big') == 0:
        raise ValueError("KDF derived all-zero key, aborting")
    M = bytes([c ^ t[i] for i, c in enumerate(C2)])
    u = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(x2_bytes + M + y2_bytes)))
    if u != C3:
        raise ValueError("Decryption failed: hash does not match")
    return M

# ------------------ 签名函数 ------------------

def sm2_sign(message: bytes, privkey):
    e = int(sm3.sm3_hash(func.bytes_to_list(message)), 16) % n
    while True:
        k = random.randint(1, n - 1)
        P1 = fixed_scalar_mult(k)
        r = (e + P1[0]) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod(1 + privkey, n) * (k - r * privkey)) % n
        if s != 0:
            break
    return (r, s)

# ------------------ 验签函数 ------------------

def sm2_verify(message: bytes, signature, pubkey):
    r, s = signature
    if not (1 <= r <= n - 1) or not (1 <= s <= n - 1):
        return False
    e = int(sm3.sm3_hash(func.bytes_to_list(message)), 16) % n
    t = (r + s) % n
    if t == 0:
        return False
    P1 = fixed_scalar_mult(s)
    P2 = scalar_mult(t, pubkey)
    Rxy = point_add(P1, P2)
    if Rxy is None:
        return False
    x1, y1 = Rxy
    R = (e + x1) % n
    return R == r

# ------------------ 工具函数 ------------------

def print_point(P):
    x, y = P
    print("x =", hex(x))
    print("y =", hex(y))

# ------------------ 主程序 ------------------

if __name__ == "__main__":
    precompute_G_table()  # 预计算 G 的倍点表

    msg = b"Hello, this is a message encrypted using SM2."
    print(msg)
    privkey, pubkey = generate_keypair()
    print("私钥:", hex(privkey))
    print("公钥:")
    print_point(pubkey)

    # 加密
    start = time.perf_counter()
    C1, C2, C3 = sm2_encrypt(msg, pubkey)
    enc_time = time.perf_counter() - start
    print("\n加密结果：")
    print("C1:")
    print_point(C1)
    print("C2:", C2.hex())
    print("C3:", C3.hex())
    print(f"加密时间: {enc_time:.6f} 秒")

    # 解密
    start = time.perf_counter()
    decrypted = sm2_decrypt(C1, C2, C3, privkey)
    dec_time = time.perf_counter() - start
    print("\n解密还原明文:")
    print(decrypted.decode())
    print(f"解密时间: {dec_time:.6f} 秒")

    # 签名
    start = time.perf_counter()
    signature = sm2_sign(msg, privkey)
    sign_time = time.perf_counter() - start
    print("\n签名结果:")
    print(f"r = {hex(signature[0])}")
    print(f"s = {hex(signature[1])}")
    print(f"签名时间: {sign_time:.6f} 秒")

    # 验签
    start = time.perf_counter()
    verify_result = sm2_verify(msg, signature, pubkey)
    verify_time = time.perf_counter() - start
    print(f"\n验证结果: {'成功' if verify_result else '失败'}")
    print(f"验签时间: {verify_time:.6f} 秒")