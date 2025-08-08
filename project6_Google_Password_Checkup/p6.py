import random
from hashlib import sha256
from tinyec import registry
import secrets

# ------------------------------------
# 工具函数
# ------------------------------------

def H_to_G(msg, curve):
    """
    哈希字符串到曲线点
    """
    h = sha256(msg.encode()).digest()
    scalar = int.from_bytes(h, 'big') % curve.field.n
    point = scalar * curve.g
    return point

def point_to_tuple(point):
    return (point.x, point.y)

def tuple_to_point(tpl, curve):
    return curve.Point(tpl[0], tpl[1])

def encode_int_to_point(m, curve):
    """
    简单映射：m * G
    注意：m必须小于曲线阶
    """
    return m * curve.g

def decode_point_to_int(point, curve):
    """
    简单暴力搜索解码，只能小权重用
    """
    # 小权重时可用暴力搜索解码
    for i in range(10000):
        if i * curve.g == point:
            return i
    raise ValueError("无法解码该点为整数")

# ------------------------------------
# ECC-ElGamal 加密/解密
# ------------------------------------

class ECCElGamal:
    def __init__(self, curve):
        self.curve = curve
        self.priv = random.randint(1, curve.field.n - 1)
        self.pub = self.priv * curve.g

    def encrypt(self, m):
        """
        m是整数，先编码成点，再加密
        返回 (C1, C2)，两个椭圆曲线点
        """
        M = encode_int_to_point(m, self.curve)
        k = random.randint(1, self.curve.field.n - 1)
        C1 = k * self.curve.g
        C2 = M + k * self.pub
        return (C1, C2)

    def decrypt(self, C):
        """
        C = (C1, C2)
        解密得到点M，再解码成整数
        """
        C1, C2 = C
        S = self.priv * C1
        M = C2 - S
        m = decode_point_to_int(M, self.curve)
        return m

    @staticmethod
    def add_ciphertexts(C1, C2):
        """
        椭圆曲线上的点加法，实现同态加密相加
        """
        return (C1[0] + C2[0], C1[1] + C2[1])

# ------------------------------------
# 协议主体
# ------------------------------------

class Party1:
    def __init__(self, V, curve):
        self.V = V
        self.curve = curve
        self.k1 = random.randint(1, curve.field.n - 1)
        self.Z_tuples = None
        self.intersection_set = set()

    def round1_send(self):
        points = []
        for v in self.V:
            p = H_to_G(v, self.curve)
            p1 = self.k1 * p
            points.append(p1)
        random.shuffle(points)
        return points

    def round3_receive(self, encrypted_pairs):
        Z_set = set(self.Z_tuples)
        sum_enc = None
        for (point_k2, enc_t) in encrypted_pairs:
            val = self.k1 * point_k2
            val_tuple = point_to_tuple(val)
            if val_tuple in Z_set:
                self.intersection_set.add(val_tuple)
                if sum_enc is None:
                    sum_enc = enc_t
                else:
                    sum_enc = ECCElGamal.add_ciphertexts(sum_enc, enc_t)
        return sum_enc


class Party2:
    def __init__(self, W, curve):
        self.W = W
        self.curve = curve
        self.k2 = random.randint(1, curve.field.n - 1)
        self.elgamal = ECCElGamal(curve)

    def round2_receive_and_send(self, points_k1):
        Z = []
        for p in points_k1:
            Z.append(self.k2 * p)
        random.shuffle(Z)

        pairs = []
        for (w, t) in self.W:
            p = H_to_G(w, self.curve)
            p_k2 = self.k2 * p
            enc_t = self.elgamal.encrypt(t)
            pairs.append((p_k2, enc_t))
        random.shuffle(pairs)
        return Z, pairs

    def round3_decrypt(self, sum_enc):
        return self.elgamal.decrypt(sum_enc)



def main():
    curve = registry.get_curve('secp256r1')

    V = ["alice", "bob", "carol", "dave"]
    W = [("bob", 3), ("carol", 5), ("eve", 2), ("frank", 1)]

    P1 = Party1(V, curve)
    P2 = Party2(W, curve)

    round1_msg = P1.round1_send()
    Z_points, pairs = P2.round2_receive_and_send(round1_msg)
    P1.Z_tuples = set(point_to_tuple(p) for p in Z_points)
    sum_enc = P1.round3_receive(pairs)
    intersection_sum = P2.round3_decrypt(sum_enc)

    print(f"Intersection sum = {intersection_sum}")  # 预期：8

if __name__ == "__main__":
    main()

