from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from tinyec import registry
from tinyec.ec import Point
import secrets


def encode_point_uncompressed(point, curve):
    prefix = b"\x04"
    coord_size = (curve.field.p.bit_length() + 7) // 8
    x_bytes = point.x.to_bytes(coord_size, byteorder="big")
    y_bytes = point.y.to_bytes(coord_size, byteorder="big")
    return prefix + x_bytes + y_bytes


def mac(hash, key, message):
    h = hmac.HMAC(key, hash)
    h.update(message)
    return h.finalize()


def get_len(array):
    return len(array).to_bytes(8, byteorder="little")


def main():
    context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
    w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
    L = "04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd"
    x = "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539"
    y = "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3"
    M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
    N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    x = int(x, 16)
    y = int(y, 16)

    # private_key = ec.generate_private_key(ec.SECP256R1())
    # curve = private_key.curve
    # x_1 = ECC.generate(curve='P-256').pointQ
    # M = EllipticCurvePublicKey.from_encoded_point(curve, bytes.fromhex(M))
    # print(M.public_numbers())
    # N = EllipticCurvePublicKey.from_encoded_point(curve, bytes.fromhex(N))
    # print("N", N.public_numbers())
    # L = EllipticCurvePublicKey.from_encoded_point(curve, bytes.fromhex(L))
    # print("L", L.public_numbers())

    # -------------------
    curve = registry.get_curve("secp256r1")
    P = curve.g

    M = Point(
        curve,
        61709229055687782219344352628424647386531596507379261315813478518843566432559,
        43399651700267013692148409492066214468674361939146464406474584691695279811872,
    )
    N = Point(
        curve,
        98031458012971070369465795029179261841266230867477002166417845678366165379913,
        3544368724946236282841049099645644789675854804295951046212527731618188549095,
    )

    h = 1

    hash = hashes.SHA256()
    mac = hashes.SHA256()
    kdf = hashes.SHA256()

    params = GlobalParameters(M, N, h, curve, hash, mac, kdf)
    protocol = Protocol(params, idProver, idVerifier, w0, w1, context, x, y)


class Protocol:
    def __init__(self, params, idProver, idVerifier, w0, w1, context, x, y):
        self.params = params
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.context = context
        print(f"Running SPAKE2+ with curve {self.params.curve.name}, {self.params.hash.name.split('.')[-1].upper()}, HKDF-{self.params.kdf.name.split('.')[-1].upper()} and HMAC-{self.params.mac.name.split('.')[-1].upper()}")
        prover = Prover(idProver, idVerifier, w0, w1, context, params)
        verifier = Verifier(idProver, idVerifier, w0, w1, context, params)

        X = prover.init(x)
        Y = verifier.finish(X, y)

        prover.finish(Y)
        prover.compute_key_schedule()
        verifier.compute_key_schedule()

        confirmVV, confirmPV = verifier.confirm()
        confirmVP, confirmPP = prover.confirm()

        if not prover.check(confirmVV, confirmPV) or not verifier.check(
            confirmVP, confirmPP
        ):
            print("Error")

        print(verifier.shared_key().hex())
        print(prover.shared_key().hex())


class GlobalParameters:
    def __init__(self, M, N, h, curve, hash, mac, kdf):
        self.M = M
        self.N = N
        self.P = curve.g
        self.h = h
        self.curve = curve
        self.hash = hash
        self.mac = mac
        self.kdf = kdf


class Party:
    def __init__(self, idProver, idVerifier, w0, w1, context, params):
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.w0 = w0
        self.w1 = w1
        self.params = params
        self.L = int.from_bytes(self.w1) * self.params.P
        self.context = context

    def shared_key(self):
        return self.K_shared

    def compute_transcript(self):
        return (
            get_len(self.context)
            + self.context
            + get_len(self.idProver)
            + self.idProver
            + get_len(self.idVerifier)
            + self.idVerifier
            + get_len(encode_point_uncompressed(self.params.M, self.params.curve))
            + encode_point_uncompressed(self.params.M, self.params.curve)
            + get_len(encode_point_uncompressed(self.params.N, self.params.curve))
            + encode_point_uncompressed(self.params.N, self.params.curve)
            + get_len(encode_point_uncompressed(self.X, self.params.curve))
            + encode_point_uncompressed(self.X, self.params.curve)
            + get_len(encode_point_uncompressed(self.Y, self.params.curve))
            + encode_point_uncompressed(self.Y, self.params.curve)
            + get_len(encode_point_uncompressed(self.Z, self.params.curve))
            + encode_point_uncompressed(self.Z, self.params.curve)
            + get_len(encode_point_uncompressed(self.V, self.params.curve))
            + encode_point_uncompressed(self.V, self.params.curve)
            + get_len(self.w0)
            + self.w0
        )

    def compute_key_schedule(self):
        h = hashes.Hash(self.params.hash)
        self.TT = self.compute_transcript()
        h.update(self.TT)
        K_main = h.finalize()
        K_confirm = HKDF(
            algorithm=self.params.kdf, length=64, salt=None, info=b"ConfirmationKeys"
        ).derive(K_main)
        self.K_confirmP = K_confirm[:32]
        self.K_confirmV = K_confirm[32:]
        self.K_shared = HKDF(
            algorithm=self.params.kdf, length=32, salt=None, info=b"SharedKey"
        ).derive(K_main)

    def confirm(self):
        self.confirmV = mac(
            self.params.mac,
            self.K_confirmV,
            encode_point_uncompressed(self.X, self.params.curve),
        )
        self.confirmP = mac(
            self.params.mac,
            self.K_confirmP,
            encode_point_uncompressed(self.Y, self.params.curve),
        )
        return self.confirmV, self.confirmP

    def check(self, confirmV, confirmP):
        return self.confirmV == confirmV and self.confirmP == confirmP


class Prover(Party):
    x: bytes

    def init(self, x):
        if not x:
            x = secrets.randbelow(self.curve.field.n)
        self.x = x
        self.X = self.x * self.params.P + int.from_bytes(self.w0) * self.params.M
        return self.X

    def finish(self, Y):
        if not Y.on_curve:
            raise "invalid input"

        self.Y = Y
        self.Z = self.params.h * self.x * (Y - int.from_bytes(self.w0) * self.params.N)
        self.V = (
            self.params.h
            * int.from_bytes(self.w1)
            * (Y - int.from_bytes(self.w0) * self.params.N)
        )


class Verifier(Party):
    y: bytes

    def finish(self, X, y):
        if not y:
            y = secrets.randbelow(self.curve.field.n)

        if not X.on_curve:
            raise "invalid input"

        self.y = y
        self.X = X
        self.Y = self.y * self.params.P + int.from_bytes(self.w0) * self.params.N
        self.Z = (
            self.params.h * self.y * (self.X - int.from_bytes(self.w0) * self.params.M)
        )
        self.V = self.params.h * self.y * self.L

        return self.Y


if __name__ == "__main__":
    main()
