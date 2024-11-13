from tinyec import registry
from tinyec.ec import Point

from spake2plus import *


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


if __name__ == "__main__":
    main()
