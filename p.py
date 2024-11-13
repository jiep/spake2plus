from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


from tinyec import registry
from tinyec.ec import Point
import secrets


context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors"
idProver = b"client"
idVerifier = b"server"
w0_str = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
L = "04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd"
x = "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539"
y = "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3"
# M = (x=61709229055687782219344352628424647386531596507379261315813478518843566432559, y=43399651700267013692148409492066214468674361939146464406474584691695279811872)
M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"


w0 = int(w0_str, 16)
w1 = int(w1, 16)
x = int(x, 16)
y = int(y, 16)

private_key = ec.generate_private_key(ec.SECP256R1())
curve = private_key.curve
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

# x = secrets.randbelow(curve.field.n)
# y = secrets.randbelow(curve.field.n)


def encode_point_uncompressed(point):
    prefix = b"\x04"
    coord_size = (curve.field.p.bit_length() + 7) // 8
    x_bytes = point.x.to_bytes(coord_size, byteorder="big")
    y_bytes = point.y.to_bytes(coord_size, byteorder="big")
    return prefix + x_bytes + y_bytes


def ProverInit(w0, x):
    # x = secrets.randbelow(curve.field.n)
    X = x * P + w0 * M
    return (x, X)


def ProverFinish(w0, w1, x, Y):
    if not Y.on_curve:
        raise "invalid input"

    Z = h * x * (Y - w0 * N)
    V = h * w1 * (Y - w0 * N)

    return (Z, V)


def VerifierFinish(w0, L, X, y):
    if not X.on_curve:
        raise "invalid input"
    # y = secrets.randbelow(curve.field.n)
    Y = y * P + w0 * N
    Z = h * y * (X - w0 * M)
    V = h * y * L
    return (Y, Z, V)


def get_len(array):
    return len(array).to_bytes(8, byteorder="little")


def ComputeTranscript(context, idProver, idVerifier, shareP, shareV, Z, V, w0):
    return (
        get_len(context)
        + context
        + get_len(idProver)
        + idProver
        + get_len(idVerifier)
        + idVerifier
        + get_len(encode_point_uncompressed(M))
        + encode_point_uncompressed(M)
        + get_len(encode_point_uncompressed(N))
        + encode_point_uncompressed(N)
        + get_len(shareP)
        + shareP
        + get_len(shareV)
        + shareV
        + get_len(Z)
        + Z
        + get_len(V)
        + V
        + get_len(w0)
        + w0
    )


def ComputeKeySchedule(TT):
    h = hashes.Hash(hashes.SHA256())
    h.update(TT)
    K_main = h.finalize()
    K_confirm = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=b"ConfirmationKeys"
    ).derive(K_main)
    K_confirmP = K_confirm[:32]
    K_confirmV = K_confirm[32:]
    K_shared = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"SharedKey"
    ).derive(K_main)
    print("K", K_shared.hex())
    return K_confirmP, K_confirmV, K_shared


def mac(hash, key, message):
    h = hmac.HMAC(key, hash)
    h.update(message)
    return h.finalize()


# --------
print("Protocol...")

L = w1 * P

(x, X) = ProverInit(w0, x)


class Party:
    curve = registry.get_curve("secp256r1")
    P = curve.g
    h = 1
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
    idProver: bytes
    idVerifier: bytes
    w0: bytes
    w1: bytes
    L: bytes
    context: bytes
    X: Point
    Y: Point
    Z: Point
    V: Point
    TT: bytes
    K_confirmP: bytes
    K_confirmV: bytes 
    K_shared: bytes
    confirmV: bytes
    confirmP: bytes

    def __init__(self, idProver, idVerifier, w0, w1, context):
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.w0 = w0
        self.w1 = w1
        self.L = self.w1 * self.P
        self.context = context

    def compute_transcript():
        self.TT = (
            get_len(self.context)
            + self.context
            + get_len(self.idProver)
            + self.idProver
            + get_len(self.idVerifier)
            + self.idVerifier
            + get_len(encode_point_uncompressed(self.M))
            + encode_point_uncompressed(self.M)
            + get_len(encode_point_uncompressed(self.N))
            + encode_point_uncompressed(self.N)
            + get_len(self.shareP)
            + self.shareP
            + get_len(self.shareV)
            + self.shareV
            + get_len(self.Z)
            + self.Z
            + get_len(self.V)
            + self.V
            + get_len(self.w0)
            + self.w0
        )
        return self.TT

    def compute_key_schedule(self):
        h = hashes.Hash(hashes.SHA256())
        h.update(self.TT)
        K_main = h.finalize()
        K_confirm = HKDF(
            algorithm=hashes.SHA256(), length=64, salt=None, info=b"ConfirmationKeys"
        ).derive(K_main)
        self.K_confirmP = K_confirm[:32]
        self.K_confirmV = K_confirm[32:]
        self.K_shared = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"SharedKey"
        ).derive(K_main)
        print("K", K_shared.hex())

    def hmac(self, expected):
        self.confirmV = mac(hashes.SHA256(), self.K_confirmV, encode_point_uncompressed(self.X))
        self.confirmP = mac(hashes.SHA256(), self.K_confirmP, encode_point_uncompressed(self.Y))


class Prover(Party):
    x: bytes

    def init(self, x):
        if(not x): 
            x = secrets.randbelow(self.curve.field.n)
        self.x = x
        self.X = self.x * self.P + self.w0 * self.M
        return X

    def finish(Y):
        if not Y.on_curve:
            raise "invalid input"

        self.Z = self.h * self.x * (Y - self.w0 * self.N)
        self.V = self.h * self.w1 * (Y - self.w0 * self.N)

        return Z, V

    def compute_mac(self):
        return mac(hashes.SHA256(), self.K_confirmV, self.X)


    def check_mac(self, confirm):
        return self.compute_mac() == confirm



class Verifier(Party):
    y: bytes

    def finish(self, X, y):
        if(not y):
            y = secrets.randbelow(self.curve.field.n)

        if not X.on_curve:
            raise "invalid input"
        
        self.y = y
        self.X = X
        self.Y = self.y * self.P + self.w0 * self.N
        self.Z = self.h * self.y * (self.X - self.w0 * self.M)
        self.V = self.h * self.y * self.L

        return self.Y


prover = Prover(idProver, idVerifier, w0, w1, context)
verifier = Verifier(idProver, idVerifier, w0, w1, context)

X = prover.init(x)
Y = verifier.finish(X, y)



# (Y, Z, V) = VerifierFinish(w0, L, X, y)

# Verifier["Y"] = Y
# Verifier["Z"] = Z
# Verifier["V"] = V

# Prover["Y"] = Y

# (Z, V) = ProverFinish(w0, w1, x, Y)

# Prover["Z"] = Z
# Prover["V"] = V

# TT = ComputeTranscript(
#     context,
#     idProver,
#     idVerifier,
#     encode_point_uncompressed(X),
#     encode_point_uncompressed(Y),
#     encode_point_uncompressed(Z),
#     encode_point_uncompressed(V),
#     bytes.fromhex(w0_str),
# )

# TT2 = ComputeTranscript(
#     context,
#     idProver,
#     idVerifier,
#     encode_point_uncompressed(Prover["X"]),
#     encode_point_uncompressed(Prover["Y"]),
#     encode_point_uncompressed(Prover["Z"]),
#     encode_point_uncompressed(Prover["V"]),
#     bytes.fromhex(w0_str),
# )
# TT3 = ComputeTranscript(
#     context,
#     idProver,
#     idVerifier,
#     encode_point_uncompressed(Verifier["X"]),
#     encode_point_uncompressed(Verifier["Y"]),
#     encode_point_uncompressed(Verifier["Z"]),
#     encode_point_uncompressed(Verifier["V"]),
#     bytes.fromhex(w0_str),
# )

# K_confirmP, K_confirmV, K_shared = ComputeKeySchedule(TT)

# K_confirmPP, K_confirmVP, K_sharedP = ComputeKeySchedule(TT2)
# K_confirmPV, K_confirmVV, K_sharedV = ComputeKeySchedule(TT3)

# print("KV", K_sharedV.hex())
# print("KP", K_sharedP.hex())

# confirmV = mac(hashes.SHA256(), K_confirmV, encode_point_uncompressed(X))
# confirmP = mac(hashes.SHA256(), K_confirmP, encode_point_uncompressed(Y))

# print(confirmP.hex())
