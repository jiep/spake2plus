from cryptography.hazmat.primitives import hmac
from ecpy.curves import Curve


def decode_point_uncompressed(data: bytes, curve: Curve) -> tuple:

    return curve.decode_point(data)


def encode_point_uncompressed(point, curve):

    return bytes(curve.encode_point(point))


def mac(hash, key, message):
    h = hmac.HMAC(key, hash)
    h.update(message)
    return h.finalize()


def get_len(array):
    return len(array).to_bytes(8, byteorder="little")
