from cryptography.hazmat.primitives import hashes, hmac
from tinyec.ec import Point


def decode_point_uncompressed(data: bytes, curve) -> tuple:
    coord_size = (curve.field.p.bit_length() + 7) // 8

    if len(data) != 1 + 2 * coord_size:
        raise ValueError("Invalid data length for the given field size.")

    if data[0] != 0x04:
        raise ValueError("Invalid prefix; expected 0x04 for uncompressed format.")

    x = int.from_bytes(data[1 : 1 + coord_size], byteorder="big")
    y = int.from_bytes(data[1 + coord_size :], byteorder="big")
    return Point(curve, x, y)


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
