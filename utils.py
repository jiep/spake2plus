from cryptography.hazmat.primitives import hashes, hmac


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
