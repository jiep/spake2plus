from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from spake2plus.utils import encode_point_uncompressed, get_len, mac

import math


class Role:
    def __init__(
        self,
        idProver,
        idVerifier,
        password,
        salt,
        iterations,
        context,
        params,
        host="localhost",
        port=12345,
    ):
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.password = password
        self.salt = salt
        self.params = params
        self.iterations = iterations
        self.compute_w0_w1(password, salt, iterations)
        self.L = int.from_bytes(self.w1, byteorder="big") * self.params.P
        self.context = context
        self.host = host
        self.port = port

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
            algorithm=self.params.kdf,
            length=2 * self.params.length,
            salt=None,
            info=b"ConfirmationKeys",
        ).derive(K_main)
        self.K_confirmP = K_confirm[: self.params.length]
        self.K_confirmV = K_confirm[self.params.length :]
        self.K_shared = HKDF(
            algorithm=self.params.kdf,
            length=self.params.length,
            salt=None,
            info=b"SharedKey",
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

    def set_w0_w1(self, w0, w1):
        self.w0 = w0
        self.w1 = w1

    def compute_w0_w1(self, pw, salt, iterations=100000):

        input_data = (
            get_len(pw)
            + pw.encode("utf-8")
            + get_len(self.idProver)
            + self.idProver
            + get_len(self.idVerifier)
            + self.idVerifier
        )

        print(input_data)

        k = 64
        output_length = 2 * math.ceil(math.log(self.params.curve.field.n, 2) + k)

        kdf = PBKDF2HMAC(
            algorithm=self.params.hash,
            length=output_length,
            salt=salt,
            iterations=iterations,
        )

        derived_key = kdf.derive(input_data)

        half_length = len(derived_key) // 2
        w0s = int.from_bytes(derived_key[:half_length], "big")
        w1s = int.from_bytes(derived_key[half_length:], "big")

        w0 = w0s % self.params.curve.field.n
        w1 = w1s % self.params.curve.field.n
        self.w0 = w0.to_bytes((w0.bit_length() + 7) // 8, "big")
        self.w1 = w0.to_bytes((w1.bit_length() + 7) // 8, "big")
