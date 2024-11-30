import math
from spake2plus.exceptions import InvalidInputError
from spake2plus.parameters import Parameters
from spake2plus.role import Role
from spake2plus.utils import (
    encode_point_uncompressed,
    decode_point_uncompressed,
    get_len,
)
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

import secrets
import socket


SALT_SIZE = 32


class Prover(Role):
    w1: bytes

    def __init___(
        self,
        idProver: bytes,
        idVerifier: bytes,
        context: bytes,
        params: Parameters,
        w0: bytes,
        w1: bytes,
        host: str = "localhost",
        port: str = 12345,
    ):
        super().__init__(idProver, idVerifier, context, params, w0, host, port)
        self.w1 = w1

    def init(self, x=None):
        if not x:
            x = secrets.randbelow(self.params.curve.field.n)
        self.x = x
        self.X = (
            self.x * self.params.P
            + int.from_bytes(self.w0, byteorder="big") * self.params.M
        )
        return self.X

    def finish(self, Y):
        if not self.is_in_subgroup(Y):
            raise InvalidInputError("invalid input")

        self.Y = Y
        self.Z = (
            self.params.h
            * self.x
            * (Y - int.from_bytes(self.w0, byteorder="big") * self.params.N)
        )
        self.V = (
            self.params.h
            * int.from_bytes(self.w1, byteorder="big")
            * (Y - int.from_bytes(self.w0, byteorder="big") * self.params.N)
        )

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.host, self.port))
            print(f"Connected to Verifier at {self.host}:{self.port}")
            self.handle_protocol(client_socket)

    def handle_protocol(self, client_socket):
        X = self.init()
        print(f"X = ({X.x}, {X.y})")
        X = encode_point_uncompressed(X, self.params.curve)
        client_socket.sendall(X)
        print(f"Sent X to verifier: {X.hex()}")

        Y = client_socket.recv(1024)  # Receive bytes
        print(f"Received Y: {Y.hex()}")
        Y = decode_point_uncompressed(Y, self.params.curve)
        print(f"Y = ({Y.x}, {Y.y})")
        self.finish(Y)

        print("Computing key schedule...")
        self.compute_key_schedule()

        confirmV, confirmP = self.confirm()
        confirmVV = client_socket.recv(1024)
        print(f"Received confirmV: {confirmV.hex()}")

        client_socket.sendall(confirmP)
        print(f"Sent confirmP to Verifier: {confirmV.hex()}")

        assert confirmV == confirmVV

        print(f"Key: {self.shared_key().hex()}")
        print("Protocol completed successfully.")

    def registration(self, password):
        input_data = (
            get_len(password)
            + password.encode("utf-8")
            + get_len(self.idProver)
            + self.idProver
            + get_len(self.idVerifier)
            + self.idVerifier
        )

        k = 64
        output_length = 2 * math.ceil(math.log(self.params.curve.field.n, 2) + k)

        kdf = Argon2id(
            salt=secrets.token_bytes(SALT_SIZE),
            length=output_length,
            iterations=3,
            lanes=4,
            memory_cost=2**16,
            ad=None,
            secret=None,
        )

        derived_key = kdf.derive(input_data)

        half_length = len(derived_key) // 2
        w0s = int.from_bytes(derived_key[:half_length], "big")
        w1s = int.from_bytes(derived_key[half_length:], "big")

        w0 = w0s % self.params.curve.field.n
        w1 = w1s % self.params.curve.field.n
        self.w0 = w0.to_bytes((w0.bit_length() + 7) // 8, "big")
        self.w1 = w1.to_bytes((w1.bit_length() + 7) // 8, "big")
        self.L = int.from_bytes(self.w1, byteorder="big") * self.params.P

        return self.w0, self.w1, encode_point_uncompressed(self.L, self.params.curve)
