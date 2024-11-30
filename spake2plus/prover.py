from spake2plus.exceptions import InvalidInputError
from spake2plus.role import Role
from spake2plus.utils import encode_point_uncompressed, decode_point_uncompressed

import secrets
import socket


class Prover(Role):
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
