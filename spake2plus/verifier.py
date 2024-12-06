from spake2plus.exceptions import InvalidInputError
from spake2plus.role import Role
from spake2plus.utils import decode_point_uncompressed, encode_point_uncompressed
from tinyec.ec import Point

import secrets
import socket

BUFFER_SIZE = 1024


class Verifier(Role):
    def __init__(
        self,
        idProver,
        idVerifier,
        context,
        params,
        w0: bytes,
        L: Point,
        logger,
        host="localhost",
        port=12345,
    ):
        super().__init__(idProver, idVerifier, context, params, w0, logger, host, port)
        self.L = L

    def finish(self, X, y=None):
        if not y:
            y = secrets.randbelow(self.params.curve.field.n)

        if not self.is_in_subgroup(X):
            raise InvalidInputError("invalid input")

        self.y = y
        self.X = X
        self.Y = (
            self.y * self.params.P
            + int.from_bytes(self.w0, byteorder="big") * self.params.N
        )
        self.Z = (
            self.params.h
            * self.y
            * (self.X - int.from_bytes(self.w0, byteorder="big") * self.params.M)
        )
        self.V = self.params.h * self.y * self.L

        return self.Y

    def handle_client(self, conn):
        X = conn.recv(BUFFER_SIZE)
        self.logger.info(f"P -> V [{len(X)}]: X = {X.hex()}")
        X = decode_point_uncompressed(X, self.params.curve)
        self.logger.debug(f"V: X = ({X.x}, {X.y})")

        Y = self.finish(X)
        self.logger.debug(f"V: Y = ({Y.x}, {Y.y})")
        Y = encode_point_uncompressed(Y, self.params.curve)
        conn.sendall(Y)
        self.logger.info(f"P <- V [{len(Y)}]: Y = {Y.hex()}")

        self.logger.info("V: Computing key schedule...")
        self.compute_key_schedule()
        confirmV, confirmP = self.confirm()
        conn.sendall(confirmV)
        self.logger.info(f"P <- V [{len(confirmV)}]: confirmV = {confirmV.hex()}")

        confirmPP = conn.recv(BUFFER_SIZE)
        self.logger.info(f"P -> V [[{len(confirmP)}]]: confirmP = {confirmP.hex()}")

        assert confirmP == confirmPP

        self.logger.debug(
            f"V [{len(self.shared_key())}]: Key = {self.shared_key().hex()}"
        )
        self.logger.info("V: Protocol completed successfully.")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            self.logger.info(f"Verifier is listening on {self.host}:{self.port}...")

            conn, _ = server_socket.accept()
            with conn:
                self.handle_client(conn)
