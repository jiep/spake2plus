from spake2plus.exceptions import InvalidInputError
from spake2plus.role import Role
from spake2plus.utils import decode_point_uncompressed, encode_point_uncompressed
from spake2plus.logger_config import get_logger
from tinyec.ec import Point

import secrets
import socket


logger = get_logger("Verifier")


class Verifier(Role):
    def __init__(
        self,
        idProver,
        idVerifier,
        context,
        params,
        w0: bytes,
        L: Point,
        host="localhost",
        port=12345,
    ):
        super().__init__(idProver, idVerifier, context, params, w0, host, port)
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
        X = conn.recv(1024)
        logger.info(f"Received X from Prover: {X.hex()}")
        X = decode_point_uncompressed(X, self.params.curve)
        logger.debug(f"X = ({X.x}, {X.y})")

        Y = self.finish(X)
        logger.debug(f"Y = ({Y.x}, {Y.y})")
        Y = encode_point_uncompressed(Y, self.params.curve)
        conn.sendall(Y)
        logger.info(f"Sent Y to Verifier: {Y.hex()}")

        logger.info("Computing key schedule...")
        self.compute_key_schedule()
        confirmV, confirmP = self.confirm()
        conn.sendall(confirmV)
        logger.info(f"Sent confirmV to Prover: {confirmV.hex()}")

        confirmPP = conn.recv(1024)
        logger.info(f"Received X from Prover: {confirmP.hex()}")

        assert confirmP == confirmPP

        logger.debug(f"Key: {self.shared_key().hex()}")
        logger.info("Protocol completed successfully.")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            logger.info(f"Verifier is listening on {self.host}:{self.port}...")

            conn, _ = server_socket.accept()
            with conn:
                self.handle_client(conn)
