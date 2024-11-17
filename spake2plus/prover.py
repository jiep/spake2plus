from spake2plus.role import Role

from cryptography.hazmat.primitives import hashes
import secrets


class Prover(Role):
    def init(self, x):
        if not x:
            x = secrets.randbelow(self.params.curve.field.n)
        self.x = x
        self.X = (
            self.x * self.params.P
            + int.from_bytes(self.w0, byteorder="big") * self.params.M
        )
        return self.X

    def finish(self, Y):
        if not Y.on_curve:
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
