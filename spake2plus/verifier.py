from spake2plus.role import Role

from cryptography.hazmat.primitives import hashes
import secrets


class Verifier(Role):
    def finish(self, X, y):
        if not y:
            y = secrets.randbelow(self.params.curve.field.n)

        if not X.on_curve:
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
