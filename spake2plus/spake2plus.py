from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import secrets

from spake2plus.utils import encode_point_uncompressed, mac, get_len


class GlobalParameters:
    def __init__(self, M, N, h, curve, hash, mac, kdf, length):
        self.M = M
        self.N = N
        self.P = curve.g
        self.h = h
        self.curve = curve
        self.hash = hash
        self.mac = mac
        self.kdf = kdf
        self.length = length


class ConfirmingError(Exception):
    pass


class InvalidInputError(Exception):
    pass


class Protocol:
    def __init__(
        self,
        params: GlobalParameters,
        idProver: bytes,
        idVerifier: bytes,
        w0: bytes,
        w1: bytes,
        context: bytes,
        x: bytes,
        y: bytes,
    ):
        self.params = params
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.context = context
        print(
            f"Running SPAKE2+ with curve {self.params.curve.name}, {self.params.hash.name.split('.')[-1].upper()}, HKDF-{self.params.kdf.name.split('.')[-1].upper()} and HMAC-{self.params.mac.name.split('.')[-1].upper()}"
        )
        self.prover = Prover(idProver, idVerifier, w0, w1, context, params)
        self.verifier = Verifier(idProver, idVerifier, w0, w1, context, params)

        X = self.prover.init(x)
        Y = self.verifier.finish(X, y)

        self.prover.finish(Y)
        self.prover.compute_key_schedule()
        self.verifier.compute_key_schedule()

        confirmVV, confirmPV = self.verifier.confirm()
        confirmVP, confirmPP = self.prover.confirm()

        if not self.prover.check(confirmVV, confirmPV) or not self.verifier.check(
            confirmVP, confirmPP
        ):
            raise ConfirmingError("error confirming")


class Party:
    def __init__(self, idProver, idVerifier, w0, w1, context, params):
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.w0 = w0
        self.w1 = w1
        self.params = params
        self.L = int.from_bytes(self.w1, byteorder="big") * self.params.P
        self.context = context

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


class Prover(Party):
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


class Verifier(Party):
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
