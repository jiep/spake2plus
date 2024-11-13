from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets

from utils import *


class Protocol:
    def __init__(self, params, idProver, idVerifier, w0, w1, context, x, y):
        self.params = params
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.context = context
        print(
            f"Running SPAKE2+ with curve {self.params.curve.name}, {self.params.hash.name.split('.')[-1].upper()}, HKDF-{self.params.kdf.name.split('.')[-1].upper()} and HMAC-{self.params.mac.name.split('.')[-1].upper()}"
        )
        prover = Prover(idProver, idVerifier, w0, w1, context, params)
        verifier = Verifier(idProver, idVerifier, w0, w1, context, params)

        X = prover.init(x)
        Y = verifier.finish(X, y)

        prover.finish(Y)
        prover.compute_key_schedule()
        verifier.compute_key_schedule()

        confirmVV, confirmPV = verifier.confirm()
        confirmVP, confirmPP = prover.confirm()

        if not prover.check(confirmVV, confirmPV) or not verifier.check(
            confirmVP, confirmPP
        ):
            print("Error")

        print(verifier.shared_key().hex())
        print(prover.shared_key().hex())


class GlobalParameters:
    def __init__(self, M, N, h, curve, hash, mac, kdf):
        self.M = M
        self.N = N
        self.P = curve.g
        self.h = h
        self.curve = curve
        self.hash = hash
        self.mac = mac
        self.kdf = kdf


class Party:
    def __init__(self, idProver, idVerifier, w0, w1, context, params):
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.w0 = w0
        self.w1 = w1
        self.params = params
        self.L = int.from_bytes(self.w1) * self.params.P
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
            algorithm=self.params.kdf, length=64, salt=None, info=b"ConfirmationKeys"
        ).derive(K_main)
        self.K_confirmP = K_confirm[:32]
        self.K_confirmV = K_confirm[32:]
        self.K_shared = HKDF(
            algorithm=self.params.kdf, length=32, salt=None, info=b"SharedKey"
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
    x: bytes

    def init(self, x):
        if not x:
            x = secrets.randbelow(self.curve.field.n)
        self.x = x
        self.X = self.x * self.params.P + int.from_bytes(self.w0) * self.params.M
        return self.X

    def finish(self, Y):
        if not Y.on_curve:
            raise "invalid input"

        self.Y = Y
        self.Z = self.params.h * self.x * (Y - int.from_bytes(self.w0) * self.params.N)
        self.V = (
            self.params.h
            * int.from_bytes(self.w1)
            * (Y - int.from_bytes(self.w0) * self.params.N)
        )


class Verifier(Party):
    y: bytes

    def finish(self, X, y):
        if not y:
            y = secrets.randbelow(self.curve.field.n)

        if not X.on_curve:
            raise "invalid input"

        self.y = y
        self.X = X
        self.Y = self.y * self.params.P + int.from_bytes(self.w0) * self.params.N
        self.Z = (
            self.params.h * self.y * (self.X - int.from_bytes(self.w0) * self.params.M)
        )
        self.V = self.params.h * self.y * self.L

        return self.Y
