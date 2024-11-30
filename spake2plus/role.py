from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from tinyec.ec import Point, Inf

from spake2plus.parameters import Parameters
from spake2plus.utils import encode_point_uncompressed, get_len, mac


class Role:
    def __init__(
        self,
        idProver: bytes,
        idVerifier: bytes,
        context: bytes,
        params: Parameters,
        w0: bytes,
        host="localhost",
        port=12345,
    ):
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.params = params
        self.context = context
        self.w0 = w0
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


    def is_in_subgroup(self, X: Point):
        infinity = Inf(self.params.curve)
        check1 = X.on_curve
        check1 = check1 and (infinity == self.params.curve.field.n * X)
        check1 = check1 and (infinity != self.params.h * X)
        return check1
