from cryptography.hazmat.primitives import hashes
import secrets

from spake2plus.utils import encode_point_uncompressed, mac, get_len
from spake2plus.parameters import Parameters
from spake2plus.prover import Prover
from spake2plus.verifier import Verifier
from spake2plus.exceptions import ConfirmingError


class SPAKE2PLUS:
    def __init__(
        self,
        params: Parameters,
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

        pw = "1234"
        salt = "salt"
        iterations = 1000

        self.prover = Prover(
            idProver, idVerifier, pw, salt.encode(), iterations, context, params
        )
        self.prover.set_w0_w1(w0, w1)
        self.verifier = Verifier(
            idProver, idVerifier, pw, salt.encode(), iterations, context, params
        )
        self.verifier.set_w0_w1(w0, w1)

        X = self.prover.init(x)
        Y = self.verifier.finish(X, y)

        self.prover.finish(Y)
        self.prover.compute_key_schedule()
        self.verifier.compute_key_schedule()

        print("K_shared->", self.prover.shared_key().hex())
        print("K_shared->", self.verifier.shared_key().hex())

        confirmVV, confirmPV = self.verifier.confirm()
        confirmVP, confirmPP = self.prover.confirm()

        if not self.prover.check(confirmVV, confirmPV) or not self.verifier.check(
            confirmVP, confirmPP
        ):
            raise ConfirmingError("error confirming")
