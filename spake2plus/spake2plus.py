from spake2plus.parameters import Parameters
from spake2plus.prover import Prover
from spake2plus.verifier import Verifier
from spake2plus.exceptions import ConfirmingError

from tinyec.ec import Point


class SPAKE2PLUS:
    def __init__(
        self,
        params: Parameters,
        idProver: bytes,
        idVerifier: bytes,
        w0: bytes,
        w1: bytes,
        L: Point,
        context: bytes,
        x: bytes,
        y: bytes,
    ):
        self.params = params
        self.idProver = idProver
        self.idVerifier = idVerifier
        self.context = context

        self.prover = Prover(idProver, idVerifier, context, params, w0, w1, None)

        self.verifier = Verifier(idProver, idVerifier, context, params, w0, L, None)
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
