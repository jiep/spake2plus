from cryptography.hazmat.primitives import hashes
from spake2plus.spake2plus import SPAKE2PLUS
from spake2plus.parameters import Parameters
from spake2plus.prover import Prover
from spake2plus.verifier import Verifier
from spake2plus.ciphersuites import *


def test_p256():
    context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
    w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
    x = "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539"
    y = "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3"
    K_shared = "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)

    x = int(x, 16)
    y = int(y, 16)

    ciphersuite = CiphersuiteP256_SHA256()
    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, context, x, y
    )

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared

