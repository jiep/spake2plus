import sys

from spake2plus.ciphersuites import CiphersuiteP256_SHA256
from spake2plus.prover import Prover
from spake2plus.verifier import Verifier


def run_prover():
    idProver = b"alice"
    idVerifier = b"bob"
    context = b"protocol"
    ciphersuite = CiphersuiteP256_SHA256()
    w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
    w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    prover = Prover(idProver, idVerifier, w0, w1, context, ciphersuite.params)
    prover.start()


def run_verifier():
    idProver = b"alice"
    idVerifier = b"bob"
    context = b"protocol"
    ciphersuite = CiphersuiteP256_SHA256()
    w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
    w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    verifier = Verifier(idProver, idVerifier, w0, w1, context, ciphersuite.params)
    verifier.start()


def main():
    role = sys.argv[1]

    if role == "prover":
        run_prover()
    else:
        run_verifier()
