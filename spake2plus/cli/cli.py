import sys
import argparse

from spake2plus.ciphersuites import CiphersuiteP256_SHA256, CiphersuiteP256_SHA512, CiphersuiteP384_SHA256, CiphersuiteP384_SHA512, CiphersuiteP521_SHA512
from spake2plus.prover import Prover
from spake2plus.verifier import Verifier


def main():
    parser = argparse.ArgumentParser(
        prog='spake2+',
        description='SPAKE2+ protocol')

    ROLES = ['prover', 'verifier']
    CIPHERSUITES = ["P256-SHA256", "P256-SHA512", "P384-SHA256", "P384-SHA512", "P521-SHA512"]
    
    parser = argparse.ArgumentParser()
    required = parser.add_argument_group('required arguments')
    required.add_argument("role", choices=ROLES)
    required.add_argument('--idProver', required=True)
    required.add_argument('--idVerifier', required=True)
    required.add_argument('--context', required=True)
    required.add_argument("--ciphersuite", choices=CIPHERSUITES, default=CIPHERSUITES[0])

    args = parser.parse_args()

    ciphersuite: Ciphersuite

    match args.ciphersuite:
        case "P256-SHA256": ciphersuite = CiphersuiteP256_SHA256()
        case "P256-SHA512": ciphersuite = CiphersuiteP256_SHA512()
        case "P384-SHA256": ciphersuite = CiphersuiteP384_SHA256()
        case "P384-SHA512": ciphersuite = CiphersuiteP384_SHA512()
        case "P521-SHA512": ciphersuite = CiphersuiteP521_SHA512()

    w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
    w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)

    match args.role:
        case "prover":
            prover = Prover(args.idProver.encode(), args.idVerifier.encode(), w0, w1, args.context.encode(), ciphersuite.params)
            prover.start()
        case "verifier":
            verifier = Verifier(args.idProver.encode(), args.idVerifier.encode(), w0, w1, args.context.encode(), ciphersuite.params)
            verifier.start()

