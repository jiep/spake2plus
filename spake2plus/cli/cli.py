import sys
import argparse

from spake2plus.ciphersuites import (
    Ciphersuite,
    CiphersuiteP256_SHA256,
    CiphersuiteP256_SHA512,
    CiphersuiteP384_SHA256,
    CiphersuiteP384_SHA512,
    CiphersuiteP521_SHA512,
)
from spake2plus.prover import Prover
from spake2plus.verifier import Verifier
from spake2plus import __version__

def banner():
    print(f"""
███████ ██████   █████  ██   ██ ███████ ██████  ██████  ██      ██    ██ ███████ 
██      ██   ██ ██   ██ ██  ██  ██           ██ ██   ██ ██      ██    ██ ██      
███████ ██████  ███████ █████   █████    █████  ██████  ██      ██    ██ ███████ 
     ██ ██      ██   ██ ██  ██  ██      ██      ██      ██      ██    ██      ██ 
███████ ██      ██   ██ ██   ██ ███████ ███████ ██      ███████  ██████  ███████
                                                                          v{__version__} 
    """)

def main():
    parser = argparse.ArgumentParser(prog="spake2plus", description="SPAKE2+ protocol")

    banner()

    ROLES = ["prover", "verifier"]
    CIPHERSUITES = [
        "P256-SHA256",
        "P256-SHA512",
        "P384-SHA256",
        "P384-SHA512",
        "P521-SHA512",
    ]

    parser = argparse.ArgumentParser()
    required = parser.add_argument_group("required arguments")
    required.add_argument("role", choices=ROLES)
    required.add_argument("--idProver", required=True)
    required.add_argument("--idVerifier", required=True)
    required.add_argument("--context", required=True)
    required.add_argument("--password", required=True)
    required.add_argument("--salt", required=True)
    required.add_argument("--iterations", type=int, default=100000)
    required.add_argument(
        "--ciphersuite", choices=CIPHERSUITES, default=CIPHERSUITES[0]
    )

    args = parser.parse_args()

    match args.ciphersuite:
        case "P256-SHA256":
            ciphersuite = CiphersuiteP256_SHA256()
        case "P256-SHA512":
            ciphersuite = CiphersuiteP256_SHA512()
        case "P384-SHA256":
            ciphersuite = CiphersuiteP384_SHA256()
        case "P384-SHA512":
            ciphersuite = CiphersuiteP384_SHA512()
        case "P521-SHA512":
            ciphersuite = CiphersuiteP521_SHA512()

    match args.role:
        case "prover":
            prover = Prover(
                args.idProver.encode(),
                args.idVerifier.encode(),
                args.password,
                args.salt.encode(),
                args.iterations,
                args.context.encode(),
                ciphersuite.params,
            )
            prover.start()
        case "verifier":
            verifier = Verifier(
                args.idProver.encode(),
                args.idVerifier.encode(),
                args.password,
                args.salt.encode(),
                args.iterations,
                args.context.encode(),
                ciphersuite.params,
            )
            verifier.start()
