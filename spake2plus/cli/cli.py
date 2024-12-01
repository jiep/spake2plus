import argparse

from spake2plus.ciphersuites import (
    CiphersuiteP256_SHA256,
    CiphersuiteP256_SHA512,
    CiphersuiteP384_SHA256,
    CiphersuiteP384_SHA512,
    CiphersuiteP521_SHA512,
)
from spake2plus.prover import Prover
from spake2plus.utils import decode_point_uncompressed
from spake2plus.verifier import Verifier
from spake2plus.cli.banner import banner
from spake2plus.logger_config import get_logger


import argparse

CIPHERSUITE_MAP = {
    "P256-SHA256": CiphersuiteP256_SHA256,
    "P256-SHA512": CiphersuiteP256_SHA512,
    "P384-SHA256": CiphersuiteP384_SHA256,
    "P384-SHA512": CiphersuiteP384_SHA512,
    "P521-SHA512": CiphersuiteP521_SHA512,
}

DEFAULT_CIPHERSUITE = list(CIPHERSUITE_MAP.keys())[0]

logger = get_logger("CLI")

class SPAKE2PlusCLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="SPAKE2+ Protocol")
        self.subparsers = self.parser.add_subparsers(dest="command", required=True)

        self._add_verifier_command()
        self._add_prover_command()
        self._add_prover_registration_command()

    def _add_verifier_command(self):
        parser_verifier = self.subparsers.add_parser(
            "verifier", help="Run the verifier role in the SPAKE2+ protocol"
        )
        parser_verifier.add_argument(
            "--idProver", required=True, help="Prover's identity"
        )
        parser_verifier.add_argument(
            "--idVerifier", required=True, help="Verifier's identity"
        )
        parser_verifier.add_argument(
            "--context", required=True, help="Protocol context"
        )
        parser_verifier.add_argument(
            "--w0", required=True, help="Value for w0 as hexadecimal string"
        )
        parser_verifier.add_argument(
            "--L", required=True, help="Value for L as hexadecimal string"
        )
        parser_verifier.add_argument(
            "--ciphersuite",
            required=False,
            choices=list(CIPHERSUITE_MAP.keys()),
            default=DEFAULT_CIPHERSUITE,
            help=f"Ciphersuite to use (default: {DEFAULT_CIPHERSUITE})",
        )

    def _add_prover_command(self):
        parser_prover = self.subparsers.add_parser(
            "prover", help="Run the prover role in the SPAKE2+ protocol"
        )
        parser_prover.add_argument(
            "--idProver", required=True, help="Prover's identity"
        )
        parser_prover.add_argument(
            "--idVerifier", required=True, help="Verifier's identity"
        )
        parser_prover.add_argument("--context", required=True, help="Protocol context")
        parser_prover.add_argument(
            "--w0", required=True, help="Value for w0 as hexadecimal string"
        )
        parser_prover.add_argument(
            "--w1", required=True, help="Value for w1 as hexadecimal string"
        )
        parser_prover.add_argument(
            "--ciphersuite",
            required=False,
            choices=list(CIPHERSUITE_MAP.keys()),
            default=DEFAULT_CIPHERSUITE,
            help=f"Ciphersuite to use (default: {DEFAULT_CIPHERSUITE})",
        )

    def _add_prover_registration_command(self):
        parser_registration = self.subparsers.add_parser(
            "registration", help="Perform registration for the Prover", add_help=False
        )
        parser_registration.add_argument(
            "--password", required=True, help="Password for key generation"
        )
        parser_registration.add_argument(
            "--idProver", required=True, help="Prover's identity"
        )
        parser_registration.add_argument(
            "--idVerifier", required=True, help="Verifier's identity"
        )
        parser_registration.add_argument(
            "--ciphersuite",
            required=False,
            choices=list(CIPHERSUITE_MAP.keys()),
            default=DEFAULT_CIPHERSUITE,
            help=f"Ciphersuite to use (default: {DEFAULT_CIPHERSUITE})",
        )

    def run(self, args=None):
        logger.info(banner())

        args = self.parser.parse_args(args)
        if args.command == "verifier":
            self.run_verifier(args)
        elif args.command == "prover":
            self.run_prover(args)
        elif args.command == "registration":
            self.run_prover_registration(args)

    def run_verifier(self, args):
        ciphersuite = CIPHERSUITE_MAP[args.ciphersuite]()
        verifier = Verifier(
            args.idProver.encode(),
            args.idVerifier.encode(),
            args.context.encode(),
            ciphersuite.params,
            bytes.fromhex(args.w0),
            decode_point_uncompressed(bytes.fromhex(args.L), ciphersuite.params.curve),
        )
        verifier.start()

    def run_prover(self, args):
        ciphersuite = CIPHERSUITE_MAP[args.ciphersuite]()
        prover = Prover(
            args.idProver.encode(),
            args.idVerifier.encode(),
            args.context.encode(),
            ciphersuite.params,
            bytes.fromhex(args.w0),
            bytes.fromhex(args.w1),
        )
        prover.start()

    def run_prover_registration(self, args):

        ciphersuite = CIPHERSUITE_MAP[args.ciphersuite]()
        prover = Prover(
            args.idProver.encode(),
            args.idVerifier.encode(),
            None,
            ciphersuite.params,
            None,
            None,
            None,
        )
        w0, w1, L = prover.registration(args.password)
        logger.info(f"Ciphersuite: {args.ciphersuite}")
        logger.info(f"w0 = {w0.hex()}")
        logger.info(f"w1 = {w1.hex()}")
        logger.info(f"L  = {L.hex()}")


def main():
    cli = SPAKE2PlusCLI()
    cli.run()
