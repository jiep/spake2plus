import argparse
import logging
from spake2plus.cli.banner import banner
from spake2plus.cli.constants import (
    CIPHERSUITE_MAP,
    CIPHERSUITE_COMPLETE_MAP,
    DEFAULT_CIPHERSUITE,
)

from spake2plus.prover import Prover
from spake2plus.verifier import Verifier
from spake2plus.utils import decode_point_uncompressed


class SPAKE2PlusCLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="SPAKE2+ Protocol")
        self.parser.add_argument(
            "-v",
            "--verbose",
            action="count",
            default=1,
            help="Increase output verbosity (e.g., -v, -vv, -vvv)",
        )

        self.parser.add_argument(
            "--host",
            default="localhost",
            help="Host to connect to (default: localhost)",
        )
        self.parser.add_argument(
            "--port",
            type=int,
            default=12345,
            help="Port to connect to (default: 12345)",
        )

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
            "registration", help="Perform registration for the Prover"
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
        args = self.parser.parse_args(args)
        verbosity = args.verbose
        self.logger = self.configure_logger(verbosity)

        self.logger.info(banner())

        if args.command == "verifier":
            self.run_verifier(args)
        elif args.command == "prover":
            self.run_prover(args)
        elif args.command == "registration":
            self.run_prover_registration(args)

    def run_verifier(self, args):
        ciphersuite = CIPHERSUITE_MAP[args.ciphersuite]()
        self.logger.debug(f"Ciphersuite: {CIPHERSUITE_COMPLETE_MAP[args.ciphersuite]}")
        self.logger.info(f"Ciphersuite: {args.ciphersuite}")
        verifier = Verifier(
            args.idProver.encode(),
            args.idVerifier.encode(),
            args.context.encode(),
            ciphersuite.params,
            bytes.fromhex(args.w0),
            decode_point_uncompressed(bytes.fromhex(args.L), ciphersuite.params.curve),
            self.logger,
            args.host,
            args.port,
        )
        verifier.start()

    def run_prover(self, args):
        ciphersuite = CIPHERSUITE_MAP[args.ciphersuite]()
        self.logger.debug(f"Ciphersuite: {CIPHERSUITE_COMPLETE_MAP[args.ciphersuite]}")
        self.logger.info(f"Ciphersuite: {args.ciphersuite}")
        prover = Prover(
            args.idProver.encode(),
            args.idVerifier.encode(),
            args.context.encode(),
            ciphersuite.params,
            bytes.fromhex(args.w0),
            bytes.fromhex(args.w1),
            self.logger,
            args.host,
            args.port,
        )
        prover.start()

    def run_prover_registration(self, args):
        ciphersuite = CIPHERSUITE_MAP[args.ciphersuite]()
        self.logger.debug(f"Ciphersuite: {CIPHERSUITE_COMPLETE_MAP[args.ciphersuite]}")
        self.logger.info(f"Ciphersuite: {args.ciphersuite}")
        prover = Prover(
            args.idProver.encode(),
            args.idVerifier.encode(),
            None,
            ciphersuite.params,
            None,
            self.logger,
            None,
            None,
        )
        w0, w1, L = prover.registration(args.password)
        self.logger.info(f"w0 = {w0.hex()}")
        self.logger.info(f"w1 = {w1.hex()}")
        self.logger.info(f"L  = {L.hex()}")

    @staticmethod
    def configure_logger(verbosity: int) -> logging.Logger:
        levels = [logging.WARNING, logging.INFO, logging.DEBUG]
        level = levels[min(len(levels) - 1, verbosity)]

        logger = logging.getLogger("spake2plus")
        logger.setLevel(level)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger


def main():
    cli = SPAKE2PlusCLI()
    cli.run()


if __name__ == "__main__":
    main()
