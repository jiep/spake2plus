# SPAKE2+

**SPAKE2+** is a Python 3 implementation of SPAKE2+ protocol, according to [RFC 9383
SPAKE2+, an Augmented Password-Authenticated Key Exchange (PAKE) Protocol](https://www.rfc-editor.org/rfc/rfc9383.html).

## Protocol overview

```
                 Prover                     Verifier

                   |        (registration)     |
                   |<- - - - - - - - - - - - ->|
                   |                           |
                   |   (set up the protocol)   |
(compute shareP)   |            shareP         |
                   |-------------------------->|
                   |            shareV         | (compute shareV)
                   |<--------------------------|
                   |                           |
                   |       (derive secrets)    | (compute confirmV)
                   |           confirmV        |
                   |<--------------------------|
(compute confirmP) |           confirmP        |
                   |-------------------------->|
```

## Requirements

This package requires the following dependencies:

* `cryptography==43.0.3`
* `tinyec==0.4.0`

All dependencies are automatically installed when you install the package via `pip`.

## Installation

You can install this package locally using `pip`:

```bash
pip install -e .
```

## Usage

```bash
usage: spake2plus [-h] --idProver IDPROVER --idVerifier IDVERIFIER --context CONTEXT --password
                  PASSWORD --salt SALT [--iterations ITERATIONS]
                  [--ciphersuite {P256-SHA256,P256-SHA512,P384-SHA256,P384-SHA512,P521-SHA512}]
                  {prover,verifier}
```

### Example: Verifier

The `Verifier` acts as a server in the protocol. You can run it as follows:

```bash

spake2plus verifier  --idProver alice --idVerifier bob --context 1234 --password 1234 --salt 1234
```

The `Prover` acts as a client in the protocol. You can run it as follows:

```bash
spake2plus prover --idProver alice --idVerifier bob --context 1234 --password 1234 --salt 1234
```

> [!NOTE]  
> If not specified ciphersuite, P256-SHA256 is used by default.
> Ciphersuites allowed: P256-SHA256, P256-SHA512, P384-SHA256, P384-SHA512,and P521-SHA512.

> [!WARNING]  
> Salt must have a length of 32 bytes at least!

> [!WARNING]  
> `idProvider`, `idVerifier`, `context`, `password`, and `salt` must be the same for `Prover` and `Verifier`! 


## Contributing

Contributions are welcome! To contribute, follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/new-feature`).
3. Make your changes and commit them (`git commit -m 'Add new feature'`).
4. Push to your branch (git push origin feature/new-feature).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Disclaimer

> [!CAUTION]
This code has not been audited or formally reviewed for security. Use it at your own risk and only for educational purposes or in non-critical environments.