# SPAKE2+

[![Python Tests](https://github.com/jiep/spake2plus/actions/workflows/test.yml/badge.svg)](https://github.com/jiep/spake2plus/actions/workflows/test.yml)
[![Lint](https://github.com/jiep/spake2plus/actions/workflows/lint.yml/badge.svg)](https://github.com/jiep/spake2plus/actions/workflows/lint.yml)
[![Build Wheel](https://github.com/jiep/spake2plus/actions/workflows/wheel.yml/badge.svg)](https://github.com/jiep/spake2plus/actions/workflows/wheel.yml)
[![Dependabot Updates](https://github.com/jiep/spake2plus/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/jiep/spake2plus/actions/workflows/dependabot/dependabot-updates)

**SPAKE2+** is a Python 3 implementation of SPAKE2+ protocol, according to [RFC 9383
SPAKE2+, an Augmented Password-Authenticated Key Exchange (PAKE) Protocol](https://www.rfc-editor.org/rfc/rfc9383.html).

## What is SPAKE2+?

SPAKE2+ is a cryptographic protocol designed to establish a shared secret between two parties (Prover and Verifier) over an insecure channel. It is an augmentation of the SPAKE2 protocol, adding explicit identities to prevent key compromise impersonation (KCI) attacks. 

The protocol is efficient, secure, and suitable for password-based authenticated key exchange (PAKE). Unlike traditional methods that transmit hashed passwords or challenge-responses, SPAKE2+ ensures the shared secret is derived without exposing the password, even in the presence of eavesdroppers or active attackers.

### Key Features:
1. **Password-Based Authentication**: Ensures both parties authenticate using a shared password, protecting against unauthorized access.
2. **Implicit Mutual Authentication**: If the protocol succeeds, both parties confirm they share the same password.
3. **Resistance to KCI Attacks**: Explicit identities (`idProver` and `idVerifier`) are incorporated into the protocol to prevent impersonation by a compromised party.
4. **Elliptic Curve Cryptography (ECC)**: Leverages ECC for computational efficiency and security.
5. **No Password Exposure**: The password itself is never transmitted or derived directly during the protocol.

### How it Works:
1. **Registration Phase**: Both parties exchange public parameters to initialize the protocol securely.
2. **Password Derivation**: The shared password is processed with Argon2id, using explicit identities (`idProver` and `idVerifier`) and the hash function of the ciphersuite, to derive keying material.
2. **Key Exchange**: The Prover and Verifier compute and exchange values (`X`, `Y`) to establish a shared secret.
3. **Verification**: Both parties derive cryptographic secrets (`confirmP`, `confirmV`) to verify the integrity of the exchange and finalize authentication.

SPAKE2+ is commonly used in applications requiring secure password-based authentication without relying on a trusted third party. It is especially suitable for environments where both parties already share a secret (like a password) and need to establish a secure communication channel.


### Protocol overview

```mermaid

sequenceDiagram
    participant Prover
    participant Verifier

    Note over Prover, Verifier: password
    Prover<<->>Verifier: Registration

    Note over Prover, Verifier: w0, w1

    Note left of Prover: x <- [0, p-1]<br/>X = x*P + w0*M
    Prover->>Verifier: X
    Note right of Verifier: y <- [0, p-1]<br/>Y = y*P + w0*N
    Verifier->>Prover: Y
    Note left of Prover: Z = h*x*(Y - w0*N)<br/>V = h*w1*(Y - w0*N)
    Note right of Verifier: Z = h*y*(X - w0*M)<br/>V = h*y*L

    Note over Prover,Verifier: Compute transcript TT<br/>K_main = Hash(TT)<br/>K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")<br/>K_shared = KDF(nil, K_main, "SharedKey")
    
    Note right of Verifier: confirmP = MAC(K_confirmV, Y)

    Verifier->>Prover: confirmV
    Note left of Prover: confirmV = MAC(K_confirmV, X)<br/>expected_confirmV = MAC(K_confirmV, X)<br/>equal_constant_time(expected_confirmV, confirmV)
    Prover->>Verifier: confirmP

    Note right of Verifier: expected_confirmP = MAC(K_confirmP, Y)<br/>equal_constant_time(expected_confirmP, confirmP)
```

## Requirements

This package requires the following dependencies:

* `cryptography==44.0.0`
* `tinyec==0.4.0`

All dependencies are automatically installed when you install the package via `pip`.

## Installation

You can install this package locally using `pip`:

```bash
pip install -e .
```

## Usage

```bash 
usage: spake2plus [-h] [-v] [--host HOST] [--port PORT]
                  {verifier,prover,registration} ...

SPAKE2+ Protocol

positional arguments:
  {verifier,prover,registration}
    verifier            Run the verifier role in the
                        SPAKE2+ protocol
    prover              Run the prover role in the SPAKE2+
                        protocol
    registration        Perform registration for the Prover

options:
  -h, --help            show this help message and exit
  -v, --verbose         Increase output verbosity (e.g.,
                        -v, -vv, -vvv)
  --host HOST           Host to connect to (default:
                        localhost)
  --port PORT           Port to connect to (default: 12345)
```

### Offline registration

The `Prover` computes the values `w0` and `w1`, as well as the registration record `L`. `w0` and `w1` are derived by hashing the password with the identities of the two participants. `w0` and the record `L` are then shared with the `Verifier`. 

```bash
usage: spake2plus registration [-h] --password PASSWORD --idProver IDPROVER
                               --idVerifier IDVERIFIER
                               [--ciphersuite {P256-SHA256,P256-SHA512,P384-SHA256,P384-SHA512,P521-SHA512}]

options:
  -h, --help            show this help message and exit
  --password PASSWORD   Password for key generation
  --idProver IDPROVER   Prover's identity
  --idVerifier IDVERIFIER
                        Verifier's identity
  --ciphersuite {P256-SHA256,P256-SHA512,P384-SHA256,P384-SHA512,P521-SHA512}
                        Ciphersuite to use (default: P256-SHA256)
```

### Verifier

```bash
usage: spake2plus verifier [-h] --idProver IDPROVER --idVerifier IDVERIFIER
                           --context CONTEXT --w0 W0 --L L
                           [--ciphersuite {P256-SHA256,P256-SHA512,P384-SHA256,P384-SHA512,P521-SHA512}]

options:
  -h, --help            show this help message and exit
  --idProver IDPROVER   Prover's identity
  --idVerifier IDVERIFIER
                        Verifier's identity
  --context CONTEXT     Protocol context
  --w0 W0               Value for w0 as hexadecimal string
  --L L                 Value for L as hexadecimal string
  --ciphersuite {P256-SHA256,P256-SHA512,P384-SHA256,P384-SHA512,P521-SHA512}
                        Ciphersuite to use (default: P256-SHA256)
```

### Prover

```bash
usage: spake2plus prover [-h] --idProver IDPROVER --idVerifier IDVERIFIER --context
                         CONTEXT --w0 W0 --w1 W1
                         [--ciphersuite {P256-SHA256,P256-SHA512,P384-SHA256,P384-SHA512,P521-SHA512}]

options:
  -h, --help            show this help message and exit
  --idProver IDPROVER   Prover's identity
  --idVerifier IDVERIFIER
                        Verifier's identity
  --context CONTEXT     Protocol context
  --w0 W0               Value for w0 as hexadecimal string
  --w1 W1               Value for w1 as hexadecimal string
  --ciphersuite {P256-SHA256,P256-SHA512,P384-SHA256,P384-SHA512,P521-SHA512}
                        Ciphersuite to use (default: P256-SHA256)
```

## Examples

### Registration

```bash
$ spake2plus registration --password superImporT4antPassWord! --idProver alice --idVerifier bob --ciphersuite P256-SHA256

2024-12-01 14:06:51.789 [INFO] Ciphersuite: P256-SHA256
2024-12-01 14:06:52.048 [INFO] w0 = 3bccdf7f0940907dac69758d327eb9c40c5a7f95ee63a80e042e5473ce789e76
2024-12-01 14:06:52.048 [INFO] w1 = 59f7bce5c93c087e114d95b542f100124e1814be7f383c376a9a441045092a0b
2024-12-01 14:06:52.048 [INFO] L  = 04c9b019fbe6d4e727dfd9cd831f3c36a6fec8b05972bed62d3b0493c8cfc2163dc739cda27dcb7aa6726008f7312281d9ffe61edc178af1f26a96a1a6dc6cfbc4
```

### Verifier

The `Verifier` acts as a server in the protocol. You can run it as follows:

```bash
spake2plus verifier --idProver alice --idVerifier bob --context KeyExchange --w0 3bccdf7f0940907dac69758d327eb9c40c5a7f95ee63a80e042e5473ce789e76 --L 04c9b019fbe6d4e727dfd9cd831f3c36a6fec8b05972bed62d3b0493c8cfc2163dc739cda27dcb7aa6726008f7312281d9ffe61edc178af1f26a96a1a6dc6cfbc4 --ciphersuite P256-SHA256
```

<details>

<summary>Show output</summary>

```bash
2024-12-01 14:11:45.727 [INFO] Ciphersuite: P256-SHA256
2024-12-01 14:11:45.728 [INFO] Verifier is listening on localhost:12345...
2024-12-01 14:13:04.771 [INFO] P -> V [65]: X = 04dfc96734066fd75a4093d402f33945312f71637c8515524cd44736d0d762cd8a162a72d868fb5e155908f01af1319f69739f6591451ca9978b6bb64a4c4383a8
2024-12-01 14:13:04.886 [INFO] P <- V [65]: Y = 04835bd8437b2dd3bd920dcbb3aa81c72874e8bdb81aa76c3c2b99a7e9ca22ad397dd844c701eb77264d61f13926a5fc3730d100bb08e4935d770885392d29e1dd
2024-12-01 14:13:04.887 [INFO] V: Computing key schedule...
2024-12-01 14:13:04.888 [INFO] P <- V [32]: confirmV = ab44635917470ac4cf52130c881749151e544b8f4fcc987aad2e64afc5201665
2024-12-01 14:13:04.979 [INFO] P -> V [[32]]: confirmP = d97eba35ac718b69bc8549bb5d73646d42d68739cf392f4d346eab88a6e556a3
2024-12-01 14:13:04.979 [INFO] V: Protocol completed successfully.
```
</details>

### Prover

The `Prover` acts as a client in the protocol. You can run it as follows:

```bash
spake2plus prover --idProver alice --idVerifier bob --context KeyExchange --w0 3bccdf7f0940907dac69758d327eb9c40c5a7f95ee63a80e042e5473ce789e76 --w1 59f7bce5c93c087e114d95b542f100124e1814be7f383c376a9a441045092a0b --ciphersuite P256-SHA256
```

<details>

<summary>Show output</summary>

```bash
2024-12-01 14:13:04.724 [INFO] Ciphersuite: P256-SHA256
2024-12-01 14:13:04.725 [INFO] Connected to Verifier at localhost:12345
2024-12-01 14:13:04.771 [INFO] P -> V [65]: X = 04dfc96734066fd75a4093d402f33945312f71637c8515524cd44736d0d762cd8a162a72d868fb5e155908f01af1319f69739f6591451ca9978b6bb64a4c4383a8]
2024-12-01 14:13:04.886 [INFO] P <- V [65]: Y = 04835bd8437b2dd3bd920dcbb3aa81c72874e8bdb81aa76c3c2b99a7e9ca22ad397dd844c701eb77264d61f13926a5fc3730d100bb08e4935d770885392d29e1dd
2024-12-01 14:13:04.977 [INFO] P: Computing key schedule...
2024-12-01 14:13:04.979 [INFO] P <- V [32]: confirmV = ab44635917470ac4cf52130c881749151e544b8f4fcc987aad2e64afc5201665
2024-12-01 14:13:04.979 [INFO] P -> V [32]: confirmP = d97eba35ac718b69bc8549bb5d73646d42d68739cf392f4d346eab88a6e556a3
2024-12-01 14:13:04.979 [INFO] P: Protocol completed successfully.
```
</details>

> [!NOTE]  
> If not specified ciphersuite, `P256-SHA256` is used by default.
>
> Ciphersuites allowed: `P256-SHA256`, `P256-SHA512`, `P384-SHA256`, `P384-SHA512`, and `P521-SHA512`.

> [!WARNING]  
> `idProvider`, `idVerifier`, `context`  must be the identical for `Prover` and `Verifier`! 


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