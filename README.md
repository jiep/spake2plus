# SPAKE2+

[![Python Tests](https://github.com/jiep/spake2plus/actions/workflows/test.yml/badge.svg)](https://github.com/jiep/spake2plus/actions/workflows/test.yml)
[![Lint](https://github.com/jiep/spake2plus/actions/workflows/lint.yml/badge.svg)](https://github.com/jiep/spake2plus/actions/workflows/lint.yml)
[![Build Wheel](https://github.com/jiep/spake2plus/actions/workflows/wheel.yml/badge.svg)](https://github.com/jiep/spake2plus/actions/workflows/wheel.yml)
[![Dependabot Updates](https://github.com/jiep/spake2plus/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/jiep/spake2plus/actions/workflows/dependabot/dependabot-updates)

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

## Contributing

Contributions are welcome! To contribute, follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/new-feature`).
3. Make your changes and commit them (`git commit -m 'Add new feature'`).
4. Push to your branch (git push origin feature/new-feature).
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

