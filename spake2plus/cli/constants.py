from spake2plus.ciphersuites.ciphersuites import (
    CiphersuiteP256_SHA256,
    CiphersuiteP256_SHA512,
    CiphersuiteP384_SHA256,
    CiphersuiteP384_SHA512,
    CiphersuiteP521_SHA512,
    CiphersuiteEdwards25519_SHA256,
    CiphersuiteEdwards448_SHA512
)

CIPHERSUITE_MAP = {
    "P256-SHA256": CiphersuiteP256_SHA256,
    "P256-SHA512": CiphersuiteP256_SHA512,
    "P384-SHA256": CiphersuiteP384_SHA256,
    "P384-SHA512": CiphersuiteP384_SHA512,
    "P521-SHA512": CiphersuiteP521_SHA512,
    "Edwards25519-SHA256": CiphersuiteEdwards25519_SHA256,
    "Edwards448-SHA512": CiphersuiteEdwards448_SHA512,
}

CIPHERSUITE_COMPLETE_MAP = {
    "P256-SHA256": "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256-Argon2id",
    "P256-SHA512": "SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512-Argon2id",
    "P384-SHA256": "SPAKE2+-P384-SHA256-HKDF-SHA256-HMAC-SHA256-Argon2id",
    "P384-SHA512": "SPAKE2+-P384-SHA512-HKDF-SHA512-HMAC-SHA512-Argon2id",
    "P521-SHA512": "SPAKE2+-P521-SHA512-HKDF-SHA512-HMAC-SHA512-Argon2id",
    "Edwards25519-SHA256": "SPAKE2+-Edwards25519-SHA256-HKDF-SHA256-HMAC-SHA256-Argon2id",
    "Edwards448-SHA512": "SPAKE2+-Edwards448-SHA512-HKDF-SHA512-HMAC-SHA512-Argon2id",
}

DEFAULT_CIPHERSUITE = list(CIPHERSUITE_MAP.keys())[0]
