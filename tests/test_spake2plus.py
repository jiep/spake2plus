import pytest
from spake2plus.exceptions.exceptions import ConfirmingError, InvalidInputError
from spake2plus.roles.prover import Prover
from spake2plus.protocol.spake2plus import SPAKE2PLUS
from spake2plus.ciphersuites.ciphersuites import (
    CiphersuiteP256_SHA256,
    CiphersuiteP256_SHA512,
    CiphersuiteP384_SHA256,
    CiphersuiteP384_SHA512,
    CiphersuiteP521_SHA512,
    CiphersuiteEdwards25519_SHA256,
    CiphersuiteEdwards448_SHA512,
)
from spake2plus.utils.utils import decode_point_uncompressed, encode_point_uncompressed
from spake2plus.roles.verifier import Verifier


def test_p256():
    ciphersuite = CiphersuiteP256_SHA256()
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
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P
    x = int(x, 16)
    y = int(y, 16)

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_p256_2():
    ciphersuite = CiphersuiteP256_SHA512()
    context = b"SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "1cc5207d6e34b8f7828206fb64b86aa9c712bc952abf251bb9f5856b24d8c8cc"
    w1 = "4279649e62532b01dc27d2ed39100ba350518fb969672061a01edce752d0e672"
    x = "b586ab83f175c1a2b56b6a1b6a283523f88a9befcf11e22efb48e2ee1fe69a23"
    y = "ac1fb828f041782d452ea9cc00c3fa34a55fa8f7f98c04be45a3d607b092d441"
    K_shared = "11887659d9e002f34fa6cc270d33570f001b2a3fc0522b643c07327d09a4a9f47aab85813d13c585b53adf5ac9de5707114848f3dc31a4045f69a2cc1972b098"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P
    x = int(x, 16)
    y = int(y, 16)

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_p384():
    ciphersuite = CiphersuiteP384_SHA256()
    context = b"SPAKE2+-P384-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "097a61cbb1cee72bb654be96d80f46e0e3531151003903b572fc193f233772c23c22228884a0d5447d0ab49a656ce1d2"
    w1 = "18772816140e6c3c3938a693c600b2191118a34c7956e1f1cd5b0d519b56ea5858060966cfaf27679c9182129949e74f"
    x = "2f1bdbeda162ff2beba0293d3cd3ae95f663c53663378c7e18ee8f56a4a48b00d31ce0ef43606548da485058f12e8e73"
    y = "bbcaf02404a16ed4fa73b183f703a8d969386f3d34f5e98b3a904e760512f11757f07dfcf87a2ada8fc6d028445bd53e"
    K_shared = "99758e838ae1a856589689fb55b6befe4e2382e6ebbeca1a6232a68f9dc04c1a"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P
    x = int(x, 16)
    y = int(y, 16)

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_p384_2():
    ciphersuite = CiphersuiteP384_SHA512()
    context = b"SPAKE2+-P384-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "b8d44a0982b88abe19b724d4bdafba8c90dc93130e0bf4f8062810992326da126fd01db53e40250ca33a3ff302044cb0"
    w1 = "2373e2071c3bb2a6d53ece57830d56f8080189816803c22375d6a4a514f9d161b64d0f05b97735b98b348f9b33cc2e30"
    x = "5a835d52714f30d2ef539268b89df9558628400063dfa0e41eb979066f4caf409bbf7aab3ddddea13f1b070a1827d3d4"
    y = "c883ee5b08cf7ba122038c279459ab1a730f85f2d624a02732d519faab56a498e773a8dec6c447ed02d5c00303a18bc4"
    K_shared = "31e0075a823b9269af5769d71ef3b2f5001cbfe044584fe8551124a217dad078415630bf3eda16b5a38341d418a6d72b3960f818a0926f0de88784b59d6a694b"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P
    x = int(x, 16)
    y = int(y, 16)

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_p521():
    ciphersuite = CiphersuiteP521_SHA512()
    context = b"SPAKE2+-P521-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "009c79bcd7656716314fca5a6e2c5cda7ef86131399438e012a043051e863f60b5aeb3c101731e1505e721580f48535a9b0456b231b9266ae6fff49ee90d25f72f5f"
    w1 = "01632c15f51fcd916cd79e19075f8a69b72b0099922ad62ff8d540b469569f0aa027047aed2b3f242ea0ac4288b4e4db6a4e5946d8ad32b42192c5aa66d9ef8e1b33"
    x = "00b69e3bb15df82c9fa0057461334e2c66ab92fc9b8d3662eec81216ef5ddc4a43f19e90dedaa2d72502f69673a115984ffcf88e03a9364b07102114c5602cd93c69"
    y = "0056d01c5246fbde964c0493934b7ece89eafd943eb27d357880a2a22022499e249528c5707b1afe8794c8a1d60ceedaeed96dd0dd904ea075f096c9fec5da7de496"
    K_shared = "d1c170e4e55efacb9db8abad286293ebd1dcf24f13973427b9632bbc323e42e447afca2aa7f74f2af3fb5f51684ec543db854b7002cde6799c330b032ba8820a"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P
    x = int(x, 16)
    y = int(y, 16)

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_edwards25519():
    ciphersuite = CiphersuiteEdwards25519_SHA256()
    context = b"SPAKE2+-Edwards25519-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "0deebbf7a7289efe7c2ec435ac7181a527b57294bd02b90feda36b77c3a149b5"
    w1 = "0391b2028edb047df9446bbb3385c7bc0ef716d0792b8bd98d23b1777e7805f3"
    x = "4eaffe97749551261dd45cc0018622dc9339ad2c8cf813272a5b1767b776b05f"
    y = "df49d1a53a4cd75aee2a8dfb2ac0eec8480df65ebd5fe35c4f915fcccb7c61a5"
    K_shared = "0067c7851018685d8d061e5c0ff7c4b7ebd3fd90b93890198783e9d57305788b"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P
    x = int(x, 16)
    y = int(y, 16)

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_edwards448():
    ciphersuite = CiphersuiteEdwards448_SHA512()
    context = b"SPAKE2+-Edwards448-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "37e969f792a11b2e2d23eaf2a6b4ce734e5377c4271bcd1d5e07d202365ad2d2bcf757a42379afdd18188a71327c35dd8f6011fc9ed8440b"
    w1 = "1c48d2c4646af3bdd95778328666eb1dfc0e59ac11ac4b442cdc10e9d5d54cc7f7d0e36dd1f47c0e4b4b2fd4db6145cf1885f23a5246d48b"
    x = "9fc7d75d5f8a28eeab15394b379fa044e4a43cda3784089a46697dc7e4ec939c1c65ed03724211bbf133ca9900bc0c8b3d2c50bc7cb8ff71f0"
    y = "248254ba77c13649675d14ff08537b22e9f5a415e93c6ed4645eac24a01013cf3a6e83d4711f1a14b0308dbe069d4378413c844045d11a7420"
    K_shared = "2a54e4100107666990b37659160e3e196523648524f3b52c95659e31de49d277a2deb64b0f4fd5adce7167f56226379c86e1cbee8e0dd4135b599505389fec3a"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P
    x = int(x, 16)
    y = int(y, 16)

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_random_nist_curve():
    ciphersuite = CiphersuiteP256_SHA256()
    context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Random Values"
    idProver = b"alice"
    idVerifier = b"bob"
    w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
    w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
    x = None
    y = None

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == protocol.verifier.shared_key().hex()


def test_random_edwards25519():
    ciphersuite = CiphersuiteEdwards25519_SHA256()
    context = b"SPAKE2+-Edwards25519-SHA256-HKDF-SHA256-HMAC-SHA256 Random Values"
    idProver = b"alice"
    idVerifier = b"bob"
    w0 = "0deebbf7a7289efe7c2ec435ac7181a527b57294bd02b90feda36b77c3a149b5"
    w1 = "0391b2028edb047df9446bbb3385c7bc0ef716d0792b8bd98d23b1777e7805f3"
    x = None
    y = None

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == protocol.verifier.shared_key().hex()


def test_random_edwards448():
    ciphersuite = CiphersuiteEdwards448_SHA512()
    context = b"SPAKE2+-Edwards448-SHA512-HKDF-SHA512-HMAC-SHA512 Random Values"
    idProver = b"alice"
    idVerifier = b"bob"
    w0 = "37e969f792a11b2e2d23eaf2a6b4ce734e5377c4271bcd1d5e07d202365ad2d2bcf757a42379afdd18188a71327c35dd8f6011fc9ed8440b"
    w1 = "1c48d2c4646af3bdd95778328666eb1dfc0e59ac11ac4b442cdc10e9d5d54cc7f7d0e36dd1f47c0e4b4b2fd4db6145cf1885f23a5246d48b"
    x = None
    y = None

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P

    protocol = SPAKE2PLUS(
        ciphersuite.params, idProver, idVerifier, w0, w1, L, context, x, y
    )

    assert protocol.prover.shared_key().hex() == protocol.verifier.shared_key().hex()


def test_incorrect_message():

    with pytest.raises(InvalidInputError):

        ciphersuite = CiphersuiteP256_SHA256()
        context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Random Values"
        idProver = b"alice"
        idVerifier = b"bob"
        w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
        w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
        x = None
        y = None

        w0 = bytes.fromhex(w0)
        w1 = bytes.fromhex(w1)
        L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P

        prover = Prover(idProver, idVerifier, context, ciphersuite.params, w0, w1, None)
        verifier = Verifier(
            idProver, idVerifier, context, ciphersuite.params, w0, L, None
        )
        X = prover.init(x)
        X_encoded = bytearray(encode_point_uncompressed(X, ciphersuite.params.curve))
        X_encoded[5] = X_encoded[5] ^ 0x56  # modified message X
        X = bytes(X_encoded)
        X = decode_point_uncompressed(X, ciphersuite.params.curve)
        Y = verifier.finish(X, y)


def test_incorrect_message2():

    with pytest.raises(InvalidInputError):

        ciphersuite = CiphersuiteP256_SHA256()
        context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Random Values"
        idProver = b"alice"
        idVerifier = b"bob"
        w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
        w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
        x = None
        y = None

        w0 = bytes.fromhex(w0)
        w1 = bytes.fromhex(w1)
        L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P

        prover = Prover(idProver, idVerifier, context, ciphersuite.params, w0, w1, None)
        verifier = Verifier(
            idProver, idVerifier, context, ciphersuite.params, w0, L, None
        )
        X = prover.init(x)
        Y = verifier.finish(X, y)

        Y_encoded = bytearray(encode_point_uncompressed(Y, ciphersuite.params.curve))
        Y_encoded[5] = Y_encoded[5] ^ 0x32  # modified message Y
        Y = bytes(Y_encoded)
        Y = decode_point_uncompressed(Y, ciphersuite.params.curve)

        prover.finish(Y)


def test_incorrect_message3():

    with pytest.raises(ConfirmingError):

        ciphersuite = CiphersuiteP256_SHA256()
        context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Random Values"
        idProver = b"alice"
        idVerifier = b"bob"
        w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
        w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
        x = None
        y = None

        w0 = bytes.fromhex(w0)
        w1 = bytes.fromhex(w1)
        L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P

        prover = Prover(idProver, idVerifier, context, ciphersuite.params, w0, w1, None)
        verifier = Verifier(
            idProver, idVerifier, context, ciphersuite.params, w0, L, None
        )
        X = prover.init(x)
        Y = verifier.finish(X, y)

        Y = bytes.fromhex(
            "04835bd8437b2dd3bd920dcbb3aa81c72874e8bdb81aa76c3c2b99a7e9ca22ad397dd844c701eb77264d61f13926a5fc3730d100bb08e4935d770885392d29e1dd"
        )
        Y = decode_point_uncompressed(Y, ciphersuite.params.curve)

        prover.finish(Y)

        prover.compute_key_schedule()
        verifier.compute_key_schedule()

        confirmVV, confirmPV = verifier.confirm()
        confirmVP, confirmPP = prover.confirm()

        if not prover.check(confirmVV, confirmPV) or not verifier.check(
            confirmVP, confirmPP
        ):
            raise ConfirmingError("error confirming")


def test_incorrect_message4():

    with pytest.raises(ConfirmingError):

        ciphersuite = CiphersuiteP256_SHA256()
        context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Random Values"
        idProver = b"alice"
        idVerifier = b"bob"
        w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
        w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
        x = None
        y = None

        w0 = bytes.fromhex(w0)
        w1 = bytes.fromhex(w1)
        L = int.from_bytes(w1, byteorder="big") * ciphersuite.params.P

        prover = Prover(idProver, idVerifier, context, ciphersuite.params, w0, w1, None)
        verifier = Verifier(
            idProver, idVerifier, context, ciphersuite.params, w0, L, None
        )
        X = prover.init(x)
        X = bytes.fromhex(
            "04835bd8437b2dd3bd920dcbb3aa81c72874e8bdb81aa76c3c2b99a7e9ca22ad397dd844c701eb77264d61f13926a5fc3730d100bb08e4935d770885392d29e1dd"
        )
        X = decode_point_uncompressed(X, ciphersuite.params.curve)
        Y = verifier.finish(X, y)

        prover.finish(Y)

        prover.compute_key_schedule()
        verifier.compute_key_schedule()

        confirmVV, confirmPV = verifier.confirm()
        confirmVP, confirmPP = prover.confirm()

        if not prover.check(confirmVV, confirmPV) or not verifier.check(
            confirmVP, confirmPP
        ):
            raise ConfirmingError("error confirming")
