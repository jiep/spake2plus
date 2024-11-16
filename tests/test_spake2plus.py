from tinyec import registry
from tinyec.ec import Point
from cryptography.hazmat.primitives import hashes
from spake2plus.spake2plus import Protocol, GlobalParameters, Prover, Verifier


def test_p256():
    context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
    w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
    x = "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539"
    y = "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3"
    M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
    N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    x = int(x, 16)
    y = int(y, 16)

    curve = registry.get_curve("secp256r1")

    M = Point(
        curve,
        61709229055687782219344352628424647386531596507379261315813478518843566432559,
        43399651700267013692148409492066214468674361939146464406474584691695279811872,
    )
    N = Point(
        curve,
        98031458012971070369465795029179261841266230867477002166417845678366165379913,
        3544368724946236282841049099645644789675854804295951046212527731618188549095,
    )

    h = 1

    length = 32

    hash = hashes.SHA256()
    mac = hashes.SHA256()
    kdf = hashes.SHA256()

    K_shared = "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7"

    params = GlobalParameters(M, N, h, curve, hash, mac, kdf, length)
    protocol = Protocol(params, idProver, idVerifier, w0, w1, context, x, y)

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_p256_2():
    context = b"SPAKE2+-P256-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "1cc5207d6e34b8f7828206fb64b86aa9c712bc952abf251bb9f5856b24d8c8cc"
    w1 = "4279649e62532b01dc27d2ed39100ba350518fb969672061a01edce752d0e672"
    x = "b586ab83f175c1a2b56b6a1b6a283523f88a9befcf11e22efb48e2ee1fe69a23"
    y = "ac1fb828f041782d452ea9cc00c3fa34a55fa8f7f98c04be45a3d607b092d441"
    M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
    N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    x = int(x, 16)
    y = int(y, 16)

    curve = registry.get_curve("secp256r1")

    M = Point(
        curve,
        61709229055687782219344352628424647386531596507379261315813478518843566432559,
        43399651700267013692148409492066214468674361939146464406474584691695279811872,
    )
    N = Point(
        curve,
        98031458012971070369465795029179261841266230867477002166417845678366165379913,
        3544368724946236282841049099645644789675854804295951046212527731618188549095,
    )

    h = 1

    length = 64

    hash = hashes.SHA512()
    mac = hashes.SHA512()
    kdf = hashes.SHA512()

    K_shared = "11887659d9e002f34fa6cc270d33570f001b2a3fc0522b643c07327d09a4a9f47aab85813d13c585b53adf5ac9de5707114848f3dc31a4045f69a2cc1972b098"

    params = GlobalParameters(M, N, h, curve, hash, mac, kdf, length)
    protocol = Protocol(params, idProver, idVerifier, w0, w1, context, x, y)

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_p384():
    context = b"SPAKE2+-P384-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "097a61cbb1cee72bb654be96d80f46e0e3531151003903b572fc193f233772c23c22228884a0d5447d0ab49a656ce1d2"
    w1 = "18772816140e6c3c3938a693c600b2191118a34c7956e1f1cd5b0d519b56ea5858060966cfaf27679c9182129949e74f"
    x = "2f1bdbeda162ff2beba0293d3cd3ae95f663c53663378c7e18ee8f56a4a48b00d31ce0ef43606548da485058f12e8e73"
    y = "bbcaf02404a16ed4fa73b183f703a8d969386f3d34f5e98b3a904e760512f11757f07dfcf87a2ada8fc6d028445bd53e"
    M = "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853"
    N = "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    x = int(x, 16)
    y = int(y, 16)

    curve = registry.get_curve("secp384r1")

    M = Point(
        curve,
        2453328341088410655806131466038173624424135336066351068839646162336465402802535862431019396549146473960824785086547,
        23294640406627271543417083582466225371738900189665029330187180272595765612681186975555019017632761455422930196219357,
    )
    N = Point(
        curve,
        30655927672861681533601287186200501993542536603935442878200350109312632862816848293657430745422176677166687696870416,
        30097112182408431705538766315379525408034649126463303016311063563718154649941714405753637728743842635659072636403520,
    )

    h = 1

    length = 32

    hash = hashes.SHA256()
    mac = hashes.SHA256()
    kdf = hashes.SHA256()

    K_shared = "99758e838ae1a856589689fb55b6befe4e2382e6ebbeca1a6232a68f9dc04c1a"

    params = GlobalParameters(M, N, h, curve, hash, mac, kdf, length)
    protocol = Protocol(params, idProver, idVerifier, w0, w1, context, x, y)

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_p384_2():
    context = b"SPAKE2+-P384-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "b8d44a0982b88abe19b724d4bdafba8c90dc93130e0bf4f8062810992326da126fd01db53e40250ca33a3ff302044cb0"
    w1 = "2373e2071c3bb2a6d53ece57830d56f8080189816803c22375d6a4a514f9d161b64d0f05b97735b98b348f9b33cc2e30"
    x = "5a835d52714f30d2ef539268b89df9558628400063dfa0e41eb979066f4caf409bbf7aab3ddddea13f1b070a1827d3d4"
    y = "c883ee5b08cf7ba122038c279459ab1a730f85f2d624a02732d519faab56a498e773a8dec6c447ed02d5c00303a18bc4"
    M = "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853"
    N = "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    x = int(x, 16)
    y = int(y, 16)

    curve = registry.get_curve("secp384r1")

    M = Point(
        curve,
        2453328341088410655806131466038173624424135336066351068839646162336465402802535862431019396549146473960824785086547,
        23294640406627271543417083582466225371738900189665029330187180272595765612681186975555019017632761455422930196219357,
    )
    N = Point(
        curve,
        30655927672861681533601287186200501993542536603935442878200350109312632862816848293657430745422176677166687696870416,
        30097112182408431705538766315379525408034649126463303016311063563718154649941714405753637728743842635659072636403520,
    )

    h = 1

    length = 64

    hash = hashes.SHA512()
    mac = hashes.SHA512()
    kdf = hashes.SHA512()

    K_shared = "31e0075a823b9269af5769d71ef3b2f5001cbfe044584fe8551124a217dad078415630bf3eda16b5a38341d418a6d72b3960f818a0926f0de88784b59d6a694b"

    params = GlobalParameters(M, N, h, curve, hash, mac, kdf, length)
    protocol = Protocol(params, idProver, idVerifier, w0, w1, context, x, y)

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_p521():
    context = b"SPAKE2+-P521-SHA512-HKDF-SHA512-HMAC-SHA512 Test Vectors"
    idProver = b"client"
    idVerifier = b"server"
    w0 = "009c79bcd7656716314fca5a6e2c5cda7ef86131399438e012a043051e863f60b5aeb3c101731e1505e721580f48535a9b0456b231b9266ae6fff49ee90d25f72f5f"
    w1 = "01632c15f51fcd916cd79e19075f8a69b72b0099922ad62ff8d540b469569f0aa027047aed2b3f242ea0ac4288b4e4db6a4e5946d8ad32b42192c5aa66d9ef8e1b33"
    x = "00b69e3bb15df82c9fa0057461334e2c66ab92fc9b8d3662eec81216ef5ddc4a43f19e90dedaa2d72502f69673a115984ffcf88e03a9364b07102114c5602cd93c69"
    y = "0056d01c5246fbde964c0493934b7ece89eafd943eb27d357880a2a22022499e249528c5707b1afe8794c8a1d60ceedaeed96dd0dd904ea075f096c9fec5da7de496"
    M = "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa"
    N = "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)
    x = int(x, 16)
    y = int(y, 16)

    curve = registry.get_curve("secp521r1")

    M = Point(
        curve,
        845055962952368331951159507688534929395345073663506870408450235432184560074601620081311006767318652924394084568107240174513867528116514620255274340502919082,
        5977445632963858990652492474469123382244636078317232731018001146648411793333255868298157123207048229829031482470051919990330400410630874761794133023867871634,
    )
    N = Point(
        curve,
        2675815889405249854638847677579146841583107056900904599986403005453609141733439907137704277089930487127355047517262693128235312573127827705408249221531159845,
        6089445665372642417268682388153161887791169656628044809189188333842571756565207121777242185173763151143747961784854242003682275536963387633832989387700433716,
    )

    h = 1

    length = 64

    hash = hashes.SHA512()
    mac = hashes.SHA512()
    kdf = hashes.SHA512()

    K_shared = "d1c170e4e55efacb9db8abad286293ebd1dcf24f13973427b9632bbc323e42e447afca2aa7f74f2af3fb5f51684ec543db854b7002cde6799c330b032ba8820a"

    params = GlobalParameters(M, N, h, curve, hash, mac, kdf, length)
    protocol = Protocol(params, idProver, idVerifier, w0, w1, context, x, y)

    assert protocol.prover.shared_key().hex() == K_shared
    assert protocol.verifier.shared_key().hex() == K_shared


def test_random():
    context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Random Values"
    idProver = b"alice"
    idVerifier = b"bob"
    w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"
    w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"
    x = None
    y = None
    M = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
    N = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"

    w0 = bytes.fromhex(w0)
    w1 = bytes.fromhex(w1)

    curve = registry.get_curve("secp256r1")

    M = Point(
        curve,
        61709229055687782219344352628424647386531596507379261315813478518843566432559,
        43399651700267013692148409492066214468674361939146464406474584691695279811872,
    )
    N = Point(
        curve,
        98031458012971070369465795029179261841266230867477002166417845678366165379913,
        3544368724946236282841049099645644789675854804295951046212527731618188549095,
    )

    h = 1

    length = 32

    hash = hashes.SHA256()
    mac = hashes.SHA256()
    kdf = hashes.SHA256()

    params = GlobalParameters(M, N, h, curve, hash, mac, kdf, length)
    protocol = Protocol(params, idProver, idVerifier, w0, w1, context, x, y)

    assert protocol.prover.shared_key().hex() == protocol.verifier.shared_key().hex()