from spake2plus.exceptions.exceptions import InvalidInputError
from spake2plus.protocol.parameters import Parameters
from ecpy.curves import Curve, Point
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import HashAlgorithm


class Ciphersuite:
    def __init__(self, curve_name: str, hash_function: str):

        match curve_name:
            case "P-256":
                curve = Curve.get_curve("secp256r1")
                M = Point(
                    61709229055687782219344352628424647386531596507379261315813478518843566432559,
                    43399651700267013692148409492066214468674361939146464406474584691695279811872,
                    curve,
                )
                N = Point(
                    98031458012971070369465795029179261841266230867477002166417845678366165379913,
                    3544368724946236282841049099645644789675854804295951046212527731618188549095,
                    curve,
                )
                h = 1
            case "P-384":
                curve = Curve.get_curve("secp384r1")
                M = Point(
                    2453328341088410655806131466038173624424135336066351068839646162336465402802535862431019396549146473960824785086547,
                    23294640406627271543417083582466225371738900189665029330187180272595765612681186975555019017632761455422930196219357,
                    curve,
                )
                N = Point(
                    30655927672861681533601287186200501993542536603935442878200350109312632862816848293657430745422176677166687696870416,
                    30097112182408431705538766315379525408034649126463303016311063563718154649941714405753637728743842635659072636403520,
                    curve,
                )
                h = 1
            case "P-521":
                curve = Curve.get_curve("secp521r1")
                M = Point(
                    845055962952368331951159507688534929395345073663506870408450235432184560074601620081311006767318652924394084568107240174513867528116514620255274340502919082,
                    5977445632963858990652492474469123382244636078317232731018001146648411793333255868298157123207048229829031482470051919990330400410630874761794133023867871634,
                    curve,
                )
                N = Point(
                    2675815889405249854638847677579146841583107056900904599986403005453609141733439907137704277089930487127355047517262693128235312573127827705408249221531159845,
                    6089445665372642417268682388153161887791169656628044809189188333842571756565207121777242185173763151143747961784854242003682275536963387633832989387700433716,
                    curve,
                )
                h = 1

            case "Edwards25519":
                curve = Curve.get_curve("Ed25519")
                M = Point(
                    8158688967149231307266666683326742915289288280191350817196911733632187385319,
                    21622333750659878624441478467798461427617029906629724657331223068277098105040,
                    curve,
                )
                N = Point(
                    10742253510813957597047979962966927467575235974254765187031601461055699024931,
                    19796686047937480651099107989427797822652529149428697746066532921705571401683,
                    curve,
                )
                h = 8

            case "Edwards448":
                curve = Curve.get_curve("Ed448")
                M = Point(
                    10488591292321963092120050408926499591039575869422861700662226247901940490541612219904881578656779352523608858423842346482934103792039,
                    386798376487661638453517850814402027115378206662439517461337279157386462053905048087988398164634648067621984161091089999449415174070966,
                    curve,
                )
                N = Point(
                    132192936556464106854982406191572848315871074751255042918291569508429203833023395294311088083236725514133573850798074900914938033073648,
                    289829979055738771200547917506013133729052789564680705454895151017412048946887145378457374803631807388668209688372144080172125595776096,
                    curve,
                )
                h = 4
            case _:
                raise InvalidInputError("invalid curve")

        hash: HashAlgorithm
        kdf: HashAlgorithm
        mac: HashAlgorithm

        match hash_function:
            case "SHA-256":
                hash = hashes.SHA256()
                mac = hashes.SHA256()
                kdf = hashes.SHA256()
                length = 32
            case "SHA-512":
                hash = hashes.SHA512()
                mac = hashes.SHA512()
                kdf = hashes.SHA512()
                length = 64
            case _:
                raise InvalidInputError("invalid hash function")

        self.params = Parameters(M, N, h, curve, hash, mac, kdf, length)


class CiphersuiteP256_SHA256(Ciphersuite):

    def __init__(self):
        super().__init__("P-256", "SHA-256")


class CiphersuiteP256_SHA512(Ciphersuite):

    def __init__(self):
        super().__init__("P-256", "SHA-512")


class CiphersuiteP384_SHA256(Ciphersuite):

    def __init__(self):
        super().__init__("P-384", "SHA-256")


class CiphersuiteP384_SHA512(Ciphersuite):

    def __init__(self):
        super().__init__("P-384", "SHA-512")


class CiphersuiteP521_SHA512(Ciphersuite):

    def __init__(self):
        super().__init__("P-521", "SHA-512")


class CiphersuiteEdwards25519_SHA256(Ciphersuite):

    def __init__(self):
        super().__init__("Edwards25519", "SHA-256")


class CiphersuiteEdwards448_SHA512(Ciphersuite):

    def __init__(self):
        super().__init__("Edwards448", "SHA-512")
