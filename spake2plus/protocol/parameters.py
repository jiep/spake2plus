class Parameters:
    def __init__(self, M, N, h, curve, hash, mac, kdf, length):
        self.M = M
        self.N = N
        self.P = curve.g
        self.h = h
        self.curve = curve
        self.hash = hash
        self.mac = mac
        self.kdf = kdf
        self.length = length
