"""Vortex Cipher v9: second implementation, written from the design record's
specification only (not from vortex.js). A learning toy. Not for real data."""
import hashlib, hmac, sys, unicodedata

H = lambda b: hashlib.sha256(b).digest()
LANES, ROUNDS = 8, 8
VERSION, FINAL = 9, 255

def _aes_sbox():
    # standard AES S-box, built from the field inverse and affine map
    p = q = 1; s = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80: q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        s[p] = (x ^ 0x63) & 0xFF
        if p == 1: break
    s[0] = 0x63
    return s
S = _aes_sbox(); SI = [0] * 256
for i, v in enumerate(S): SI[v] = i
assert S[1] == 0x7C and S[0x53] == 0xED

rotl = lambda x, k: ((x << k) | (x >> (8 - k))) & 0xFF
root = lambda parent, label: hmac.new(parent, label, hashlib.sha256).digest()
def text(t):
    """Text becomes bytes one way only: Unicode NFC, then UTF-8."""
    return unicodedata.normalize("NFC", t).encode("utf-8") if isinstance(t, str) else bytes(t)

class Gen:
    def __init__(self, key, r, n): self.key, self.r, self.n, self.ctr, self.buf = key, r, n, 0, b""
    def byte(self):
        if not self.buf:
            self.buf = H(self.key + bytes([self.r]) + self.n.to_bytes(8, "big") + self.ctr.to_bytes(4, "big")); self.ctr += 1
        b, self.buf = self.buf[0], self.buf[1:]
        return b

def bases(n):
    """Group start positions. Full groups of 8, plus a tail group over the LAST 8 bytes when n is not a multiple of 8.
    A message shorter than 8 bytes is one short group."""
    if n < 8: return [0] if n else []
    out = list(range(0, n - 7, 8))
    if n % 8: out.append(n - 8)
    return out

def material(key, r, n):
    g = Gen(key, r, n)
    iv = g.byte()
    rots = [1 + g.byte() % 7 for _ in range(3)]
    exits = []
    for _ in range(len(bases(n)) if n >= 8 else 0):
        p = list(range(8))
        for i in range(7, 0, -1):
            lim = 256 - 256 % (i + 1)
            while True:
                b = g.byte()
                if b < lim: break
            k = b % (i + 1); p[i], p[k] = p[k], p[i]
        exits.append(p)
    order = list(range(n))
    for i in range(n - 1, 0, -1):
        lim = 2**24 - 2**24 % (i + 1)
        while True:
            x = (g.byte() << 16) | (g.byte() << 8) | g.byte()
            if x < lim: break
        k = x % (i + 1); order[i], order[k] = order[k], order[i]
    ks = [g.byte() for _ in range(n)]
    kf = [g.byte() for _ in range(n)]
    kb = [g.byte() for _ in range(n)]
    return iv, rots, exits, order, ks, kf, kb

def pairs(glen):
    for st, span in enumerate((1, 2, 4)):
        for i in range(8):
            if not (i & span) and (i | span) < glen: yield st, i, i | span

def final_key(skey, n):
    g = Gen(skey, FINAL, n)
    return [g.byte() for _ in range(n)]

def encrypt(msg, skey, rounds=ROUNDS):
    b = list(msg); n = len(b); B = bases(n); glen = min(8, n)
    for r in range(rounds):
        iv, rots, exits, order, ks, kf, kb = material(skey, r, n)
        b = [(b[j] + ks[j]) % 256 for j in range(n)]             # step 1: key layer
        c = [b[order[j]] for j in range(n)]                       # step 2: key shuffle
        for g in B:                                               # step 3: cross and merge, groups in order
            for st, i, j in pairs(glen):
                c[g + i] = (c[g + i] + rotl(c[g + j], rots[st])) % 256
                c[g + j] ^= rotl(c[g + i], rots[st])
        c = [S[x] for x in c]                                     # step 4: pinch
        for gi, p in enumerate(exits):                            # step 5: exits, groups in order, each on the current bytes
            g = B[gi]; grp = c[g: g + 8]
            for l in range(8): c[g + l] = grp[p[l]]
        for j in range(n):                                        # step 6: forward chain
            c[j] ^= S[(c[j - 1] if j > 0 else iv) ^ kf[j]] ^ (c[j - 8] if j >= 8 else 0)
        for j in range(n - 2, -1, -1):                            # step 7: backward chain
            c[j] ^= S[c[j + 1] ^ kb[j]] ^ (c[j + 8] if j + 8 < n else 0)
        b = c
    fk = final_key(skey, n)                                       # closing key layer
    return bytes((b[j] + fk[j]) % 256 for j in range(n))

def decrypt(ct, skey, rounds=ROUNDS):
    n = len(ct); fk = final_key(skey, n); B = bases(n); glen = min(8, n)
    c = [(ct[j] - fk[j]) % 256 for j in range(n)]
    for r in range(rounds - 1, -1, -1):
        iv, rots, exits, order, ks, kf, kb = material(skey, r, n)
        for j in range(n - 1): c[j] ^= S[c[j + 1] ^ kb[j]] ^ (c[j + 8] if j + 8 < n else 0)
        for j in range(n - 1, -1, -1):
            c[j] ^= S[(c[j - 1] if j > 0 else iv) ^ kf[j]] ^ (c[j - 8] if j >= 8 else 0)
        for gi in range(len(exits) - 1, -1, -1):
            g = B[gi]; grp = c[g: g + 8]; p = exits[gi]
            for l in range(8): c[g + p[l]] = grp[l]
        c = [SI[x] for x in c]
        for g in reversed(B):
            for st, i, j in reversed(list(pairs(glen))):
                c[g + j] ^= rotl(c[g + i], rots[st])
                c[g + i] = (c[g + i] - rotl(c[g + j], rots[st])) % 256
        b = [0] * n
        for j in range(n): b[order[j]] = c[j]
        c = [(b[j] - ks[j]) % 256 for j in range(n)]
    return bytes(c)

def stretch(passphrase, salt):
    return hashlib.scrypt(text(passphrase), salt=b"vortex-v9|" + salt, n=32768, r=8, p=3, dklen=32, maxmem=2**27)
def raw_key(key): return root(H(b"vortex-v9|" + text(key)), b"raw")
def branch(base, name): return root(base, b"branch|" + text(name))
def seal(msg, passphrase, salt, nonce):
    assert len(salt) == 16 and len(nonce) == 16
    mk = root(stretch(passphrase, salt), b"msg|" + nonce)
    head = bytes([VERSION]) + salt + nonce
    body = encrypt(msg, root(mk, b"scramble"))
    tag = hmac.new(root(mk, b"fingerprint"), head + body, hashlib.sha256).digest()[:16]
    return head + body + tag
def open_(sealed, passphrase):
    if len(sealed) < 49 or sealed[0] != VERSION: return None
    salt, nonce, body, tag = sealed[1:17], sealed[17:33], sealed[33:-16], sealed[-16:]
    mk = root(stretch(passphrase, salt), b"msg|" + nonce)
    want = hmac.new(root(mk, b"fingerprint"), sealed[:-16], hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, want): return None
    return decrypt(body, root(mk, b"scramble"))

def reference():
    K = "golden-spiral"; salt = bytes(range(0xA0, 0xB0)); nonce = bytes(range(16))
    base = stretch(K, salt); rk = raw_key(K)
    long_msg = bytes((i * 7 + 3) % 256 for i in range(70000))
    return [
        ("stretched base", base.hex()),
        ("seal 'Vortex'", seal(b"Vortex", K, salt, nonce).hex()),
        ("seal empty message", seal(b"", K, salt, nonce).hex()),
        ("branch 'phone'", branch(base, "phone").hex()),
        ("raw, 16 zero bytes, 8 rounds", encrypt(bytes(16), rk).hex()),
        ("raw, bytes 0..20 (21 bytes), 8 rounds", encrypt(bytes(range(21)), rk).hex()),
        ("raw, bytes 0..39 (40 bytes), 1 round", encrypt(bytes(range(40)), rk, 1).hex()),
        ("raw unscramble of 16 zero bytes, 8 rounds", decrypt(bytes(16), rk).hex()),
        ("raw, 70,000 bytes (i*7+3 mod 256), 8 rounds, SHA-256 of output", H(encrypt(long_msg, rk)).hex()),
        ("raw, the 1 byte 41, 8 rounds", encrypt(b"\x41", rk).hex()),
        ("raw, 16 zero bytes, 8 rounds, key 'caf\u00e9' (composed)", encrypt(bytes(16), raw_key("caf\u00e9")).hex()),
        ("raw, 16 zero bytes, 8 rounds, key 'cafe\u0301' (decomposed)", encrypt(bytes(16), raw_key("cafe\u0301")).hex()),
        ("seal bytes 0..20 (21 bytes)", seal(bytes(range(21)), K, salt, nonce).hex()),
        ("raw, bytes 0..8 (9 bytes), 8 rounds", encrypt(bytes(range(9)), rk).hex()),
        ("raw, bytes 0..6 (7 bytes), 8 rounds", encrypt(bytes(range(7)), rk).hex()),
        ("raw, bytes 0..8 (9 bytes), 1 round", encrypt(bytes(range(9)), rk, 1).hex()),
        ("raw unscramble of bytes 0..20 (21 bytes), 8 rounds", decrypt(bytes(range(21)), rk).hex()),
        ("raw unscramble of bytes 0..8 (9 bytes), 1 round", decrypt(bytes(range(9)), rk, 1).hex()),
    ]

EXPECTED = {
    "stretched base": "4bb33aab7e5a71e940c72bd5c3c0075931f083c58dac0385ceaa0d9e9dee7fb4",
    "seal 'Vortex'": "09a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0f1bfe76119f340894a76b84e47413c3a45b12025a8e45",
    "seal empty message": "09a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0fb21f8c2e1ed3dd58224c24f3d573d14a",
    "branch 'phone'": "9c97e2b245aaef9924fd0cbb7120d2c5984e14257da23f44b302e45976a4f3ec",
    "raw, 16 zero bytes, 8 rounds": "492659aa863d27e31325c796b32555e4",
    "raw, bytes 0..20 (21 bytes), 8 rounds": "6fc00925e9b4d0a202cbe3c31683640f0e172fa4b6",
    "raw, bytes 0..39 (40 bytes), 1 round": "ffeeaa1f670debbb24f51c463833422a72e1cffd528aa3b1a318154e1ba8fc9034f64d7d8f355096",
    "raw unscramble of 16 zero bytes, 8 rounds": "fad8dff3a2c36ec008a43b0c656c1de5",
    "raw, 70,000 bytes (i*7+3 mod 256), 8 rounds, SHA-256 of output": "e974952a77ba0d298bef63f771549aad32b4ab40a2b69af75fd5ec4d663b617e",
    "raw, the 1 byte 41, 8 rounds": "1f",
    "raw, 16 zero bytes, 8 rounds, key 'caf\u00e9' (composed)": "03db4647656796fddd0d313457b73660",
    "raw, 16 zero bytes, 8 rounds, key 'cafe\u0301' (decomposed)": "03db4647656796fddd0d313457b73660",
    "seal bytes 0..20 (21 bytes)": "09a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0f1dbb3bd35eded1686062dc1cff9ea3183c387c4c78040a81484d8a9c06e48a790db03a7692",
    "raw, bytes 0..8 (9 bytes), 8 rounds": "baa15922623db57ae8",
    "raw, bytes 0..6 (7 bytes), 8 rounds": "447b57a659610c",
    "raw, bytes 0..8 (9 bytes), 1 round": "cfa3004412ec88f6a3",
    "raw unscramble of bytes 0..20 (21 bytes), 8 rounds": "960b9952932dd8a453a6d5c5e472f4280aa08af354",
    "raw unscramble of bytes 0..8 (9 bytes), 1 round": "61160ed159c42f9ca2",
}

if __name__ == "__main__":
    bad = 0
    for name, got in reference():
        want = EXPECTED.get(name)
        ok = got == want; bad += not ok
        print(("MATCH   " if ok else "DIFFERS ") + name + ("" if ok else f"\n  got  {got}\n  want {want}"))
    sys.exit(bad)
