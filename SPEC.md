# Vortex Cipher specification, version 9


This section states the rules exactly enough for someone else to rebuild the cipher and get the same output. All values are bytes (0 to 255) unless stated. `H` means SHA-256. `HMAC(k, m)` means HMAC-SHA-256 with key `k` over message `m`. `||` means joined end to end. Every multi-byte number, wherever it appears, is written or read most significant byte first.

What changed from version 8: the golden-angle spiral sort became a plain key shuffle; the crossing rotates one byte of each pair before adding; the chains take key bytes; a message whose length is not a multiple of 8 gets a tail group over its last 8 bytes. The golden step, the 16-bit seats, the tie rule and the odd-round reversal are gone.

### Text and bytes

- Text labels in this section are UTF-8 with no terminator.
- A passphrase, a test-mode key or a branch name given as text is first put into Unicode form NFC and then encoded as UTF-8. Text that is not well-formed Unicode (an unpaired surrogate) is refused. A passphrase or key given as bytes is used as it is, with no normalisation.
- A passphrase must not be empty. A test-mode key must not be empty. A branch name must be non-empty text.
- A message is a sequence of n bytes. n may be 0. Sealing refuses a message longer than 4,194,304 bytes, and opening refuses a body longer than that. In every mode n must be below 16,777,216.

### Constants

- Group size: 8.
- Rounds: 8, numbered r = 0 to 7. Sealed messages always use 8. Test mode accepts a round count R from 1 to 8, uses rounds r = 0 to R − 1, and refuses any other value.
- Pinch table `S`: the AES substitution box (FIPS 197, figure 7), a table of 256 bytes. `S[0x00] = 0x63`, `S[0x01] = 0x7c`, `S[0x53] = 0xed`, `S[0xff] = 0x16`. `S⁻¹` is its inverse.
- Version byte: `0x09`.
- Closing round number: 255.

### Key tree

1. A root is grown from a parent key and a label: `root(parent, label) = HMAC(parent, label)`. The parent is always 32 bytes.
2. Base key for sealed messages: `base = scrypt(passphrase, salt = "vortex-v9|" || salt16, N = 32768, r = 8, p = 3, output length 32)`. `salt16` is 16 random bytes. scrypt is the function of RFC 7914, and the passphrase is its password input.
3. Side root (branch key) for a named device or job: `root(base, "branch|" || name)`. A side root is a separate 32-byte key handed out for some other use. It leaves the tree and does not come back: seal and open never use it, it plays no part in message keys, and holding one reveals nothing about the base key or about any other side root. This specification does not define a way to seal messages under a side root.
4. Per message, with a 16-byte random start value `nonce`: `mk = root(base, "msg|" || nonce)`. The scrambling key is `root(mk, "scramble")`. The fingerprint key is `root(mk, "fingerprint")`.
5. Test mode has no salt, no start value, no stretching and no fingerprint. Its scrambling key is `root(H("vortex-v9|" || key), "raw")`. It gives the same output for the same key and message every time. It exists to test the scrambler, must not be used to protect anything, and must never be given a real passphrase.

In the labels `"msg|" || nonce` and `"vortex-v9|" || salt16`, the nonce and salt are the raw 16 bytes, not text.

### Groups

The bytes are handled in groups of 8, each named by the position of its first byte.

- If n is less than 8, there is one short group of n bytes starting at 0 (none if n is 0). It has no exit order.
- Otherwise there is a group starting at 0, 8, 16 and so on for every full 8 bytes. If n is not a multiple of 8, there is one more group, the tail group, starting at n − 8. It covers the last 8 bytes and overlaps the group before it.

The groups are always taken in this order, tail group last. For example n = 21 gives groups starting at 0, 8 and 13.

### Key material

A byte generator for scrambling key `k`, round number `r` and message length `n` produces the blocks `H(k || r || n || counter)` for counter = 0, 1, 2 and so on, joined end to end. `k` is the 32 raw bytes, `r` is 1 byte, `n` is 8 bytes and `counter` is 4 bytes, with nothing between them. Bytes are used in the order produced. Unused bytes of a block carry over to the next item drawn. Each round number has its own generator, starting at counter 0.

For round r, bytes are drawn in this order:

1. Chain start value `iv`: 1 byte.
2. Three rotation amounts `rot[0]`, `rot[1]`, `rot[2]`: for each, 1 byte `x`, giving `1 + (x modulo 7)`.
3. One exit order for each group, in group order, when n is 8 or more. Nothing is drawn when n is less than 8. For one group: start with the list `p = [0, 1, 2, 3, 4, 5, 6, 7]`. For i = 7 down to 1: draw bytes until one is below `256 − (256 modulo (i + 1))`, discarding the others; call it `x`; let `k = x modulo (i + 1)`; swap `p[i]` and `p[k]`. The result is `exit` for that group.
4. Position order: start with the list `order = [0, 1, …, n − 1]`. For i = n − 1 down to 1: draw 3 bytes and read them as one number `x` from 0 to 16,777,215; if `x` is not below `16777216 − (16777216 modulo (i + 1))`, discard all 3 and draw 3 more; let `k = x modulo (i + 1)`; swap `order[i]` and `order[k]`.
5. Key layer: n bytes, `ks[0]` to `ks[n − 1]`.
6. Forward chain key: n bytes, `kf[0]` to `kf[n − 1]`.
7. Backward chain key: n bytes, `kb[0]` to `kb[n − 1]`.

The closing key layer `fk[0]` to `fk[n − 1]` is the first n bytes produced by a fresh generator with round number 255. Nothing else is drawn from that generator. Test mode with fewer than 8 rounds still uses round number 255.

### One round

A round turns the n bytes `b` into n new bytes. The steps are done in this order.

1. **Key layer.** For every j: `b[j]` becomes `(b[j] + ks[j]) modulo 256`.
2. **Key shuffle.** `c[j] = b[order[j]]` for every j.
3. **Cross and merge.** Take the groups in order, each working on the bytes as the groups before it left them. In a group of length m (8, or n when n is less than 8), run three stages, s = 0, 1, 2, with spans 1, 2 and 4. In stage s, for each index i from 0 to 7 whose span bit is 0 (that is, `i AND span = 0`), let `j = i + span`; skip the pair if j ≥ m. For a pair, with x = the byte at the lower index i and y = the byte at j: x becomes `(x + rotl(y, rot[s])) modulo 256`, then y becomes `y XOR rotl(x, rot[s])` using the new x. `rotl(x, k)` rotates the 8 bits of one byte left by k places. Pairs within one stage do not overlap.
4. **The pinch.** Replace every byte `x` with `S[x]`.
5. **Key-picked exits.** When n is 8 or more, take the groups in order, each working on the bytes as the groups before it left them: the new byte at place `l` of the group is the old byte at place `exit[l]` of the same group, for l = 0 to 7.
6. **Forward chain.** For j from 0 to n − 1 in that order: `c[j]` becomes `c[j] XOR S[p XOR kf[j]] XOR q`. Here p is the already-updated `c[j − 1]`, or `iv` when j is 0. q is the already-updated `c[j − 8]`, or 0 when j is less than 8.
7. **Backward chain.** For j from n − 2 down to 0: `c[j]` becomes `c[j] XOR S[c[j + 1] XOR kb[j]] XOR q`. Here `c[j + 1]` is the already-updated value, and q is the already-updated `c[j + 8]`, or 0 when j + 8 is n or more. The last byte is not changed by this chain, and `kb[n − 1]` is drawn but not used.

The output of the round is `c`, which is the input `b` of the next round.

**Scrambling** runs rounds 0 to R − 1 and then adds the closing key layer: every byte becomes `(byte + fk[j]) modulo 256`.

**Unscrambling** first removes the closing key layer, `(byte − fk[j]) modulo 256`, then runs the rounds from R − 1 down to 0, undoing the steps of each round in the order 7, 6, 5, 4, 3, 2, 1:

- Undo 7: for j from 0 up to n − 2: `c[j]` becomes `c[j] XOR S[c[j + 1] XOR kb[j]] XOR q`, with `c[j + 1]` and q (`c[j + 8]`, or 0) taken as they stand at that moment.
- Undo 6: for j from n − 1 down to 0: `c[j]` becomes `c[j] XOR S[p XOR kf[j]] XOR q`, with p (`c[j − 1]`, or `iv`) and q (`c[j − 8]`, or 0) taken as they stand at that moment.
- Undo 5: take the groups in reverse order, tail group first. In each, the byte at place `l` goes back to place `exit[l]`.
- Undo 4: replace every byte `x` with `S⁻¹[x]`.
- Undo 3: take the groups in reverse order, tail group first. In each, stages s = 2, 1, 0. For a pair: y becomes `y XOR rotl(x, rot[s])`, then x becomes `(x − rotl(y, rot[s])) modulo 256` using the new y.
- Undo 2: `b[order[j]] = c[j]` for every j.
- Undo 1: `b[j]` becomes `(b[j] − ks[j]) modulo 256`.

### Seal and open

**Seal.** Inputs: a message and either a passphrase or a base key already stretched together with the salt it was stretched for. The sealer itself generates the 16-byte salt (when given a passphrase) and the 16-byte start value. Both must come from the operating system's or platform's cryptographic random generator (in the reference code, the Web Crypto `getRandomValues`), bound once when the code loads. If no such generator is available, sealing must fail. A salt or start value that comes back all zero is refused and sealing fails. The caller cannot choose the start value or the number of rounds. Nothing in this design detects a repeated start value; it relies on 16 random bytes not repeating. A separate function for tests and the demo page takes a chosen salt and a chosen start value, each exactly 16 bytes, and does not apply the all-zero check.

1. `base` as in the key tree, then the scrambling key and fingerprint key for this start value.
2. `head = 0x09 || salt16 || nonce` (33 bytes).
3. `body` = the message scrambled with the scrambling key, 8 rounds.
4. `tag` = the first 16 bytes of `HMAC(fingerprint key, head || body)`.
5. The sealed message is `head || body || tag`, which is 49 bytes longer than the message.

**Open.** The opener takes one private copy of its input and reads only that. Input shorter than 49 bytes is rejected. A first byte other than `0x09` is rejected. A body longer than 4,194,304 bytes is rejected. If a stretched base key is supplied, its salt is compared with the salt in the message and the message is rejected if they differ. Then derive the keys, recompute the tag over everything except the last 16 bytes, and compare it with the last 16 bytes without stopping early at the first difference. If they differ, reject and unscramble nothing. Otherwise unscramble the body with 8 rounds. A wrong passphrase and a changed message give the same rejection.

### Limits and warnings for implementers

- A start value must never be used twice with the same base key. If it is, equal messages give equal sealed messages.
- Test mode with one key is a fixed table for very short messages: 256 tries tabulate every 1-byte message and 65,536 every 2-byte message. Sealed messages are not affected because each gets its own scrambling key.
- The whole message is one block. It cannot be processed as a stream, and the length of the message is not hidden.
- The reference code takes about 1.7 seconds per megabyte, without pausing.
- Opening has to run scrypt before it can reject anything, so refusing junk costs about a second.
- A message of 1 byte has no shuffle, no merge, no exit and no backward chain. Each round is the key layer, the pinch and the forward chain. Messages of 2 to 7 bytes are one short group with fewer merge pairs and no exits.
- The chains spread a change through the whole message in one round. They take key bytes, but the design still relies on them for nearly all spreading between groups.
- Adding 128 to a byte is the same as flipping its top bit, and that change passes through every addition unchanged. Inside a round, only the pinch stops it.
- Because scrypt is built on HMAC, some different passphrases give the same key. A passphrase shorter than 64 bytes gives the same key as itself followed by zero bytes, as long as the total stays at 64 bytes or fewer. A passphrase longer than 64 bytes gives the same key as its SHA-256.
- The reference code keeps a stretched key out of reach of ordinary code, but other code running in the same page or process can still read it.

### Reference outputs (version 9)

A correct rebuild must reproduce all of these. Passphrase and test-mode key, unless stated: the text `golden-spiral`. Salt: `a0a1a2a3a4a5a6a7a8a9aaabacadaeaf`. Start value: `000102030405060708090a0b0c0d0e0f`.

| Case | Output (hex) |
| --- | --- |
| Stretched base key for that passphrase and salt | `4bb33aab7e5a71e940c72bd5c3c0075931f083c58dac0385ceaa0d9e9dee7fb4` |
| Branch key named `phone`, from that base | `9c97e2b245aaef9924fd0cbb7120d2c5984e14257da23f44b302e45976a4f3ec` |
| Seal the 6-byte text `Vortex` | `09a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0f1bfe76119f340894a76b84e47413c3a45b12025a8e45` |
| Seal the empty message | `09a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0fb21f8c2e1ed3dd58224c24f3d573d14a` |
| Seal the 21 bytes 00 01 02 … 14 | `09a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0f1dbb3bd35eded1686062dc1cff9ea3183c387c4c78040a81484d8a9c06e48a790db03a7692` |
| Test mode, scramble 16 zero bytes, 8 rounds | `492659aa863d27e31325c796b32555e4` |
| Test mode, scramble the 21 bytes 00 01 02 … 14, 8 rounds | `6fc00925e9b4d0a202cbe3c31683640f0e172fa4b6` |
| Test mode, scramble the 40 bytes 00 01 02 … 27, 1 round | `ffeeaa1f670debbb24f51c463833422a72e1cffd528aa3b1a318154e1ba8fc9034f64d7d8f355096` |
| Test mode, scramble the 9 bytes 00 01 … 08, 8 rounds | `baa15922623db57ae8` |
| Test mode, scramble the 9 bytes 00 01 … 08, 1 round | `cfa3004412ec88f6a3` |
| Test mode, scramble the 7 bytes 00 01 … 06, 8 rounds | `447b57a659610c` |
| Test mode, scramble the 1 byte 41, 8 rounds | `1f` |
| Test mode, unscramble 16 zero bytes, 8 rounds | `fad8dff3a2c36ec008a43b0c656c1de5` |
| Test mode, scramble 70,000 bytes where byte i is (i × 7 + 3) modulo 256, 8 rounds; SHA-256 of the output | `e974952a77ba0d298bef63f771549aad32b4ab40a2b69af75fd5ec4d663b617e` |
| Test mode, scramble 16 zero bytes, 8 rounds, key the text `café`, typed either as one accented letter (U+00E9) or as e followed by a combining accent (U+0065 U+0301); both give the same output | `03db4647656796fddd0d313457b73660` |
| Test mode, unscramble the 21 bytes 00 01 02 … 14, 8 rounds | 960b9952932dd8a453a6d5c5e472f4280aa08af354 |
| Test mode, unscramble the 9 bytes 00 01 … 08, 1 round | 61160ed159c42f9ca2 |

