# Older specifications (replaced)

Kept so the attacks in RECORD.md can be checked against the versions they broke.

## Specification (version 8, replaced by version 9)

This section states the rules exactly enough for someone else to rebuild the cipher and get the same output. All values are bytes (0 to 255) unless stated. `H` means SHA-256. `HMAC(k, m)` means HMAC-SHA-256 with key `k` over message `m`. `||` means joined end to end. Every multi-byte number, wherever it appears, is written or read most significant byte first.

### Text and bytes

- Text labels in this section are UTF-8 with no terminator.
- A passphrase, a test-mode key or a branch name given as text is first put into Unicode form NFC and then encoded as UTF-8. Text that is not well-formed Unicode (an unpaired surrogate) is refused. A passphrase or key given as bytes is used as it is, with no normalisation.
- A passphrase must not be empty. A test-mode key must not be empty. A branch name must be non-empty text.
- A message is a sequence of n bytes. n may be 0. Sealing refuses a message longer than 4,194,304 bytes, and opening refuses a body longer than that.

### Constants

- Streams per group: 8.
- Rounds: 8, numbered r = 0 to 7. Sealed messages always use 8. Test mode accepts a round count R from 1 to 8, uses rounds r = 0 to R − 1, and refuses any other value.
- Golden step: `GOLD32 = 0x61C88647` (1640531527). This is the golden angle as a fraction of a full turn, (3 − √5) / 2, multiplied by 2³² and rounded up to an odd whole number.
- Pinch table `S`: the AES substitution box (FIPS 197, figure 7), a table of 256 bytes. `S[0x00] = 0x63`, `S[0x01] = 0x7c`, `S[0x53] = 0xed`, `S[0xff] = 0x16`. `S⁻¹` is its inverse: `S⁻¹[S[x]] = x`.
- Version byte: `0x08`.
- Closing round number: 255.

### Key tree

1. A root is grown from a parent key and a label: `root(parent, label) = HMAC(parent, label)`. The parent is always 32 bytes.
2. Base key for sealed messages: `base = scrypt(passphrase, salt = "vortex-v8|" || salt16, N = 32768, r = 8, p = 3, output length 32)`. `salt16` is 16 random bytes. scrypt is the function of RFC 7914, and the passphrase is its password input.
3. Side root (branch key) for a named device or job: `root(base, "branch|" || name)`.
4. Per message, with a 16-byte random start value `nonce`: `mk = root(base, "msg|" || nonce)`. The scrambling key is `root(mk, "scramble")`. The fingerprint key is `root(mk, "fingerprint")`.
5. Test mode has no salt, no start value, no stretching and no fingerprint. Its scrambling key is `root(H("vortex-v8|" || key), "raw")`. Test mode gives the same output for the same key and message every time. It exists to test the scrambler. It must not be used to protect anything, and a real passphrase must never be given to it.

In the labels `"msg|" || nonce` and `"vortex-v8|" || salt16`, the nonce and salt are the raw 16 bytes, not text.

### Key material

A byte generator for scrambling key `k`, round number `r` and message length `n` produces the blocks `H(k || r || n || counter)` for counter = 0, 1, 2 and so on, joined end to end. `k` is the 32 raw bytes, `r` is 1 byte, `n` is 8 bytes and `counter` is 4 bytes, with nothing between them. Bytes are used in the order produced. Unused bytes of a block carry over to the next item drawn. Each round number has its own generator, starting at counter 0.

For round r, bytes are drawn in this order:

1. Spiral offset: 4 bytes read as one whole number from 0 to 2³² − 1, most significant byte first.
2. Chain start value `iv`: 1 byte.
3. Three rotation amounts `rot[0]`, `rot[1]`, `rot[2]`: for each, 1 byte `x`, giving `1 + (x modulo 7)`.
4. Exit order for each full group of 8, in turn, all groups before anything in item 5. There are floor(n / 8) full groups. A final group of fewer than 8 bytes draws nothing. For one group: start with the list `p = [0, 1, 2, 3, 4, 5, 6, 7]`. For i = 7 down to 1: draw bytes until one is below `256 − (256 modulo (i + 1))`, discarding the others; call it `x`; let `k = x modulo (i + 1)`; swap `p[i]` and `p[k]`. The result is `exit` for that group.
5. Key twist: for each i from 0 to n − 1, 2 bytes read as a number from 0 to 65535, most significant byte first, giving `twist[i]`. All n twists are drawn before item 6.
6. Key layer: n bytes, `ks[0]` to `ks[n − 1]`.

The closing key layer `fk[0]` to `fk[n − 1]` is the first n bytes produced by a fresh generator with round number 255. Nothing else is drawn from that generator. Test mode with fewer than 8 rounds still uses round number 255.

### One round

A round turns the n bytes `b` into n new bytes. The steps are done in this order.

1. **Key layer.** For every j: `b[j]` becomes `(b[j] + ks[j]) modulo 256`.
2. **Loop the spiral.** For each position i, compute its seat in whole numbers: `seat[i] = ((((i × GOLD32 + offset) modulo 2³²) >> 16) + twist[i]) modulo 65536`, where `>> 16` drops the lowest 16 bits. List the positions 0 to n − 1 sorted by seat, smallest first; positions with equal seats are listed smallest position first. If r is odd, reverse the whole list. That is the same as sorting by seat largest first, with equal seats largest position first. Call the list `order`. Then `c[j] = b[order[j]]` for every j.
3. **Cross and merge.** Split `c` into groups of 8 in order; the last group may be shorter. In each group of length m, run three stages, s = 0, 1, 2, with spans 1, 2 and 4. In stage s, for each index i from 0 to 7 whose span bit is 0 (that is, `i AND span = 0`), let `j = i + span`; skip the pair if j ≥ m. For a pair, with x = the byte at the lower index i and y = the byte at j: x becomes `(x + y) modulo 256`, then y becomes `y XOR rotl(x, rot[s])` using the new x. `rotl(x, k)` rotates the 8 bits of one byte left by k places. Pairs within one stage do not overlap, so their order does not matter. A last group of 1 byte has no pairs and is not changed by this step.
4. **The pinch.** Replace every byte `x` with `S[x]`, in every group including a short last one.
5. **Key-picked exits.** In each full group of 8, the new byte at place `l` is the old byte at place `exit[l]` of the same group, for l = 0 to 7. A shorter last group is left as it is.
6. **Forward chain.** For j from 0 to n − 1 in that order: `c[j]` becomes `c[j] XOR S[p] XOR q`. Here p is the already-updated `c[j − 1]`, or `iv` when j is 0, and `iv` is put through `S` like any other p. q is the already-updated `c[j − 8]`, or 0 when j is less than 8.
7. **Backward chain.** For j from n − 2 down to 0: `c[j]` becomes `c[j] XOR S[c[j + 1]] XOR q`. Here `c[j + 1]` is the already-updated value, and q is the already-updated `c[j + 8]`, or 0 when j + 8 is n or more. The last byte is not changed by this chain.

The output of the round is `c`, which is the input `b` of the next round.

**Scrambling** runs rounds 0 to R − 1 and then adds the closing key layer: every byte becomes `(byte + fk[j]) modulo 256`.

**Unscrambling** first removes the closing key layer, `(byte − fk[j]) modulo 256`, then runs the rounds from R − 1 down to 0, undoing the steps of each round in the order 7, 6, 5, 4, 3, 2, 1:

- Undo 7: for j from 0 up to n − 2: `c[j]` becomes `c[j] XOR S[c[j + 1]] XOR q`, with `c[j + 1]` and q (`c[j + 8]`, or 0) taken as they stand at that moment, which are the values not yet undone.
- Undo 6: for j from n − 1 down to 0: `c[j]` becomes `c[j] XOR S[p] XOR q`, with p (`c[j − 1]`, or `iv`) and q (`c[j − 8]`, or 0) taken as they stand at that moment.
- Undo 5: in each full group, the byte at place `l` goes back to place `exit[l]`.
- Undo 4: replace every byte `x` with `S⁻¹[x]`.
- Undo 3: stages s = 2, 1, 0. For a pair: y becomes `y XOR rotl(x, rot[s])`, then x becomes `(x − y) modulo 256` using the new y.
- Undo 2: `b[order[j]] = c[j]` for every j.
- Undo 1: `b[j]` becomes `(b[j] − ks[j]) modulo 256`.

The chains in steps 6 and 7 use the public table `S` and only one key byte. Their job is to spread a change through the whole message in one round. They add no secrecy of their own. The secret parts of a round are the key layer, the spiral order, the rotation amounts and the exit orders. The closing key layer is what stops an outsider undoing the last chains.

### Seal and open

**Seal.** Inputs: a message and either a passphrase or a base key already stretched together with the salt it was stretched for. The sealer itself generates the 16-byte salt (when given a passphrase) and the 16-byte start value from a cryptographic random source chosen when the code loads, and refuses an all-zero result. The caller cannot choose the start value or the number of rounds. A separate function for tests and the demo page takes a chosen start value, which must be exactly 16 bytes.

1. `base` as in the key tree, then the scrambling key and fingerprint key for this start value.
2. `head = 0x08 || salt16 || nonce` (33 bytes).
3. `body` = the message scrambled with the scrambling key, 8 rounds.
4. `tag` = the first 16 bytes of `HMAC(fingerprint key, head || body)`.
5. The sealed message is `head || body || tag`, which is 49 bytes longer than the message.

**Open.** The opener takes one private copy of its input and reads only that. Input shorter than 49 bytes is rejected. A first byte other than `0x08` is rejected. A body longer than 4,194,304 bytes is rejected. If a stretched base key is supplied, its salt is compared with the salt in the message and the message is rejected if they differ. Then derive the keys, recompute the tag over everything except the last 16 bytes, and compare it with the last 16 bytes without stopping early at the first difference. If they differ, reject and unscramble nothing. Otherwise unscramble the body with 8 rounds. A wrong passphrase and a changed message give the same rejection.

### Limits and warnings for implementers

- A start value must never be used twice with the same base key. If it is, equal messages give equal sealed messages.
- Test mode with one key is a fixed table for very short messages: 256 tries tabulate every 1-byte message and 65,536 every 2-byte message. Sealed messages are not affected because each gets its own scrambling key.
- The whole message is one block. It cannot be processed as a stream, and the length of the message is not hidden.
- Cost grows in step with length: the reference code takes about 4.4 seconds per megabyte, without pausing, so the 4 MB limit means about 17 seconds.
- Opening has to run scrypt before it can reject anything, so refusing junk costs about a second.
- Seats are 16-bit, so equal seats (ties) are common for long messages and certain above 65,536 bytes. The tie rule in step 2 matters.
- A message of 1 byte passes through no spiral, no merge, no exit and no backward chain. Each round is the key layer, the pinch and the forward chain with `iv`.
- The product `i × GOLD32` can exceed 32 bits. Keep only the lowest 32 bits of the product and of the sum with the offset, treated as unsigned.
- Because scrypt is built on HMAC, a passphrase and the same passphrase followed by zero bytes give the same key, and a passphrase longer than 64 bytes gives the same key as its SHA-256.
- The reference code keeps a stretched key out of reach of ordinary code, but other code running in the same page or process can still read it. No JavaScript library can prevent that.

### Reference outputs (version 8)

A correct rebuild must reproduce all of these. Passphrase and test-mode key, unless stated: the text `golden-spiral`. Salt: `a0a1a2a3a4a5a6a7a8a9aaabacadaeaf`. Start value: `000102030405060708090a0b0c0d0e0f`.

| Case | Output (hex) |
| --- | --- |
| Stretched base key for that passphrase and salt | `ab4ec3f032013ccd1a490993855b534b3589577aca54dda4b156504eb71478d7` |
| Branch key named `phone`, from that base | `4074f1b7b8c190532986686e4481d20e986fc690eb4aec0d6f8aa084e7ff3d41` |
| Seal the 6-byte text `Vortex` | `08a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0f896a6bb5efc56d28ae2d75c23d7a660e62ccf8b66558` |
| Seal the empty message | `08a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0f0b7b756eeda76e67226da5f55a82eac5` |
| Seal the 21 bytes 00 01 02 … 14 | `08a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0f6c00e2c6c92410254a9d124fc7d51bc42ebe7e5c3fc0f213e94fde215e69cfb1baf8263de3` |
| Test mode, scramble 16 zero bytes, 8 rounds | `bda35fd7322d8dc852d4cf8d2edef9d8` |
| Test mode, scramble the 21 bytes 00 01 02 … 14, 8 rounds | `ebd41ccbd6fa6b0dfc74c0adc753801d1440434388` |
| Test mode, scramble the 40 bytes 00 01 02 … 27, 1 round | `8c6ee9f7f246e858312fb27d5043a691e3e7285e7d1ad829aa2988f13da5c76b127da41290e108ab` |
| Test mode, scramble the 1 byte 41, 8 rounds | `22` |
| Test mode, unscramble 16 zero bytes, 8 rounds | `b9d6430c9a21ee0c1a38016a009b6d82` |
| Test mode, scramble 70,000 bytes where byte i is (i × 7 + 3) modulo 256, 8 rounds; SHA-256 of the output | `3f830fbb2d091b2d48203db55195d55908381100fc0f73b0c7d3daa22823b8b5` |
| Test mode, scramble 16 zero bytes, 8 rounds, key the text `café`, typed either as one accented letter (U+00E9) or as e followed by a combining accent (U+0065 U+0301); both give the same output | `2467281c77cd6c297cab514a98353e53` |

### File fingerprints (version 8)

SHA-256 of the files as they stood on November 16, 2026.

| File | SHA-256 |
| --- | --- |
| vortex.js, version 8 | `85e5a0c27216cd25cabc9b9c0c00ac547e4cfc1fd16942548cec1dbe414dab11` |
| vortex\_ref.py (Python second implementation), version 8 | `0e82bf7d3a6b834e191f3641062c0df9dcbbe72720e3760af40c2fa98e9be69e` |
| cross\_check.py | `8992a2b47419d92dd24e34167c754dddeaf5dc3742220b4d2a5db4aed7ee7d17` |
| test-worker.js | `b7f9688b0ed41f6b940c154de8afe8edaf18eae7bb8c824353c7264924885220` |
| spiral-code-lab.html (page and animation), version 8 | 07bce114f626c1f4726d8d6b2fc0381c904a1715dbd0afa5fc6492a9790b2b83 |

The version 7 specification is kept below as a record. Its reference outputs and fingerprints belong to version 7 only.

## Specification (version 7, replaced by version 8)

This section states the rules exactly enough for someone else to rebuild the cipher and get the same output. All values are bytes (0 to 255) unless stated. `H` means SHA-256. `||` means joined end to end. Text labels are UTF-8.

### Constants

- Streams per group: 8.
- Rounds: 8.
- Golden step: `GOLD32 = 0x61C88647` (1640531527). This is the golden angle as a fraction of a full turn, (3 − √5) / 2, multiplied by 2³² and rounded up to an odd whole number. The golden angle itself is about 137.5°.
- Fibonacci table `F`: 24 entries, `F[0] = F[1] = 1`, each next entry the sum of the previous two, modulo 256.
- Pinch table `S`: the AES substitution box. `S[0] = 0x63`, `S[1] = 0x7c`, `S[0x53] = 0xed`.

### Key tree

1. Base key for sealed messages: `base = scrypt(passphrase, "vortex-v7|" || salt)` with N = 32768, r = 8, p = 3 and a 32-byte output. The salt is 16 random bytes. scrypt is the standard defined in RFC 7914.
2. A root is grown from a parent with a label: `root(parent, label) = H(parent || "|" || label)`.
3. Side root (branch key) for a named device or job: `root(base, "branch|" || name)`.
4. Per message, with a 16-byte random start value `nonce`: `mk = root(base, "msg|" || nonce)`. The scrambling key is `root(mk, "scramble")`. The fingerprint key is `root(mk, "fingerprint")`.
5. Raw mode, used only for testing, has no salt, no nonce and no stretching. Its base is `H("vortex-v7|" || key)` and its scrambling key is `root(base, "raw")`. Versions 4 and 5 used the label `vortex-v4|` here, and version 6 used vortex-v6|, so raw-mode outputs do not match between those versions and version 7.

### Key material for round r

A byte generator produces `H(scramblingKey || r || counter)` for counter = 0, 1, 2 and so on, where `r` is one byte and `counter` is four bytes, most significant first. Bytes are drawn from it in this order, for a message of `n` bytes:

1. Spiral offset: 4 bytes read as a whole number from 0 to 2³² − 1, most significant byte first.
2. Chain start value `iv`: 1 byte.
3. Three rotation amounts: for each, 1 byte, taken as 1 + (byte modulo 7).
4. Exit order for each full group of 8, in turn: a shuffle of the numbers 0 to 7. Start with 0 to 7 in order. For `i` from 7 down to 1, draw bytes until one is below 256 − (256 modulo (i + 1)), take it modulo (i + 1) as `k`, and swap positions `i` and `k`.
5. Key twist: 2 bytes per message byte, read as a 16-bit number, most significant byte first.
6. Key stream: 1 byte per message byte.

### One round

Rounds are numbered r = 0 to 7. Each round turns the `n` bytes `b` into new bytes `c`.

1. **Loop the spiral.** For each position `i`, compute its seat in whole numbers: `seat = ((((i × GOLD32 + offset) mod 2³²) >> 16) + twist[i]) mod 65536`, where `>> 16` drops the lowest 16 bits. Sort the positions by seat, ties by position. If `r` is odd, reverse the order. The byte at the j-th position in that order becomes `c[j]`.
2. **Cross and merge.** Split `c` into groups of 8 in order. The last group may be shorter. In each group, run three stages with spans 1, 2 and 4. In a stage, for each index `i` in the group whose span bit is 0, pair it with index `i + span`, if that index exists. For a pair `(a, b)`: `a` becomes (a + b) modulo 256, then `b` becomes `b` XOR (the new `a` rotated left by that stage's rotation amount).
3. **The pinch.** Replace every byte `x` with `S[x]`.
4. **Key-picked exits.** In each full group of 8, the byte at place `l` is taken from place `exit[l]` of the same group. A shorter last group is left as it is.
5. **Fibonacci mix and forward chain.** First, for every j from 0 to n − 1, `c[j]` becomes (c\[j\] + F\[(j + r) modulo 24\] + keystream\[j\]) modulo 256. Then, for j from 0 to n − 1 in that order, `c[j]` becomes c\[j\] XOR S\[p\] XOR q. Here p is the already-updated c\[j − 1\], or `iv` when j is 0, and q is the already-updated c\[j − 8\], or 0 when j is less than 8.
6. **Backward chain.** For j from n − 2 down to 0, `c[j]` becomes c\[j\] XOR S\[c\[j + 1\]\] XOR q. Here c\[j + 1\] is the already-updated value, and q is the already-updated c\[j + 8\], or 0 when j + 8 is n or more. The last byte is not changed by this chain. Up to version 6 the chains used no table and no second byte: the forward chain was XOR with the previous byte, and the backward chain was XOR with the next byte rotated left by 3. That was the cause of the 2-round weakness.

Unscrambling runs the rounds from 7 down to 0, and inside each round undoes steps 6 to 1 in that order.

### Seal and open

- **Seal:** stretch the passphrase with the salt to get the base key. Scramble the message with the per-message scrambling key. Compute the fingerprint as the first 16 bytes of HMAC-SHA-256, keyed with the fingerprint key, over `salt || nonce || scrambled message`. The sealed output is `salt || nonce || scrambled message || fingerprint`, which is 48 bytes longer than the message.
- **Open:** read the salt, stretch the passphrase, and recompute the fingerprint. If it does not match, reject and unscramble nothing. Otherwise unscramble.

### Notes for implementers

These points were added on November 14, 2026, after the cipher was rebuilt in Python from this section, and revised for version 6. Each is a place where the text above could be read more than one way.

- The byte generator starts again at counter 0 in every round. Bytes are used in the order produced, and unused bytes from a hash block carry over to the next item drawn.
- The spiral offset is used as a whole number. It is not scaled to an angle.
- The seat calculation uses whole numbers only. The product i × GOLD32 can be larger than 32 bits, so keep only the lowest 32 bits of the product and of the sum with the offset, treated as unsigned. In JavaScript that is `Math.imul` followed by `>>> 0`. Up to version 5 the seat used floating point, and rebuilds that rounded differently could disagree. Version 6 removed that.
- All rotations are of one byte (8 bits).
- The three rotation amounts belong to the stages with spans 1, 2 and 4, in that order.
- In the labels "msg|" || nonce and "vortex-v7|" || salt, the nonce and salt are the raw 16 bytes, not text.

### Reference outputs

A correct rebuild must reproduce these, with key `golden-spiral`.

| Input | Output (hex) |
| --- | --- |
| Stretched base key for salt `a0a1a2a3a4a5a6a7a8a9aaabacadaeaf` | `2276f57d07613d3f80a0f0dcd7de20bcc71f21361299674b47d3263663dc48ff` |
| Seal the 6-byte text `Vortex` with that salt and nonce `000102030405060708090a0b0c0d0e0f` | `a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000102030405060708090a0b0c0d0e0ffe0c2a48f376cbde340abf5ee35f0bbeb160f9d7e578` |
| Raw mode, 16 zero bytes, 8 rounds | `2ae34c40671256c3d718cc8b58028b7e` |
| Branch key named `phone`, from that stretched base | `c13658220f5976802f1d0d6744b93a137192068aa4bcfc63eefa3b123364c768` |

### Implementation fingerprints

These SHA-256 hashes identify the exact files this record describes, as they stood at about 5:30 PM on November 15, 2026.

| File | SHA-256 |
| --- | --- |
| vortex.js (cipher, stretcher, tests, AI attack), version 7 | `6a90403aacf84f11edd58b82777f429712861c5a8fa179c12c2a0ceb19b0cdb6` |
| spiral-code-lab.html (page and animation), version 7 | `4a911c39e62e15b48f31135b81c90cc57238ba5466f3a8238eb9dcaa5a35dbec` |
| test-worker.js (test runner) | `a5c9a3c9d927f3feb89371441204e995db0760d22ca1f1333e47c0ca06c976fe` |
| vortex\_ref.py (Python second implementation), version 7 | `a380adac98aadfd87a2d3e648a72bbecf207df848cce4acacbbcebf0be808b8b` |
| cross\_check.py (comparison of the two implementations) | `45de5edb9c74ed944eae6c2df81ae706f90c069c7261f89aed2200d5bb03f50a` |
| vortex.js, version 5 | `31ed4b971012aa9698ddcc642808b7bb0f41853629b6e96e7b529d36fabe30f7` |
| vortex.js as tested for the version 4 attack results | `ce993e9a56fdb11f07b92dc787d014e45595599e7edb789a0639123cf36dbe5f` |

Version 6 files, kept as backups: vortex.js `724a0af9f15976bbbaf3b8d650b80bbcda8782ae49f1f5831bcc8e37bae9c40d`, vortex\_ref.py `ac71f0ed3f18eeef294bd6973d836d3d85a4af979e544291c0f627d8fd75e4dd`.

