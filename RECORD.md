# Vortex Cipher: origin, history and test record

This is the working record kept while the cipher was designed, broken and rebuilt, lightly trimmed for publication. Dates are in 2026, times US Eastern. "Claude" is the AI assistant that wrote the code and ran the tests.

## Origin and timeline

The design ideas came from Josh Hutchens in conversation. Claude wrote the code, chose the standard building blocks and ran the tests. Times are US Eastern and come from the conversation record.

| Date and time | Who | What happened |
| --- | --- | --- |
| Nov 16, 2026, afternoon and evening | Josh, Claude, Grok, Gemini, ChatGPT, AI agents | A write-up for outside review was drafted. Josh pasted a brief and the version 8 specification into Grok, Gemini and ChatGPT and brought back their answers. ChatGPT's finding was confirmed; Grok's and Gemini's attack claims were not. Josh decided that parts which do nothing should not stay in the cipher, which removed the golden-angle spiral. A trial version 9 was built and attacked by a fresh agent, which found one more one-round weak spot. Josh approved version 9 with that fixed. It was built, rebuilt independently from its specification, and tested. |
| Nov 16, 2026 | Josh, Claude, AI agents | Josh asked whether the design had grown too large and agreed to test a slimmer one for the security use, while keeping every part of the full design on record for later uses. A removal study was run. Josh asked for other AI agents to test the cipher. Three reviewed version 7 and found a full one-round break and several faults in the surrounding code. Josh approved version 8, with the key-picked exits kept. Version 8 was built, reviewed by three more agents, fixed again where they found faults, and tested. |
| Nov 15, 2026, morning to about 5:30 PM | Josh, Claude | Rounds 3 to 7 of version 6 run through the 1 GB test. Josh asked for the cause of the 2-round failures to be traced, and it was found in the chains. Josh said to continue, and version 7 was built with new chains. The Python rebuild was updated and matched. The full attack table, the NIST suite and the long-stream tests were rerun on version 7. |
| Nov 14, 2026, about 6:00 AM | Josh, Claude | Josh asked to strengthen the design and add horizontal branches. Version 4 built: key twist on the spiral and the pinch. Full attack suite rerun. This record written. PractRand and the NIST reference suite run. Weak-pinch study run. About 8:40 AM: version 5 built, adding scrypt key stretching. About 2:00 PM: guardian layer designed on paper. About 2:30 PM: guardian phase 1 built and run as a simulation. About 3:00 PM: guardian phase 2, three guardians, built and run as a simulation. Afternoon: Josh answered the five guardian decisions. The cipher was rebuilt in Python from this record, which exposed the floating-point spiral. Evening: version 6 built with a whole-number spiral and every test rerun. About 9:45 PM: longer 1 GB tests finished and showed that 2 rounds fail for some keys in both version 5 and version 6. |
| Nov 13, 2026, about 6:50 PM | Claude | Deeper attacks on version 3 found a 2-round leak, the low key-dependence of the spiral, and the one-byte weakness. |
| Nov 13, 2026, about 6:30 PM | Claude | Attacks run with the key stream off, to test the vortex structure alone. |
| Nov 13, 2026, about 5:20 PM | Claude | Version 3 built: 256-bit key setup, random start per message, fingerprint, branch keys. |
| Nov 13, 2026, about 5:05 PM | Claude | Version 2 built and tested. Randomness tests and AI attack added. The 32-bit key weakness found. |
| Nov 13, 2026, about 4:00 to 5:00 PM | Josh | On a walk, Josh described: streams that merge and move at the crossing instead of staying in their own lines; exits in many directions that are not fixed; roots from the top, bottom and sides that never return; a watching layer around the code, with wings, like guardian angels; using AI to attack the design. |
| Nov 13, 2026, 3:38 PM | Josh | Josh described the opposite-side loop: code leaves the bottom of the funnel, circles around, re-enters the top and leaves the bottom on the opposite side, repeating. He also asked for lines of code that visibly cross as they spiral. |
| Nov 13, 2026, about 3:30 PM | Claude | First animation and first toy cipher (version 1, Spiral Fold) built. |
| Nov 13, 2026, afternoon | Josh | While driving, Josh described the core picture: code spiralling like a tornado and built on the Fibonacci sequence instead of plain ones and zeros; a second, upside-down tornado joined to the first, pulling in at one end and pushing out at the other; lines crisscrossing inside like the infinity symbol; code that folds. He asked whether it could keep hackers out. |
| Oct 31, 2026 | Josh | Josh first named the idea, calling it centrifugal coding, and said he could see it but could not yet explain it. |

## Design concept

The design has three layers: a vortex at the centre that mixes, roots that carry results outward, and guardians that watch over it. The first two are built. The guardians are designed on paper, in the Guardian layer tab, and not built.

| Part of the picture | What it does in the design | Closest existing idea | Status |
| --- | --- | --- | --- |
| Double vortex (two funnels joined at the tips) | The path data follows each round: in through the top, through the centre, out the bottom, around the outside and back in | Flow over a horn torus | Built |
| Golden-angle spiral | Seats byte *i* at *i* × 137.5°, then reads the bytes back in angle order to move them | Permutation layer, like ShiftRows in AES | Built |
| Key twist | The key adds its own twist to every byte's seat, so the order is secret | Keyed permutation | Built in version 4 |
| Crossing | All 8 streams of a group merge, so each carries a piece of every other | Butterfly network; diffusion | Built |
| Pinch | Each byte passes through the centre point alone and is swapped for another | Substitution box (S-box) | Built in version 4 |
| Key-picked exits | The key decides which direction each merged stream leaves in | Key-dependent routing | Built |
| Pull in, push out | Odd rounds read the spiral inward, even rounds outward | Alternating round structure | Built |
| Top root | The scrambled message | Ciphertext | Built |
| Bottom root | A fingerprint that changes if any bit of the message changes | Message authentication code | Built |
| Side roots | Separate keys for separate devices or jobs, grown from one key and not traceable back to it | Key derivation tree | Built |
| Guardians with wings | Many small watchers that notice attacks on the code, respond, and watch each other | Anomaly detection; moving target defense | Designed on paper, not built |

Josh also sees the pattern as wider than security. This record covers only the security use, because that is the only use that has been built and tested.

## Version history

Each version fixed weaknesses that testing found in the one before.

| Version | Date | What it added | Weakness that testing then found |
| --- | --- | --- | --- |
| 9 | Nov 16, 2026 | Golden-angle spiral sort replaced by a uniform key shuffle; odd-round reversal removed. Crossing rotates one byte of each pair before adding. One key byte per position in each chain. Tail group over the last 8 bytes when the length is not a multiple of 8. New labels, version byte and reference outputs. About 1.7 seconds per megabyte, down from 4.4. | None demonstrated at any round count. Nothing in the test set can see one round any more. A top-bit change still passes every addition and is stopped only by the pinch. Tested for hours only, by AI reviewers only. |
| 8 | Nov 16, 2026 | Key layer moved to the start of each round. Closing key layer added after the last round. Fibonacci add removed. Key material depends on message length. Key tree uses HMAC. Rounds fixed at 8, sealer makes its own random values, inputs checked, 4 MB limit, version byte. New labels and reference outputs. | One round with the key layers on shows a pattern at 1 GB. With the key layers off, one round can be undone with about 128 chosen messages. Nothing found at 2 to 8 rounds. Tested for one day only. |
| 7 | Nov 15, 2026 | New forward and backward chains. Each byte is mixed with the pinch-table value of its neighbour and with the byte 8 places away. New labels and new reference outputs. | One round fails a long randomness test by 4 GB with the key stream off. Nothing found at 2 to 8 rounds so far. Tested for one afternoon only. |
| 6 | Nov 14, 2026 | Whole-number spiral in place of floating-point seats, so every correct rebuild gives the same output. New labels and new reference outputs. | Cut down to 2 rounds, the output fails a 1 GB randomness test for about 1 key in 3. Version 5 fails the same way, so the weakness is older than version 6. Nothing found at 8 rounds. |
| 5 | Nov 14, 2026 | scrypt key stretching for passphrases, with a 16-byte salt carried in each sealed message. | The spiral depended on floating-point rounding, found by rebuilding the cipher in Python. A 1 GB test run later, while testing version 6, showed that 2 rounds fail for some keys. The scrambling rounds are unchanged from version 4. |
| 4 | Nov 14, 2026 | Key twist on the spiral. The pinch, using the AES substitution box. | Passphrases could be guessed quickly, about 160,000 guesses a second on one core. The automated attacks run at the time found no weakness in the rounds from 2 rounds up. The 1 GB test run later on version 5, which has the same rounds, did find one at 2 rounds. |
| 3 | Nov 13, 2026 | SHA-256 key tree with 256-bit keys. Random start value per message. Fingerprint. Branch keys. | 2 rounds leaked under heavy data. The spiral had only as many possible orders as the message had bytes. One-byte messages were not mixed when the key stream was off. |
| 2, Vortex | Nov 13, 2026 | 8 streams that merge at the crossing. Key-picked exits. | Every key was squeezed into 32 bits, so all 4.3 billion keys could be tried in about 40 hours on one laptop core. The same message always gave the same output. Tampering went unnoticed. |
| 1, Spiral Fold | Nov 13, 2026 | Golden-angle spiral fold. Fibonacci mix. Key stream. Forward and backward chains. | Streams stayed in their own lines and did not merge. Same 32-bit key limit as version 2. |

## Test record (versions 4 to 9)

All tests were run by Claude in Node.js. The sections below are in the order the work happened: version 7 (November 15); the removal study, two agent reviews, version 8, the review by three outside AI models and version 9 (all November 16). Version 9, the current version, is the last of these. Sections after those were measured on versions 4, 5 and 6 and are kept as measured.

### Version 7 test record (November 15, 2026)

Version 7 changes the two chains, so every output changed and every test was run again. The key stream is the SHA-256 output added to each byte. "Key stream off" means it is left out, so only the vortex structure is being tested.

Correctness:

- 418 and 1,500 round-trip and tamper checks in two scripts, 0 failures. scrypt matched Node's built-in version and the RFC 7914 test vector.
- The Python rebuild was updated from the new chain rules. All four new reference outputs matched, and 538 further cases matched with 528 round trips checked.
- One bit changed in the message flips 49.95% of the output. One bit changed in the key flips 49.97%.

Long-stream test (PractRand 0.94, counter test stream):

| Rounds | Key stream | Keys | Size | Result |
| --- | --- | --- | --- | --- |
| 1 | off | golden-spiral | 4 GB | Fails. One test flagged from 512 MB and grew at each step to a failure at 4 GB (p = 1.3e-15). |
| 2 | off | golden-spiral, key-a, key-b, key-c, key-d, second-key | 1 GB each | No anomalies at 1 GB on all six. Version 6 failed on golden-spiral and key-d. |
| 2 | on | golden-spiral | 4 GB | One "mildly suspicious" flag at 1 GB. No anomalies at 2 GB or 4 GB. |
| 2 | on | key-a | 1 GB | No anomalies at 1 GB. |
| 3, 4, 5, 6, 7 | off | golden-spiral | 1 GB each | No anomalies at 1 GB on all five. |
| 8 | off | golden-spiral | 1 GB | No anomalies at 1 GB. |
| 8 | on | golden-spiral | 1 GB | No anomalies at 1 GB. |

A few runs showed a single "unusual" flag at a smaller size that was gone at the next size. That is the level chance produces.

The 2-round flag with the key stream on was on the same test, at the same size, as the flag in the 1-round run. In the 1-round run it grew into a failure. In the 2-round run it disappeared when the stream was made four times longer, so it is recorded as chance, with that coincidence noted.

Other attacks, on 16-byte messages unless stated:

| Attack | 1 round | 2 rounds | 3 to 8 rounds |
| --- | --- | --- | --- |
| AI attack, 20,000 examples, key stream off | 49.9% | 50.1% | 49.4% to 50.0% |
| AI attack, 20,000 examples, key stream on | 50.3% | 49.8% | 48.2% to 51.3% |
| AI attack, 100,000 examples, key stream off | not run | 49.4% and 49.7% | 50.1% to 50.3% at 3 and 4 rounds |
| Pattern count, 40,000 pairs | no repeats | no repeats | no repeats |
| Four-message test, 20,000 groups | no bias | no bias | no bias |
| Search of all 128 one-bit changes | not run | none held on re-test | none held on re-test at 3 rounds |
| All-256-values attack (chance 0.39%) | 0.41% off, 0.34% on | 0.34% off, 0.45% on | 0.30% to 0.41% at 3 and 4 rounds |
| Shortcut search, 16,384 links (chance about 2.9%) | 2.7% to 2.8% | 2.7% to 3.1% | 2.9% at 3 rounds |
| Heavy-data test | not rerun | not rerun | clean at 2.5 million pairs at 3 rounds, on and off, and at 2 million pairs at 4 rounds, off |
| 4,096-byte message, one bit changed | 50% flipped, no weak stretch | 50% flipped, no weak stretch | 50% flipped at 8 rounds |

NIST SP 800-22 reference suite, 100 streams of 1 million bits, 8 rounds: 188 of 188 rows passed with the key stream on. 187 of 188 passed with it off. The one miss was a template test at 92 of 100, against a pass mark of 96. Version 6 showed one such miss as well, and chance produces about that many.

What changed at 1 round, and why it matters: in version 6 one round was broken by the AI attack (98.9%), the four-message test and the all-256-values attack. In version 7 one round passes all three, and only the 4 GB long-stream test catches it. The short attacks have lost their ability to see a weak setting. That makes the clean results at 2 to 8 rounds weaker evidence than the same results were before.

Not tested on version 7: more than one key at 3 to 8 rounds; anything beyond 4 GB; the heavy-data test at 1 and 2 rounds; the weak-pinch study. Version 7 was designed and tested by the same program in one afternoon, with no outside check.

### Removal study (November 16, 2026)

Josh asked whether the design had grown too large. To find out which parts do measurable work, version 7 was run with one part removed at a time, always with the key stream off. For each stripped-down version the table gives the fewest rounds at which a 1 GB long-stream test finished without a failure, and the fewest rounds at which the short attacks (AI attack, all-256-values, four-message, spreading in a 4,096-byte message) all came back clean. One key, golden-spiral, for the long-stream test.

| What was removed | Rounds to pass 1 GB long stream | Rounds to pass short attacks |
| --- | --- | --- |
| Nothing (version 7, key stream off) | 1, with a mild flag | 1 |
| Spiral loop | 1 | 1 |
| Key twist on the spiral | 1, with a "very suspicious" flag | 1 |
| Crossing (merge) | 1 | 2 |
| Pinch | 2 | 1 |
| Key-picked exits | 1 | 1 |
| Both chains | 6 | more than 4 |
| New chains swapped for the version 6 chains | 2 | 2 |
| Fibonacci add put back in, without the key stream | 2 | 1 |
| Twist, exits and chains together, leaving spiral, crossing and pinch | 6 | more than 4 |
| Twist and exits, with the version 6 chains | 3 | 2 |
| Twist and exits, with the new chains | 1, with a mild flag | 1 |
| Everything except the new chains | 1, no flags | 2 |

What this shows:

- The new chains carry the test results. With the spiral, crossing, pinch and exits all removed, the chains alone pass the 1 GB test at one round with no flags.
- Removing the spiral, the key twist, the crossing or the exits one at a time changes nothing these tests can measure.
- The vortex without chains spreads a change slowly through a long message. One bit changed in 4,096 bytes reaches about 1% of the output after 2 rounds and about a third after 4, so it needs 6 rounds to pass.
- The Fibonacci add gives no measurable benefit.

The limit of this study, which matters more than the table: the chains-only version uses almost no key, so anyone can undo it, yet it passes every test. These tests measure how well the output is scrambled. They do not measure whether it can be unscrambled without the key. So the study can say which parts add scrambling, but it cannot say which parts add secrecy, and it is not enough on its own to decide what to cut.

Follow-up started the same day: three separate AI agents that had not seen this work were each given the specification. One was asked to break the mixing, one to attack the key setup and sealing, and one to rebuild the cipher from the specification alone. Their results will be recorded here.

### Review by three separate AI agents (November 16, 2026)

Three AI agents that had not seen any of this work were each given the version 7 specification and one job. A claimed flaw counted only if it came with code that demonstrates it. Claude then ran the code for the main findings and confirmed them. The agents run on the same underlying model as Claude, so this is a second look, not an outside review.

**Agent 1, mathematical attack.** Given the specification and vortex.js.

- One round is fully broken in the real setting, with the key stream on. For messages shorter than 8 bytes, about 15 chosen messages and under a second of work recover everything secret in the round: the spiral order, the rotation amounts, the chain start value and the key stream. The recovered values then unscrambled 300 of 300 fresh messages for each of 6 keys without the key.
- The two chains add no secrecy. They use only the public pinch table and one secret byte, and that byte affects only the first output byte when the chains are undone. Anyone can strip them off.
- An all-zero message passes through the spiral, crossing, pinch and exits as a constant, because moving equal bytes changes nothing and merging zeros gives zero. One all-zero message therefore reveals the chain start value and the whole key stream of a round.
- The spiral offset, chain start value and rotation amounts of a round do not depend on message length, so they are the same for every message under one key.
- No attack was found at 2 or more rounds, and no pattern past 1 round. For messages of 8 bytes or more the full 1-round recovery was not completed, because the key-picked exits were not searched.
- Raw mode gives the same output for the same message every time. That is expected, since raw mode has no random start value. Sealed messages are not affected.

**Agent 2, key setup and sealing.** Given the specification and vortex.js.

| Severity | Finding |
| --- | --- |
| High | The number of rounds is an unchecked input to seal and is not covered by the fingerprint. A null, zero or non-number value runs 0 rounds, and the sealed body is the plain text with a valid fingerprint. Sealing with 8 rounds and opening with 7 reports success with wrong bytes. |
| High | The branchKey function and raw mode derive keys from the passphrase with plain SHA-256, skipping scrypt. From one such key a weak passphrase was recovered in 0.03 seconds and then opened a sealed message. The specification says branch keys come from the stretched base; the code offers both. |
| Medium | seal does not generate the salt or start value and does not check their length. A repeated start value under one key makes identical messages seal identically. A wrong length produces output that can never be opened. |
| Medium | Wrong input types are accepted silently. A text string passed as the message is sealed as zero bytes. |
| Medium | Cost. A 16 MB message took 64 seconds and over 500 MB of memory. 48 bytes of junk cost a full scrypt run before rejection. |
| Low | A cached base key is trusted without checking it against the salt or passphrase. Returned results carry the base key and a copy of the plain text. |
| Low | The specification does not say how passphrase text becomes bytes. |
| Low | The key tree uses plain SHA-256, which allows a longer label's key to be worked out from a shorter one (length extension). The current code cannot be made to do this, but a byte-oriented rebuild could. |
| Low | The exported pinch table is the live table, so other code on the same page could change it. |

Found sound: the hand-written SHA-256, HMAC, PBKDF2 and scrypt matched Node's built-in versions on 1,193 comparisons. All 3,639 modified sealed messages were rejected. The fingerprint is checked before anything is unscrambled. The key labels cannot collide. No finding lets an outsider read or forge a correctly sealed message that has a strong passphrase and fresh start values.

**Agent 3, rebuild from the specification alone.** Given only the specification text, with no access to any code.

- All four reference outputs matched on its first run with no changes. Claude then compared its rebuild with vortex.js on 62 further cases from 0 to 200,000 bytes, and all matched.
- The four reference outputs do not exercise every rule. Of eight deliberately wrong readings, two still reproduced all four outputs: a different rule for ties in the spiral order, and a Fibonacci table index that does not wrap. Neither reference message is long enough to reach those rules.
- Other gaps: no reference output mixes full groups of 8 with a short last group; the unscrambling steps are not written out; the text encoding of keys is not stated; one note still says version 6.

**What follows from this.** Agent 1's result agrees with the removal study: the chains scramble well but hold no secret, which is why the randomness tests passed while proving little. The secrecy of a round rests on the keyed spiral order, the rotations, the exits and the key stream. A 1-round break is not by itself alarming, since single rounds of standard ciphers are also breakable, but the all-zero weakness and the unkeyed end of each round are design faults to fix. A version 8 is proposed and not yet built.

### Version 8 test record (November 16, 2026)

Version 8 changes the order of a round and the key tree, so every output changed and every test was run again. "Key layers off" means the key layer of every round and the closing key layer are left out, so only the structure is tested.

Correctness:

- 1,800 scramble and unscramble round trips at lengths 0 to 299 and 1, 2 and 8 rounds, with the key layers on and off: 0 failures.
- All 440 single-bit changes to a sealed message were rejected.
- The built-in SHA-256, HMAC, PBKDF2 and scrypt matched Node's own on 641 comparisons, including one at the real scrypt setting.
- The Python rebuild matched all 13 reference outputs and 612 further cases, with 600 round trips checked.
- One bit changed in a 40-byte message flips 50.11% of the output. One bit changed in the key flips 49.91%.

Long-stream test (PractRand 0.94, counter test stream, 1 GB each):

| Rounds | Key layers | Keys | Result |
| --- | --- | --- | --- |
| 1 | on | golden-spiral | Two "very suspicious" flags at 1 GB on one test (p = 4.5e-7 and 1.2e-9). Not a failure by the tool's scale, but a real pattern. |
| 1 | off | golden-spiral | No anomalies at 1 GB. One mild flag at a smaller size. |
| 2 | on | golden-spiral | No anomalies. |
| 2 | off | golden-spiral, key-a, key-d | No anomalies on all three. |
| 3 | off | golden-spiral | One "unusual" flag at 1 GB (p = 1.7e-4). |
| 4, 5, 6, 7 | off | golden-spiral | No anomalies on all four. |
| 8 | off | golden-spiral | One "unusual" flag at 1 GB (p = 1 − 5.8e-3). |
| 8 | on | golden-spiral | No anomalies. |

"Unusual" is the tool's lowest level and appears by chance in a fair share of runs of good generators. Version 8 was not run past 1 GB.

Other attacks, on 16-byte messages unless stated:

| Attack | 1 round | 2 rounds | 3 to 8 rounds |
| --- | --- | --- | --- |
| AI attack, 20,000 examples, key layers off | 50.0% | 51.0% | 49.7% to 50.7% |
| AI attack, 20,000 examples, key layers on | 50.7% | 50.4% | 49.4% to 49.9% |
| AI attack, 100,000 examples, key layers off | not run | 49.6% and 50.2% | 49.4% to 50.0% at 3 and 4 rounds |
| Pattern count, 40,000 pairs | no repeats | no repeats | no repeats |
| Four-message test, 20,000 groups | no bias | no bias | no bias |
| Messages of 1 to 9 bytes, one bit changed | about 50% flipped | not run separately | about 50% flipped at 8 rounds |
| Search of all 128 one-bit changes | not run | none held on re-test | none held on re-test at 3 rounds |
| Heavy-data test, 2.5 million pairs | not run | clean, key layers on | clean at 3 rounds, on and off |

NIST SP 800-22 reference suite, 100 streams of 1 million bits, 8 rounds: 188 of 188 rows passed with the key layers on. 187 of 188 passed with them off; the one miss was a template test at 95 of 100 against a pass mark of 96, which chance produces.

Not tested on version 8: more than one key at 1 and 3 to 8 rounds; anything beyond 1 GB; the weak-pinch study; the removal study, which was done on version 7.

Gap tests added later on November 16, all with the key layers on: 8 rounds on two more keys (key-a, key-b) at 1 GB each, 2 rounds on golden-spiral at 4 GB, and 4 rounds on key-a at 2 GB. All four ended with no anomalies. Each showed one or two "unusual" flags at small sizes that were gone at the next size. This narrows the "not tested" list above: 8 rounds has now been run on three keys with the key layers on, and 2 rounds to 4 GB. Still not tested: anything beyond 4 GB, and more than one key at 1, 3, 5, 6 and 7 rounds.

### Second agent review, on version 8 (November 16, 2026)

Three new agents that had seen nothing earlier were given the version 8 specification and one job each, with the same rule that a claim needs working code. Claude reran the main demonstrations.

**Mathematical attack.**

- No pattern and no recovery of key material at 1, 2 or 3 rounds with the key layers on, for messages of 8 bytes or more, using difference attacks, sum attacks of first and second order, and the AI attack. The one-round break of version 7 was not repeated.
- The all-zero weakness is closed: 2,000 keys gave 2,000 different outputs for the all-zero message.
- Test mode with one key is a fixed table for very short messages. 256 chosen messages tabulate every 1-byte message and 65,536 every 2-byte message, at all 8 rounds. This is a property of test mode having no random start value; sealed messages each get a fresh key.
- With the key layers off, one round is still undone with about 128 chosen messages, because the chains can be stripped and the secret parts do not mix between groups of 8 within one round.
- Its criticism of the design: nearly all the spreading comes from the chains, which hold no secret, so the design depends heavily on the closing key layer. It recommended adding key material to the chains, adding secret mixing between groups, and using XOR in place of addition for the key layers. None of these was adopted. They are recorded as open questions because each adds parts and none answers a demonstrated flaw.
- Its methods did not detect the one-round pattern that the long-stream test shows in the table above.

**Key setup and sealing.** Of the nine faults found in version 7, seven were fully fixed and two partly. It found no way for an outsider holding only sealed messages to read, forge or recover a key. Its new findings all need misuse or hostile code in the same page:

| Finding | What was done |
| --- | --- |
| The scrypt settings were exported as a live object that other code could weaken | Frozen |
| Test mode accepted a real passphrase with no stretching, under the names encrypt and decrypt | Renamed testScramble and testUnscramble; empty keys refused |
| A salt passed in as a Node Buffer stayed linked to the caller's memory | Every input is now copied privately |
| Settings planted on the shared object prototype reached the start value and the test switches inside seal and open | seal and open read no outside settings; the chosen start value moved to a separate test function |
| The random source was looked up at each call and could be replaced | Chosen once at load, Node's own when present; an all-zero result is refused |
| open checked the tag on one copy of its input and unscrambled another | One private copy is checked and used |
| A 16 MB message took 71 seconds and 0.7 GB | Limit lowered to 4 MB on both seal and open |
| Exported sha256 treated text as zero bytes; scrypt and pbkdf2 accepted nonsense settings | Text is encoded properly; settings are checked |
| Other code in the same page can read the stretched key out of the library | Not fixable from inside a library. Stated in the specification. |
| A passphrase and the same passphrase with zero bytes added give the same key | A property of HMAC inside scrypt. Stated in the specification. |

None of the fixes changed the cipher's output.

**Rebuild from the specification alone.** All nine reference outputs then in the specification matched on its first run. It also tried 41 deliberately wrong readings. Only skipping or changing the text normalisation still matched all nine, because the reference passphrase is plain letters. The tie rule was caught by one output only. Four reference outputs were added in response (an accented key in both typed forms, a 1-byte message, a sealed 21-byte message), and six sentences it flagged as unclear were tightened.

### Review by three other companies' AI models (November 16, 2026)

Josh pasted a brief and the version 8 specification into Grok, Gemini and ChatGPT, each in a fresh chat on a free plan, and brought back their answers. Claude tested every claim that was specific enough to test. The same rule applied: a claimed break counts only if it can be demonstrated.

| Model | Claimed | Checked result |
| --- | --- | --- |
| Grok | One round broken for 8-byte messages with 4 chosen messages and about 4 billion guesses: subtract two outputs to cancel the closing key layer, then undo the chains | Does not work as written. The difference of two outputs is not enough to undo the chains. In a test, 20,000 different closing keys gave the same output difference and 20,000 different results after stripping the chains. Grok gave no code and said it could not reproduce the reference outputs. |
| Gemini | One round broken with about 256 chosen messages; two rounds with 65,000 to a million; no margin at 8 rounds | No method or code given for any of these. The one-round claim rests on the same step as Grok's. Two statements were wrong: that the 16-byte fingerprint can be forged in 2⁶⁴ work, and that input positions can be watched moving to output positions. |
| ChatGPT | An exact property of one round for 8-byte messages: if every byte of the message has 128 added, the last output byte always differs | Confirmed. Its two test vectors matched the reference code exactly, and in 40,000 pairs over random keys the last byte never matched. |

**The ChatGPT finding in detail.** Adding 128 to a byte flips only its top bit. The key layer keeps that difference, and the spiral cannot change it because every position has the same difference. In the crossing, the first step of each pair is x + y, and 128 + 128 is 0 modulo 256, so the difference cancels in x and stays in y. After the three stages exactly one byte in each group of 8 still differs, whatever the key. The pinch and the exits move and change that byte but cannot remove it, and for an 8-byte message the forward chain carries it to the last byte, which the backward chain never touches. This is a property that holds every time, found by reasoning about the structure, and none of the earlier tests or agents found it.

Its reach, as measured: it holds for 8-byte messages at one round. For messages of 9 to 64 bytes at one round no output byte showed it, though the underlying fact (one differing byte per group after the crossing) is true at every length. At 2, 3 and 8 rounds, 150,000 to 400,000 pairs per setting showed match rates at chance. It tells one round from random; it does not recover a key.

Other points ChatGPT made that are correct:

- The golden step adds nothing measurable to the spiral order. Each position's seat is the golden value plus a uniformly random 16-bit key twist, and adding a fixed number to a uniformly random one leaves it uniformly random. Since version 3 added the twist, the order has in effect come from the twist alone.
- Above 65,536 bytes the 16-bit seats collide heavily, and tied positions keep their original order, so the spiral is far from a random reordering for large messages.
- In test mode the closing key layer does not depend on the round count, so outputs at different round counts under one key can be compared. Sealed messages always use 8 rounds and are not affected.

What all the reviewers agree on, counting the earlier attack agent:

| Point | Raised by |
| --- | --- |
| The chains do nearly all the spreading and hold no secret | Attack agent, Grok, Gemini, ChatGPT |
| The spiral costs a lot for what it adds | Grok, Gemini, ChatGPT |
| The key setup, key tree and sealed format have no way in | Grok, Gemini, ChatGPT |
| Not for real data; use a standard cipher | All |

They differ on the remedy for the chains. The attack agent, Grok and Gemini say put key material into them. ChatGPT says that would make the design harder to analyse without making it sound.

No reviewer produced an attack on 2 or more rounds. Status of version 8 after this review: one round is distinguishable by two separate methods; the crossing has a confirmed structural fault; nothing is known against 2 to 8 rounds. No design change has been made yet.

### Version 9: design decisions (November 16, 2026)

After the outside review Josh was asked whether the golden angle should be made to matter again or be kept as part of the picture only. His answer was that parts which are not useful should not be used. On that basis:

- **Golden-angle spiral removed.** The key now shuffles the positions directly with a Fisher-Yates shuffle, so every order is equally likely and there are no ties. The odd-round reversal went with it, since reversing a random order gives another random order. This step is no longer a spiral in any mathematical sense. The vortex remains the description of how data moves through a round, and the golden spiral remains in the animation and in this record.
- **Crossing changed.** The pair step was x = x + y, then y = y XOR rotl(x). It is now x = x + rotl(y), then y = y XOR rotl(x). A search over every difference applied to a whole group and a sample of rotation settings found no case that cancels with certainty. The worst case was one output byte unchanged about 11% of the time for one rotation setting, against 0.4% by chance and 100% before.
- **Chains keyed.** Each chain step takes one key byte inside the pinch table lookup. Four reviewers asked for this; ChatGPT argued against it. It was adopted because it costs little and removes the ability to strip the chains from a known state.
- **Tail group added.** Found necessary by the agent review below.

### Agent attack on the trial version 9, and the fix

A fresh agent was given the trial specification and code, the history of how each earlier version fell, and the instruction to look for relatives of ChatGPT's finding. Claude reran its two main demonstrations.

- ChatGPT's all-bytes-128 difference is closed. In the crossing alone, 0 of 343 rotation settings give an exact result. At the output, with all key layers on, it showed nothing at 1, 2 or 3 rounds for lengths 8, 16, 20 and 64.
- A relative remains inside the crossing. A top-bit change in a single byte passes through the crossing with certainty for every rotation setting, because flipping the top bit is the same as adding 128 and passes every addition. The pinch that follows destroys it, and it does not reach the output of even one round. The design's protection against this family is one pinch per round.
- A new one-round weak spot was found. When the length was one more than a multiple of 8, the last byte formed a group of one and had nothing to cross with. At one round its output difference followed the pinch table's own pattern (9 bytes: z about 33 over 600,000 pairs, all of it at the last position). At 2, 3, 4 and 8 rounds it was gone.
- An apparent result on 2-byte messages was shown by the agent to be a fault in its own measurement: an ideal 16-bit shuffle gave the same number.
- Nothing it tried showed anything at 2 or more rounds: additive differences, whole-message differences, two-valued patterns, sum attacks, and a structure-only attack.

The fix adopted for version 9: when the length is 8 or more and not a multiple of 8, a tail group covers the last 8 bytes, overlapping the group before it, and takes part in the crossing and the exits like any other group. With the fix, the agent's own test gave z = −0.8 at one round for 9 bytes, and its scan of lengths 8 to 25 showed nothing at 9, 17 or 25.

### Version 9 test record (November 16, 2026)

"Key layers off" means the key layer of every round, both chain keys and the closing key layer are left out. A restart of the test machine interrupted the battery once; the interrupted runs were started again from the beginning and no results were lost.

Correctness:

- 1,800 scramble and unscramble round trips at lengths 0 to 299 and 1, 2 and 8 rounds, key layers on and off: 0 failures.
- All 496 single-bit changes to a sealed message were rejected.
- The built-in SHA-256, HMAC and scrypt matched Node's own on 401 comparisons, including one at the real scrypt setting.
- The Python rebuild, updated by Claude from the new rules, matched all 18 reference outputs and 612 further cases with 600 round trips checked.
- A separate agent given only the specification text rebuilt the cipher and matched all 16 reference outputs then present on its first run. It tried 47 deliberately wrong readings and every one failed at least one reference output. It noted that the order for undoing overlapping groups was not covered by any reference output; two unscrambling outputs with a tail group were added.
- One bit changed in a 40-byte message flips 50.06% of the output. One bit changed in the key flips 50.02%.

Long-stream test (PractRand 0.94, counter test stream, 1 GB each):

| Rounds | Key layers | Keys | Result |
| --- | --- | --- | --- |
| 1 | on | golden-spiral | No anomalies. |
| 1 | off | golden-spiral | One "unusual" flag at 1 GB and one "mildly suspicious" at 16 MB that did not persist. |
| 2 | on | golden-spiral, key-a | No anomalies on both. |
| 2 | off | golden-spiral | One "unusual" flag at 1 GB. |
| 3 | off | golden-spiral | No anomalies. |
| 4 | on | key-a | No anomalies. |
| 8 | on | golden-spiral, key-a, key-b | No anomalies on all three. |
| 8 | off | golden-spiral | No anomalies. |

Other attacks, on 16-byte messages unless stated:

| Attack | 1 round | 2 rounds | 3 to 8 rounds |
| --- | --- | --- | --- |
| AI attack, 20,000 examples, key layers off | 50.8% | 50.3% | 48.9% to 50.5% |
| AI attack, 20,000 examples, key layers on | 50.9% | 49.7% | 48.8% to 51.5% |
| AI attack, 100,000 examples, key layers off | not run | 50.4% and 49.7% | 49.8% to 50.1% at 3 and 4 rounds |
| Pattern count, 40,000 pairs | no repeats | no repeats | no repeats |
| Four-message test, 20,000 groups | no bias | no bias | no bias |
| Search of all 128 one-bit changes | not run | none held on re-test | none held on re-test at 3 rounds |
| All-256-values attack (chance 0.39%) | 0.44% off, 0.38% on | 0.39% off, 0.44% on | 0.23% to 0.50% at 3 and 4 rounds |
| Shortcut search, 16,384 links (chance about 2.9%) | 2.9% to 3.0% | 2.7% | 2.8% to 2.9% at 3 rounds |
| Heavy-data test, 2.5 million pairs | not run | clean, key layers on | see below |

Two borderline results, each repeated on fresh data:

- Heavy-data test at 3 rounds, key layers off: smallest of 16 p-values 9.7e-4, against a line of about 6e-4. Two repeats gave 1.1e-2 and 5.8e-2. Recorded as chance.
- NIST SP 800-22 at 8 rounds, key layers off, golden-spiral: 185 of 188 rows passed. Two template rows were at 95 of 100 against a pass mark of 96, and one random-excursions row had an uneven spread of p-values (p = 0.000097). The same suite on a second key, key-a, passed 188 of 188. With the key layers on it passed 188 of 188. Recorded as chance, with the first result stated.

What this record cannot show: every test in it now passes at one round, with the key layers on. In version 8 the long-stream test and ChatGPT's test could each see one round. In version 9 nothing in this set can. So these results say that the output looks random, and say almost nothing about how many rounds are needed. The two findings that mattered in versions 7 and 8 came from reasoning about the structure.

Not tested on version 9: more than three keys at any setting; anything beyond 1 GB; the weak-pinch study; the removal study; a review of the key setup and sealing code, which did not change from version 8 apart from labels.

### Outside AI review of version 9 (November 17, 2026)

Josh pasted a new brief and the version 9 specification into Gemini, ChatGPT and Grok. The brief told them how each earlier version fell, which earlier attack claims had failed and why, and asked for procedures that can be run. Grok's written answer came with a side search still running after about two hours; the answer is recorded below and Claude ran the search itself.

| Model | What it reported | Checked result |
| --- | --- | --- |
| Gemini | No break at 1, 2 or 3 rounds. Verdict: 8 rounds give "a very comfortable security margin" | Nothing to check: no procedure, no code. The day before, the same model said version 8 had "zero structural security margin", also without evidence. It gave the AES table's worst-case difference probability as 2 in 256; the correct figure is 4 in 256. Given no weight in either direction. |
| ChatGPT | Built its own implementation and matched seven test-mode outputs, the stretched base key and the sealed `Vortex` output. No attack at 1, 2, 3 or 8 rounds. Its version 8 differential is closed and it found no replacement | Consistent with Claude's own results. Its difference experiments used 1,000 pairs each, which it noted is small. |
| Grok | Says it built a Python implementation that matched every reference output, including the 70,000-byte hash. No break or pattern at one round for lengths 8, 9, 16 and under 8, and nothing at 2 or 3 rounds. The tail group is "a net improvement". No flaw in the key setup or sealed format. Verdict: "Eight rounds supplies a large practical margin"; "four rounds would already be conservative" | Its findings agree with Claude's and ChatGPT's. Its difference probes used 200 to 1,000 pairs, which is small. One statement was wrong: that the closing additive layer preserves XOR differences (it does so only for the top bit). The margin statement has no working behind it and is given no weight. |

Points ChatGPT raised, and what was done:

- **Side-root keys had no stated use.** Correct as a gap in the specification. They are meant as separate keys that leave the tree. The key tree section now says so.
- **Keying the chains by XOR into the table input does not change the table's difference or straight-line behaviour.** Correct. It stops the chains being stripped; it does not make them a new keyed function. Standard ciphers add keys the same way. Recorded as a limit of the fix, no change made.
- **The note about passphrases followed by zero bytes was too broad.** Correct. It holds only while the total stays within 64 bytes. The note was corrected.
- **The wording on the random source was too loose.** The seal section now names the required kind of generator and what happens if it is missing.
- **`kb[n − 1]` is drawn and not used.** True and harmless; already stated in step 7.
- **Lead: the last byte is structurally special, because the backward chain never changes it.** Tested by Claude: the spread of output differences at every position, for five kinds of chosen change (top bit in one byte, low bit in the last byte, top bit in every byte, add 1 to every byte, a varying single-byte change), lengths 8, 9, 16, 17 and 24 at one round and 8 and 16 at two rounds, 60 keys and 240,000 pairs per setting. The last byte gave z between −1.4 and 1.6; the largest value at any position in any run was 2.6 among 160 positions looked at. Nothing found.

ChatGPT's verdict: "I would not call Version 9 broken. I also would not call it cryptographically sound." It declined to give a margin for 8 rounds, on the ground that nothing connects one round resisting an attack to eight rounds being safe, and it recommended mathematical analysis of the chains over further randomness testing. This record agrees with all three points.

**Search for crossing differences that do not depend on the rotation.** Grok started this search and it had not finished after about two hours, so Claude ran it exhaustively: every XOR difference and every additive difference on the two inputs of one crossing pair, every rotation from 1 to 7, all 65,536 input values.

- Exactly one XOR difference gives a certain result for every rotation: the top bit in the lower byte alone, (0x80, 0), which comes out as (0x80, rotl(0x80, r)). This is the top-bit property already listed in the limits.
- Fifteen XOR differences are certain for at least one rotation. Seven have the form (0, 2^(7 − r)): the rotation carries the bit to the top, and it comes out as (0x80, 2^(7 − r) XOR rotl(0x80, r)). Seven have the form (0x80, 2^(7 − r)): the two top-bit contributions cancel in the addition, x comes out unchanged and y keeps its difference. The fifteenth is the one above.
- No additive difference is certain for any rotation.
- A sample of one in seven XOR differences, measured exhaustively, found one that gives its best output difference with probability 50% or more at every rotation: (0x7f, 0xff).

The seven cancelling differences are the nearest relatives of the version 8 flaw. Each needs two different differences placed on the two particular bytes that a pair joins, and the right one of seven rotations. Which bytes are paired is decided by the key shuffle in step 2. In version 8 the same difference on every byte did the job, which is why no shuffle could stop it. None of the differences found here is the same on both bytes, so none can be placed without knowing the shuffle. This is the one place where the secret shuffle has been shown to do necessary work. It has not been shown that an attacker cannot learn enough about the shuffle to use them.

### Version 6 retest and the 2-round finding (November 14, 2026)

Version 6 changes the spiral seats, so every output changed and every test was run again.

Results that match the earlier versions:

- Correctness: 418 scramble round trips and 601 seal, tamper and key-stretcher checks passed. The Python rebuild, updated to version 6, matched all four reference outputs and 538 further cases.
- Spreading: one changed bit flips 50.00% of the output.
- AI attack with the key stream off: 98.8% at 1 round. About 50% at 2 to 8 rounds with 20,000 examples. 49.80%, 50.29% and 50.43% at 2, 3 and 4 rounds with 100,000 examples.
- Four-message test, difference search and shortcut search: nothing found from 2 rounds up.
- All-256-values attack: 1 round cancels 15 to 17% of the time. From 2 rounds it is at chance level.
- Heavy-data test at 2 to 3 million pairs: smallest p-values between 0.016 and 0.12, where below 0.0006 would be suspicious.
- PractRand to 256 MB at 8 rounds, with and without the key stream: no anomalies.

One result that differs slightly. The NIST reference program, at 100 sequences of 1 million bits, flagged 1 of 188 sub-tests in three of four runs: one non-overlapping-template sub-test at 95 of 100 in each run with key `golden-spiral`, and one random-excursions sub-test at 53 of 57 in the full-cipher run with a second key. The fourth run flagged none. Version 5 had none flagged. The flagged sub-test was different each time, and a truly random source also trips one now and then at these settings, so this looks like chance. It is recorded because it is not the clean sheet version 5 had.

The new finding came from running PractRand 0.94 four times longer than before, to 1 GB, on the same kind of input stream as the standard suites below.

| Version | Rounds | Key stream | Key | Result at 1 GB |
| --- | --- | --- | --- | --- |
| 6 | 8 | on | `golden-spiral` | No anomalies |
| 6 | 8 | off | `golden-spiral` | No anomalies |
| 6 | 4 | off | `golden-spiral` | One flag at the mildest level, "unusual" |
| 6 | 3 | off | `golden-spiral` | One "mildly suspicious" flag |
| 6 | 2 | on | `golden-spiral` | Fail at 512 MB (Gap-16, p = 4.3e-11) |
| 6 | 2 | off | `golden-spiral` | Fail (Gap-16, p = 3.9e-15) |
| 6 | 2 | off | `second-key` | No anomalies |
| 6 | 2 | off | `key-a` | "Very suspicious" from 256 MB on (BRank, p = 1.6e-8), no fail |
| 6 | 2 | off | `key-b` | No anomalies |
| 6 | 2 | off | `key-c` | Mild flags only |
| 6 | 2 | off | `key-d` | Fail (BRank, p = 4.6e-70, and FPF, p = 1.4e-13) |
| 5 | 2 | off | `golden-spiral` | No anomalies |
| 5 | 2 | off | `key-a` | Mild flags only |
| 5 | 2 | off | `key-b` | No anomalies |
| 5 | 2 | off | `key-c` | Fail at 256 MB (FPF, p = 7.3e-22) |
| 5 | 2 | off | `key-d` | Fail at 256 MB (BRank, p = 1.1e-16) |

What this shows:

- Two rounds are not enough. Version 6 failed on 2 of 6 keys and came close on a third. Version 5 failed on 2 of 5. With key `golden-spiral`, version 6 failed at 2 rounds even with the key stream on.
- The weakness was not introduced by the whole-number spiral. Version 5 has it at a similar rate. The earlier tests on versions 4 and 5 stopped at 256 MB and used one key, which happens to be one that passes.
- These runs cannot say whether version 6 is slightly better or worse than version 5 at 2 rounds. Five or six keys each is too few.
- Eight rounds showed nothing at 1 GB. The single flags at 3 and 4 rounds are mild enough to be chance, and are too few runs to rely on either way.
- The earlier statement in this record that the cipher is clean from 2 rounds up, with a safety margin of 6 rounds, is withdrawn.

Added November 15, 2026. Rounds 3, 4 and 5 were run on four more keys each (`key-a` to `key-d`), version 6, key stream off:

- 3 rounds: all four keys finished 1 GB with no anomalies at the end. One key showed a single "unusual" flag at 256 MB and 512 MB that was gone at 1 GB.
- 4 rounds: all four keys finished 1 GB with no anomalies at any checkpoint.
- 5 rounds: the run hit its 2-hour time limit and stopped at 256 MB. To that point, no anomalies on two keys and passing "unusual" flags on the other two that were gone by 256 MB. This is not a 1 GB result. The 5-round run was restarted on its own.

With these, 3 and 4 rounds have five keys each at 1 GB with nothing worse than one "mildly suspicious" flag. The strong failures seen at 2 rounds did not appear at 3 or 4. Five keys is still a small sample, and 1 GB is a small test by the standards of cipher review.

The restarted 5-round run finished 1 GB on all four keys. Three ended with no anomalies. One (`key-a`) ended with a single "unusual" flag on the Gap-16 test (p = 2.0e-3), the mildest level. Gap-16 is the test that failed outright at 2 rounds, so this flag is noted, but one flag at that level among 135 results per run is also what chance produces. Rounds 6 and 7 were started next on two keys each.

Rounds 6 and 7 finished 1 GB on two keys each (`key-a`, `key-b`), version 6, key stream off. At 6 rounds, one key ended with no anomalies and one with a single "unusual" flag (DC6, p = 1.7e-3). At 7 rounds, both ended with no anomalies; one showed two "unusual" flags at 512 MB that were gone at 1 GB.

Summary of November 14 and 15 at 1 GB: 2 rounds fail on 2 of 6 keys. Rounds 3 to 7, on two to five keys each, had no failures and nothing above one "mildly suspicious" flag. Eight rounds, one key, no anomalies. In these runs the failures stop after 2 rounds. This is a measurement on a few keys with one test program, not a proven margin. The Spiral Code Lab page was updated to say this.

### Why 2 rounds fail (November 15, 2026)

The cause was traced by looking inside the cipher while it scrambled the test stream. The test stream is 4,096-byte blocks that are identical except for a counter in the first bytes.

Mechanism:

- In round 1, each changing input byte lands in exactly one of the 512 columns. This was checked by tracing each counter byte on six keys. So round 1 mixes only two or three columns per block.
- The forward and backward chains carry that change to the rest of the block. The chains use no key material when the key stream is off, and with it on they add only a fixed value per position. Either way they pass a change along by XOR and rotation without adding to it. Long stretches of the round-1 output depend on only one or two bytes, and some positions do not change at all.
- Round 2 then merges columns whose eight inputs carry very little variety, so its columns take few distinct values.
- Both chains can be undone by anyone without the key. After undoing them on the 2-round output, whole 8-byte columns repeat from block to block. Random output would essentially never repeat an 8-byte value in this many blocks.

Measurement: 65,536 blocks per key, version 6. Each cell counts distinct 8-byte values seen in one column position, out of 65,536 possible. Columns were compared by a 32-bit hash, which by itself loses up to about 5 per column, so 65,531 and above counts as full.

| Key | Key stream | 1 GB result at 2 rounds | Round-1 bytes that never change | Median column after round 2 | Columns with 256 or fewer values after round 2 | Lowest column after round 3 |
| --- | --- | --- | --- | --- | --- | --- |
| `golden-spiral` | off | Fail | 7 | 42,585 | 0 | 65,532 |
| `golden-spiral` | on | Fail | 7 | 40,960 | 0 | 65,531 |
| `second-key` | off | No anomalies | 59 | 40,798 | 29 | 65,531 |
| `key-a` | off | Very suspicious | 3 | 39,780 | 0 | 65,532 |
| `key-b` | off | No anomalies | 65 | 41,406 | 28 | 65,533 |
| `key-b` | on | not run | 65 | 41,495 | 28 | 65,532 |
| `key-c` | off | Mild flags | 36 | 63,730 | 18 | 65,533 |
| `key-d` | off | Fail | 16 | 29,947 | 176 | 65,532 |

What this shows:

- The 2-round weakness is present on every key tested, including the two that passed the 1 GB test. The earlier figure of about 1 key in 3 was how often PractRand happened to catch it, not how often it exists. This column-repeat check finds it on all six keys with a quarter of the data.
- It is present with the key stream on.
- It comes from the chains, which are unchanged since version 4. That matches versions 5 and 6 failing alike.
- After round 3 every column is full on every key. On this measure the weakness is gone at 3 rounds. This is one measure and does not prove 3 rounds are sound.
- The test stream is a hard case on purpose: blocks that differ in a few bytes. Real messages that differ in a few bytes would meet the same thing at 2 rounds.

Followed up the same day: version 7 rebuilt both chains to add to a change as they spread it. The results are in the version 7 test record above.

Not tested: more than one key at 8 rounds; anything beyond 1 GB.

### Correctness

| Check | Size | Result |
| --- | --- | --- |
| Scramble then unscramble returns the message, with and without the key stream | 300 random messages of 0 to 299 bytes, random keys | 600 of 600 correct |
| Seal then open returns the message | Same 300 messages | 300 of 300 correct |
| Open with one key bit changed is rejected | Same 300 messages | 300 of 300 rejected |
| Open with one message bit changed is rejected | Same 300 messages | 300 of 300 rejected |
| SHA-256 and HMAC match the Node.js built-in versions | 400 inputs each | 0 mismatches |

### Key stretcher (version 5)

Version 5 changes only how a passphrase becomes the base key for sealed messages. The scrambling rounds are identical to version 4, and raw mode gives the same output byte for byte, so every attack result in this record applies to both versions.

| Check | Size | Result |
| --- | --- | --- |
| scrypt matches the Node.js built-in version | 15 runs across 5 parameter sets, including the one used | 0 mismatches |
| scrypt reproduces the published RFC 7914 test vector | password `password`, salt `NaCl`, N 1024, r 8, p 16 | Matches |
| PBKDF2-HMAC-SHA-256 matches the Node.js built-in version | 20 random inputs | 0 mismatches |
| Seal then open returns the message | 300 random messages of 0 to 299 bytes | 300 of 300 correct |
| Open with one bit of the sealed message changed is rejected | Same 300 messages | 300 of 300 rejected |
| Open with a passphrase one letter off is rejected | 1 message | Rejected |
| Time for one stretch | Node.js and Chromium, on the test machine | 0.59 and 0.73 seconds |
| Cost of one passphrase guess, before and after | Same machine, one core, JavaScript | About 6 microseconds before, about 0.6 seconds and 32 MB after |

### Spreading (avalanche)

A good cipher flips about 50% of output bits when one input bit changes.

| Change | Size | Output bits flipped |
| --- | --- | --- |
| One bit of a 40-byte message | 2,000 trials | 50.08% |
| One bit of the key | 2,000 trials | 49.98% |
| One bit of a 1-byte message, key stream off | 2,000 trials | 50.04% |
| One bit of a message of 1 to 9 bytes | 4,000 trials per length | 49.8% to 50.3% |
| One bit at the start, middle or end of a 4,096-byte message, 2 and 8 rounds | 40 trials each | 49.94% to 50.11%, weakest 64-byte stretch 41.4% |

### Randomness

Five tests from NIST SP 800-22 on the output of scrambling 64 KB of zeros with key `golden-spiral`. A score (p-value) of 0.01 or more passes.

| Source | Frequency | Block frequency | Runs | Longest run | Byte spread | Result |
| --- | --- | --- | --- | --- | --- | --- |
| Full cipher, 8 rounds | 0.641 | 0.540 | 1.000 | 0.338 | 0.545 | 5 of 5 pass |
| Full cipher, 1 round | 0.200 | 0.042 | 0.633 | 0.013 | 0.446 | 5 of 5 pass |
| Key stream off, 1 round | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0 of 5 pass |
| Key stream off, 8 rounds | 0.029 | 0.567 | 0.632 | 0.792 | 0.524 | 5 of 5 pass |

### Attacks

All attacks used 16-byte messages. Each was run on the full cipher and with the key stream off, and the worse result is shown.

| Attack | Method and size | 1 round | 2 rounds | 3 or more rounds |
| --- | --- | --- | --- | --- |
| AI attack | Neural network, 128 inputs, 64 hidden units. 20,000 training pairs differing in one bit, fresh key each. Tested on 4,000. 50% is guessing. | Broken: 99.1% | 50.3% full, 47.4% stream off | 48.6% to 51.2% |
| Bigger AI attack | Same network, 100,000 training pairs, 20,000 test, key stream off | Not run | 50.02% | 50.05% and 50.72% at 3 and 4 rounds |
| Four-message test | Whether E(a) XOR E(b) XOR E(c) XOR E(a XOR b XOR c) is biased, 20,000 groups of closely related messages | Broken: zero every time | No bias | No bias |
| All-256-values attack | One byte takes all 256 values, outputs are XORed. Chance of a zero byte is 0.39%. 400 trials. | Broken: 15.25% | 0.25% to 0.31% | 0.33% to 0.44% |
| Pattern count | Repeated output differences among 40,000 pairs under one key | No repeats | No repeats | No repeats |
| One-bit change search | All 128 one-bit changes, the worst retested on 60,000 fresh pairs. Chance level about 0.6% bias. | Not run | 0.56% to 0.63% | 0.56% to 0.71% |
| Shortcut search | Strongest of 16,384 links between one input bit and one output bit, 20,000 messages. Chance level about 2.9%. | 3.02% | 3.32% | 3.04% |
| Heavy-data test | Chi-square on each output byte's difference, one key. Smallest of 16 p-values, suspicious below 0.0006. | 0.053 at 100,000 pairs | 0.018 at 3 million pairs, stream off. 0.048 and 0.083 at 3 million, full. | 0.030 and 0.038 at 2.5 million pairs, 3 rounds. 0.014 at 2 million pairs, 4 rounds. |

### Standard test suites

Both industry-standard suites passed, with and without the key stream. The input stream was a run of 4,096-byte blocks, all zero except an 8-byte counter, each scrambled in raw mode with key `golden-spiral`, and the outputs joined.

| Suite | Stream | Size | Result |
| --- | --- | --- | --- |
| PractRand 0.94 | Full cipher, 8 rounds | 256 MB | No anomalies in 118 tests |
| PractRand 0.94 | Key stream off, 8 rounds | 256 MB | No anomalies in 118 tests |
| PractRand 0.94 | Key stream off, 2 rounds | 256 MB | No anomalies in 118 tests |
| NIST SP 800-22 reference program, all 15 test types | Full cipher, 8 rounds | 100 sequences of 1 million bits | 188 of 188 sub-tests passed, none flagged |
| NIST SP 800-22 reference program, all 15 test types | Key stream off, 8 rounds | 100 sequences of 1 million bits | 188 of 188 sub-tests passed, none flagged |
| NIST SP 800-22 reference program, control | True random data from the operating system | 100 sequences of 1 million bits | 188 of 188 sub-tests passed, none flagged |

Two notes on method. PractRand showed a single mild flag at an early checkpoint on two streams, which had cleared by the next checkpoint and did not return. A first attempt at the NIST tests used a third-party Python library, which reported failures. The same library failed the same tests on true random data, so it was faulty and its results were discarded.

### Weak-pinch study

The vortex structure does most of the work: with any pinch that bends the maths at all, 2 rounds are clean, and with no bending it needs 3. The AES table is not what makes it pass. Every run had the key stream off, used 16-byte messages, and applied the heavy-data test (smallest of 32 p-values over two input changes, a leak if below 0.0003) and the four-message test.

| Pinch table | What it is | 2 rounds | 3 rounds |
| --- | --- | --- | --- |
| AES table | The strongest known 8-bit table | Clean at 300,000 pairs. Clean at 3 million in the earlier run. | Clean at 300,000 pairs |
| Random table | An ordinary shuffle of 0 to 255 from a fixed seed | Clean at 3 million pairs | Clean at 300,000 pairs |
| Weak multiply | x × 5 + 1 modulo 256, which bends only slightly | Clean at 3 million pairs | Clean at 300,000 pairs |
| Rotate and flip | Rotate left by 1, XOR 0x63. No bending at all. | Leaks at 300,000 pairs | Clean at 3 million pairs |
| No pinch | The step removed | Leaks at 300,000 pairs | Clean at 3 million pairs |

The four-message test found no straight-line behaviour in any of the ten combinations, 0 of 5,000 groups each. Run on November 14, 2026.

### What this record does not show

- No test here proves security. Passing means these specific attacks found nothing.
- The attacks used 16-byte messages and simple one-bit changes. A cryptographer would hand-pick changes designed to pass through the crossing.
- The standard suites test whether the output looks random. They do not test whether a key can be recovered.
- Nobody other than Claude has run or checked these tests.

### Second implementation (November 14, 2026)

The cipher was written a second time, in Python, from the Specification section of this record and not from vortex.js. The purpose was to check that the specification is complete enough to rebuild from.

- All four reference outputs matched on the first run.
- 538 further cases were then compared against vortex.js with random keys and messages: 532 raw-mode cases at lengths from 0 to 200,000 bytes and at 1, 2 and 8 rounds, and 6 sealed messages. All 538 matched. 528 round trips and 6 tamper rejections were also correct in the Python version.
- Six places where the specification left a choice open were found and are now written down under Notes for implementers.

Version 6 update: the Python version was changed to the whole-number spiral and compared again. All four new reference outputs and all 538 further cases matched.

Version 7 update (November 15, 2026): the Python version was changed to the new chains and compared again. All four new reference outputs and all 538 further cases matched.

Limit of this check: both versions were written by Claude, which also wrote the specification. It shows the document is complete enough for its own author to rebuild from. It is not an independent rebuild. That needs a person or tool that has never seen vortex.js.

Files: vortex\_ref.py (the Python version) and cross\_check.py (the comparison).

## Known limits and open questions

The largest limit is that no cryptographer has examined the design. The others follow.

The safety margin is unknown. Nothing has been demonstrated against version 9 at any round count, but that is weaker than it sounds: no test in the set can see even one round any more, each setting has been run on one to three keys and 1 GB, and the design is hours old. Every flaw found in versions 7 and 8 was found by an AI reviewer reasoning about the structure, and each of those versions looked clean on the same tests the day before. A top-bit change still passes every addition in the design and is stopped only by the pinch, and the chains remain the only thing that spreads a change between groups within a round. Grok, Gemini and ChatGPT each judged the design not worth trusting with real data and recommended a standard cipher.

- **Weak passphrases.** Version 5 stretches the passphrase with scrypt, so each guess costs about 0.6 seconds and 32 MB. A very weak passphrase can still be guessed, only far more slowly. Attackers with custom hardware pay less per guess than a laptop does.
- **Borrowed strength.** The pinch table comes from AES and the key material from SHA-256. The weak-pinch study shows the structure does not depend on the AES table to pass these tests. It does depend on SHA-256 for all key material, and that has not been separated.
- **How new it is.** Every building block already exists: keyed permutations, butterfly mixing, substitution boxes, key trees, authentication codes. What may be new is the combination and the torus picture that organises it. That has not been checked against the published literature.
- **Speed.** One 16-byte scramble takes about 44 microseconds in JavaScript. AES in hardware is thousands of times faster. Most of the time goes on generating key material and sorting the spiral.
- **Timing leaks.** The code has not been written to run in constant time, so the time it takes could reveal information about the key.
- **Small test scale.** The largest attack used 4 million pairs. Serious analysis uses far more, and methods that do not rely on volume.
- **The guardian layer is not built.** It is designed on paper in the Guardian layer tab. Nothing is built or tested.

Open questions for an expert:

1. Is there a chosen difference that passes through the crossing and the pinch with high probability over 2 or 3 rounds?
2. Does keying the spiral order and the exits add real strength, or does it only cost speed, compared with fixed public orders?
3. Do the forward and backward chains create a weakness for very long messages?
4. How many rounds can be broken, and so what is the true safety margin of 8?

