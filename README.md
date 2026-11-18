# The Vortex Cipher

**A homemade cipher, offered for breaking. Do not use it to protect anything.**

The Vortex Cipher is a learning design by Josh Hutchens. It has not been reviewed by a cryptographer, and a cipher earns trust only after many experts have tried and failed to break it over years. If you need to protect real data, use a standard, reviewed algorithm such as AES-GCM or ChaCha20-Poly1305.

It is published so that anyone who enjoys breaking ciphers can try, and so that the record of how it was built, broken and rebuilt is useful to others learning the same way.

## The idea

Data travels as streams through two funnels joined at the narrow end, like two tornadoes meeting. At the crossing the streams merge and swap, they leave in directions the key chooses, and they loop back in at the top for the next round. Roots grow from a single seed: every key the cipher uses comes from one passphrase through a tree of derived keys.

Version 9 keeps the parts of that picture that were shown to do work and drops the parts that did not. The full specification is in [SPEC.md](SPEC.md).

## How it held up

Each version was attacked, and each break led to the next version.

| Version | What happened |
|---|---|
| 7 | One round fully broken with about 15 chosen messages: the chains at the end of a round could be stripped by anyone. |
| 8 | An exact one-round shortcut found by an outside AI model: a top-bit difference in every byte cancelled at the crossing. The golden-angle ordering was found to do nothing. |
| Trial 9 | A lone last byte, when the length is one more than a multiple of 8, was weak at one round. Fixed with an overlapping tail group. |
| 9 | No break found so far by AI agents or three outside AI models. Statistical test suites (PractRand to 1 GB, NIST SP 800-22) show nothing at any round count, but those suites also missed the version 8 flaw, so they say little. |

"Not broken by AI so far" is a low bar. That is why it is here. The complete record, including attacks that were claimed and did not work, is in [RECORD.md](RECORD.md). Earlier specifications are in [OLDER-SPECS.md](OLDER-SPECS.md).

## Break it

The most useful targets:

- One round with all key layers on: any exact or high-probability differential, linear or integral property, especially one the secret shuffle cannot disturb.
- Two or three rounds: telling the output from random, or recovering anything.
- The key tree, the passphrase stretching, the start value or the sealed format.
- Anything in the specification that two honest implementations could read differently.

A break counts when it comes with a procedure someone else can run: exact inputs, what to compute, the result to expect and how many messages it needs. Please check your own implementation against the reference outputs in SPEC.md first. Open an issue on this repository with what you found. Failed attempts are welcome too; knowing what does not work is part of the record.

## Run the checks

The JavaScript implementation is [vortex.js](vortex.js). A second, independent implementation in Python is in [reference/](reference/).

```
node test/check.js
```

checks vortex.js against the 18 reference outputs (Node.js 18 or later, no packages needed).

```
node test/make-vectors.js test/vectors.json
cd reference
python3 vortex_ref.py
python3 cross_check.py ../test/vectors.json
```

checks the Python implementation against the same outputs, then against 612 fresh random test vectors produced by the JavaScript one (Python 3.8 or later, standard library only).

## Who made it

Designed by Josh Hutchens. The code was written and the tests were run with Claude, an AI assistant made by Anthropic, working from his design and decisions. Outside reviews came from AI agents and from Grok, Gemini and ChatGPT.

## Licence

Copyright 2026 Josh Hutchens. Released under the [Apache License 2.0](LICENSE): anyone may use, study, change and share it.
