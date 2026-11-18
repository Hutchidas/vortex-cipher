/* Vortex cipher (toy), version 9 + randomness tests + AI distinguisher.
   A learning toy. Not reviewed, not secure. Never protect real data with it. */
(function (globalObj) {
"use strict";
const PHI = (1 + Math.sqrt(5)) / 2;
const GA = Math.PI * (3 - Math.sqrt(5));
const TAU = Math.PI * 2;
// (v9: the golden step was removed from the cipher; with a key twist on every position it no longer affected the order)
// const GOLD32 = 0x61C88647;              // 1640531527: the golden angle as a fraction of a full turn, (3 - sqrt 5) / 2 = 0.381966..., times 2^32, rounded up to an odd number
const LANES = 8;                       // eight code streams cross at the centre
const enc = new TextEncoder();

function mulberry32(a) { return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const rotl8 = (x, k) => ((x << k) | (x >>> (8 - k))) & 255;

/* ---------- SHA-256 (the vetted standard hash; used for all key material) ---------- */
const K256 = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
const W256 = new Uint32Array(64);
function sha256(msg) {
  const len = msg.length, total = ((len + 9 + 63) >> 6) << 6, m = new Uint8Array(total);
  m.set(msg); m[len] = 0x80;
  const bits = len * 8; m[total - 4] = bits >>> 24; m[total - 3] = bits >>> 16; m[total - 2] = bits >>> 8; m[total - 1] = bits;
  m[total - 5] = (len / 0x20000000) & 255;
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = W256;
  for (let o = 0; o < total; o += 64) {
    for (let i = 0; i < 16; i++) w[i] = (m[o + i * 4] << 24) | (m[o + i * 4 + 1] << 16) | (m[o + i * 4 + 2] << 8) | m[o + i * 4 + 3];
    for (let i = 16; i < 64; i++) { const x = w[i - 15], y = w[i - 2];
      w[i] = (w[i - 16] + ((x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ (x >>> 3)) + w[i - 7] + ((y >>> 17 | y << 15) ^ (y >>> 19 | y << 13) ^ (y >>> 10))) | 0; }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + ((e & f) ^ (~e & g)) + K256[i] + w[i]) | 0;
      const t2 = (((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0;
  }
  const out = new Uint8Array(32); [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => { out[i * 4] = v >>> 24; out[i * 4 + 1] = v >>> 16; out[i * 4 + 2] = v >>> 8; out[i * 4 + 3] = v; });
  return out;
}
function wellFormed(str) { for (let i = 0; i < str.length; i++) { const c = str.charCodeAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) { const d = str.charCodeAt(i + 1); if (!(d >= 0xDC00 && d <= 0xDFFF)) return false; i++; } else if (c >= 0xDC00 && c <= 0xDFFF) return false; } return true; }
/* Text becomes bytes one way only: Unicode NFC, then UTF-8. Anything that is not text or bytes is refused. */
const isBytes = x => ArrayBuffer.isView(x) && Object.prototype.toString.call(x) === "[object Uint8Array]";
const copyBytes = x => new Uint8Array(x);                 // a private, plain copy: its length and contents can't change under us
function toBytes(x, what) {
  if (isBytes(x)) return copyBytes(x);
  if (typeof x === "string") { if (!wellFormed(x)) throw new TypeError(what + " is not well-formed text"); return enc.encode(x.normalize("NFC")); }
  throw new TypeError(what + " must be text or bytes (Uint8Array)");
}
function needBytes(x, what, len) {
  if (!isBytes(x)) throw new TypeError(what + " must be bytes (Uint8Array)");
  x = copyBytes(x);
  if (len !== undefined && x.length !== len) throw new RangeError(what + " must be exactly " + len + " bytes");
  return x;
}
function cat(...parts) { const arrs = parts.map(p => typeof p === "string" ? enc.encode(p) : p); const o = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0)); let k = 0; for (const a of arrs) { o.set(a, k); k += a.length; } return o; }
function hmac(key, msg) { key = toBytes(key, "HMAC key"); msg = toBytes(msg, "HMAC message");
  let k = key.length > 64 ? sha256(key) : key; const ip = new Uint8Array(64), op = new Uint8Array(64); ip.fill(0x36); op.fill(0x5c);
  for (let i = 0; i < k.length; i++) { ip[i] ^= k[i]; op[i] ^= k[i]; } return sha256(cat(op, sha256(cat(ip, msg)))); }

/* ---------- key tree: one 256-bit base, with one-way roots growing out of it ---------- */
const VERSION = 9, LABEL = "vortex-v9|";
const root = (parent, label) => hmac(parent, toBytes(label, "label"));    // v8: HMAC, so a root can't be extended or traced back

/* Key material for one round: SHA-256 in counter mode, seeded by the 256-bit round root. */
function roundStream(master, r, n) {
  // v8: the message length is part of the seed, so every length gets its own key material
  const seed = new Uint8Array(45); seed.set(master); seed[32] = r; let ctr = 0, buf = null, pos = 32;
  const hi = Math.floor(n / 4294967296); seed[33] = hi >>> 24; seed[34] = hi >>> 16; seed[35] = hi >>> 8; seed[36] = hi; seed[37] = n >>> 24; seed[38] = n >>> 16; seed[39] = n >>> 8; seed[40] = n;
  const refill = () => { seed[41] = ctr >>> 24; seed[42] = ctr >>> 16; seed[43] = ctr >>> 8; seed[44] = ctr; ctr++; buf = sha256(seed); pos = 0; };
  return { byte() { if (pos === 32) refill(); return buf[pos++]; },
           fill(out) { for (let j = 0; j < out.length; j++) { if (pos === 32) refill(); out[j] = buf[pos++]; } } };
}
/* Everything one round needs, all drawn from the key. */
function roundParams(master, r, n, opts) {
  const g = roundStream(master, r, n);
  const iv = g.byte(), rots = [1 + g.byte() % 7, 1 + g.byte() % 7, 1 + g.byte() % 7];
  // v9: groups of 8. If the length is not a multiple of 8, a tail group covers the LAST 8 bytes, overlapping the group before it,
  // so no byte is ever left with too few partners. A message shorter than 8 bytes is a single short group with no exit shuffle.
  const bases = groupBases(n), cols = n >= LANES ? bases.length : 0, exits = new Uint8Array(cols * LANES);
  for (let c = 0; c < cols; c++) {              // key picks which way each stream leaves the crossing
    const p = [0, 1, 2, 3, 4, 5, 6, 7];
    for (let i = 7; i > 0; i--) { const lim = 256 - 256 % (i + 1); let v; do { v = g.byte(); } while (v >= lim); const k = v % (i + 1); const t = p[i]; p[i] = p[k]; p[k] = t; }
    exits.set(p, c * LANES);
  }
  // v9: the key shuffles every position directly (Fisher-Yates), so every order is equally likely and there are no ties
  const order = new Uint32Array(n); for (let i = 0; i < n; i++) order[i] = i;
  for (let i = n - 1; i > 0; i--) { const lim = 16777216 - 16777216 % (i + 1); let v; do { v = g.byte() * 65536 + g.byte() * 256 + g.byte(); } while (v >= lim);
    const k = v % (i + 1); const t = order[i]; order[i] = order[k]; order[k] = t; }
  const ks = new Uint8Array(n), kf = new Uint8Array(n), kb = new Uint8Array(n);
  if (!opts.noKeystream) { g.fill(ks); g.fill(kf); g.fill(kb); }
  return { iv, rots, ks, kf, kb, exits, cols, order, bases };
}
const FINAL = 255;                                // round number used for the closing key layer
function finalKey(master, n, opts) { const k = new Uint8Array(n); if (!opts.noKeystream) roundStream(master, FINAL, n).fill(k); return k; }
function checkRounds(rounds) { if (!Number.isInteger(rounds) || rounds < 1 || rounds > 8) throw new RangeError("rounds must be a whole number from 1 to 8"); }
/* The pinch: at the very centre every byte passes through alone. This is the AES S-box,
   the most studied nonlinear byte map there is, built here from its definition. */
const PINCH = new Uint8Array(256), UNPINCH = new Uint8Array(256);
(() => { let p = 1, q = 1;
  do { p = (p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0)) & 255;
    q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 255; if (q & 0x80) q ^= 0x09;
    PINCH[p] = (q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4) ^ 0x63) & 255;
  } while (p !== 1);
  PINCH[0] = 0x63; for (let i = 0; i < 256; i++) UNPINCH[PINCH[i]] = i; })();
/* The crossing: a three-stage butterfly that merges all eight streams of a column. */
function groupBases(n) { const b = []; if (n < LANES) { if (n > 0) b.push(0); return b; }
  for (let x = 0; x + LANES <= n; x += LANES) b.push(x); if (n % LANES) b.push(n - LANES); return b; }
function mergeColumn(c, base, m, rots) {
  for (let s = 0; s < 3; s++) { const span = 1 << s;
    for (let i = 0; i < LANES; i++) if (!(i & span)) { const j = i | span; if (j >= m) continue;
      let a = c[base + i], b = c[base + j]; a = (a + rotl8(b, rots[s])) & 255; b ^= rotl8(a, rots[s]); c[base + i] = a; c[base + j] = b; } }
}
function unmergeColumn(c, base, m, rots) {
  for (let s = 2; s >= 0; s--) { const span = 1 << s;
    for (let i = 0; i < LANES; i++) if (!(i & span)) { const j = i | span; if (j >= m) continue;
      let a = c[base + i], b = c[base + j]; b ^= rotl8(a, rots[s]); a = (a - rotl8(b, rots[s])) & 255; c[base + i] = a; c[base + j] = b; } }
}

const NONE = Object.freeze(Object.create(null));
const SWITCHES = ["noKeystream", "noPinch", "pinch", "unpinch", "stages"];
function testOpts(o) { const c = Object.create(null); if (o && typeof o === "object") for (const k of SWITCHES) if (Object.prototype.hasOwnProperty.call(o, k)) c[k] = o[k]; return c; }
/* The scrambler. master is a 32-byte scrambling key. Used by seal/open and by the raw test mode. */
function scramble(bytes, master, rounds, opts) {
  const n = bytes.length;
  let b = Uint8Array.from(bytes); const stages = opts.stages ? [b.slice()] : null;
  for (let r = 0; r < rounds; r++) {
    const P = roundParams(master, r, n, opts);
    // 1. key layer first (v8): every byte takes on a key byte before anything else, so no message passes through unchanged
    if (!opts.noKeystream) for (let j = 0; j < n; j++) b[j] = (b[j] + P.ks[j]) & 255;
    // 2. key shuffle: the key picks a fresh order for every position (v9; the golden-angle sort is gone)
    const perm = P.order;
    let c = new Uint8Array(n); for (let j = 0; j < n; j++) c[j] = b[perm[j]];
    // 3. cross at the centre: merge the streams of every column
    for (const base of P.bases) mergeColumn(c, base, Math.min(LANES, n), P.rots);
    // 4. the pinch: each byte squeezes through the centre point on its own
    if (!opts.noPinch) { const S = opts.pinch || PINCH; for (let j = 0; j < n; j++) c[j] = S[c[j]]; }
    // 5. key-picked exits: each stream leaves the crossing in a direction only the key knows
    const g8 = new Uint8Array(LANES);
    for (let col = 0; col < P.cols; col++) { const base = P.bases[col]; for (let l = 0; l < LANES; l++) g8[l] = c[base + P.exits[col * LANES + l]]; c.set(g8, base); }
    // 6 and 7. the chains. They spread a change through the whole message in one round. They hold no secret of their own.
    for (let j = 0; j < n; j++) c[j] ^= PINCH[(j > 0 ? c[j - 1] : P.iv) ^ P.kf[j]] ^ (j >= 8 ? c[j - 8] : 0);
    for (let j = n - 2; j >= 0; j--) c[j] ^= PINCH[c[j + 1] ^ P.kb[j]] ^ (j + 8 < n ? c[j + 8] : 0);
    b = c; if (stages) stages.push(b.slice());
  }
  // closing key layer (v8): without it anyone could undo the last chains
  const fk = finalKey(master, n, opts); for (let j = 0; j < n; j++) b[j] = (b[j] + fk[j]) & 255;
  return { out: b, stages };
}
function unscramble(bytes, master, rounds, opts) {
  const n = bytes.length;
  let b = Uint8Array.from(bytes);
  const fk = finalKey(master, n, opts); for (let j = 0; j < n; j++) b[j] = (b[j] - fk[j]) & 255;
  for (let r = rounds - 1; r >= 0; r--) {
    const P = roundParams(master, r, n, opts);
    const c = b.slice();
    for (let j = 0; j <= n - 2; j++) c[j] ^= PINCH[c[j + 1] ^ P.kb[j]] ^ (j + 8 < n ? c[j + 8] : 0);
    for (let j = n - 1; j >= 0; j--) c[j] ^= PINCH[(j > 0 ? c[j - 1] : P.iv) ^ P.kf[j]] ^ (j >= 8 ? c[j - 8] : 0);
    const d = c, g8 = new Uint8Array(LANES);
    for (let col = P.cols - 1; col >= 0; col--) { const base = P.bases[col]; for (let l = 0; l < LANES; l++) g8[P.exits[col * LANES + l]] = d[base + l]; d.set(g8, base); }
    if (!opts.noPinch) { const U = opts.unpinch || UNPINCH; for (let j = 0; j < n; j++) d[j] = U[d[j]]; }
    for (let gi = P.bases.length - 1; gi >= 0; gi--) unmergeColumn(d, P.bases[gi], Math.min(LANES, n), P.rots);
    const perm = P.order;
    const o = new Uint8Array(n); for (let j = 0; j < n; j++) o[perm[j]] = d[j];
    if (!opts.noKeystream) for (let j = 0; j < n; j++) o[j] = (o[j] - P.ks[j]) & 255;
    b = o;
  }
  return b;
}
/* Test mode: no stretching, no random start value, no fingerprint. For testing the scrambler only.
   The same key and message always give the same output. Never use it to protect anything, and never give it a real passphrase. */
function testKey(key) { const k = toBytes(key, "test key"); if (!k.length) throw new RangeError("test key must not be empty"); return root(sha256(cat(LABEL, k)), "raw"); }
function testScramble(bytes, key, rounds = 8, opts) { bytes = needBytes(bytes, "message"); checkRounds(rounds); return scramble(bytes, testKey(key), rounds, testOpts(opts)); }
function testUnscramble(bytes, key, rounds = 8, opts) { bytes = needBytes(bytes, "message"); checkRounds(rounds); return unscramble(bytes, testKey(key), rounds, testOpts(opts)); }
/* ---------- randomness tests (NIST SP 800-22 style subset) ---------- */
function erfc(x) { // Numerical Recipes erfc, ~1e-7
  const z = Math.abs(x), t = 1 / (1 + 0.5 * z);
  const r = t * Math.exp(-z * z - 1.26551223 + t * (1.00002368 + t * (0.37409196 + t * (0.09678418 + t * (-0.18628806 + t * (0.27886807 + t * (-1.13520398 + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))));
  return x >= 0 ? r : 2 - r;
}
function lgamma(x) { const c = [76.18009172947146, -86.50532032941677, 24.01409824083091, -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5];
  let y = x, tmp = x + 5.5; tmp -= (x + 0.5) * Math.log(tmp); let ser = 1.000000000190015; for (const v of c) ser += v / ++y; return -tmp + Math.log(2.5066282746310005 * ser / x); }
function igamc(a, x) { // upper regularised incomplete gamma Q(a,x)
  if (x <= 0) return 1;
  if (x < a + 1) { let sum = 1 / a, del = sum, ap = a; for (let n = 0; n < 500; n++) { ap++; del *= x / ap; sum += del; if (Math.abs(del) < Math.abs(sum) * 1e-14) break; }
    return 1 - sum * Math.exp(-x + a * Math.log(x) - lgamma(a)); }
  let b = x + 1 - a, c = 1e300, d = 1 / b, hh = d;
  for (let i = 1; i < 500; i++) { const an = -i * (i - a); b += 2; d = an * d + b; if (Math.abs(d) < 1e-300) d = 1e-300; c = b + an / c; if (Math.abs(c) < 1e-300) c = 1e-300; d = 1 / d; const del = d * c; hh *= del; if (Math.abs(del - 1) < 1e-14) break; }
  return Math.exp(-x + a * Math.log(x) - lgamma(a)) * hh;
}
function toBits(bytes) { const bits = new Uint8Array(bytes.length * 8); for (let i = 0; i < bytes.length; i++) for (let k = 0; k < 8; k++) bits[i * 8 + k] = (bytes[i] >> (7 - k)) & 1; return bits; }
function runTests(bytes) {
  const bits = toBits(bytes), n = bits.length; let ones = 0; for (const x of bits) ones += x;
  const out = [];
  // 1. frequency (monobit): about as many 1s as 0s
  const S = Math.abs(2 * ones - n);
  out.push({ name: "Frequency (monobit)", what: "about as many 1s as 0s", p: erfc(S / Math.sqrt(n) / Math.SQRT2) });
  // 2. block frequency, M = 128
  { const M = 128, N = Math.floor(n / M); let chi = 0;
    for (let i = 0; i < N; i++) { let s = 0; for (let k = 0; k < M; k++) s += bits[i * M + k]; const pi = s / M; chi += (pi - 0.5) ** 2; }
    chi *= 4 * M; out.push({ name: "Block frequency", what: "balanced inside every 128-bit block", p: igamc(N / 2, chi / 2) }); }
  // 3. runs
  { const pi = ones / n; let p = 0;
    if (Math.abs(pi - 0.5) < 2 / Math.sqrt(n)) { let V = 1; for (let i = 1; i < n; i++) if (bits[i] !== bits[i - 1]) V++;
      p = erfc(Math.abs(V - 2 * n * pi * (1 - pi)) / (2 * Math.sqrt(2 * n) * pi * (1 - pi))); }
    out.push({ name: "Runs", what: "streaks of 1s and 0s switch as often as chance", p }); }
  // 4. longest run of ones in 128-bit blocks
  { const M = 128, N = Math.floor(n / M), pis = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124], v = [0, 0, 0, 0, 0, 0];
    for (let i = 0; i < N; i++) { let best = 0, cur = 0; for (let k = 0; k < M; k++) { if (bits[i * M + k]) { cur++; if (cur > best) best = cur; } else cur = 0; }
      v[best <= 4 ? 0 : best >= 9 ? 5 : best - 4]++; }
    let chi = 0; for (let k = 0; k < 6; k++) chi += (v[k] - N * pis[k]) ** 2 / (N * pis[k]);
    out.push({ name: "Longest run of 1s", what: "no suspiciously long or short streaks", p: igamc(5 / 2, chi / 2) }); }
  // 5. byte distribution chi-square
  { const cnt = new Float64Array(256); for (const b of bytes) cnt[b]++; const e = bytes.length / 256; let chi = 0; for (const c of cnt) chi += (c - e) ** 2 / e;
    out.push({ name: "Byte spread", what: "all 256 byte values equally common", p: igamc(255 / 2, chi / 2) }); }
  for (const t of out) t.pass = t.p >= 0.01;
  return out;
}

/* ---------- AI attack: a small neural network tries to tell cipher output from random ---------- */
// Pairs of 16-byte messages differing in one bit, each under a fresh random key.
// Class 1: XOR of the two ciphertexts. Class 0: random bytes. If the net beats 50%, the rounds leak.
function makeData(N, rounds, rand, opts = {}) {
  const X = new Float32Array(N * 128), Y = new Float32Array(N), m = new Uint8Array(16), key = new Uint8Array(16);
  for (let i = 0; i < N; i++) {
    const y = rand() < 0.5 ? 1 : 0; Y[i] = y; let diff;
    if (y) { for (let k = 0; k < 16; k++) { m[k] = (rand() * 256) | 0; key[k] = (rand() * 256) | 0; }
      const a = testScramble(m, key, rounds, opts).out; const m2 = m.slice(); m2[0] ^= 1; const b = testScramble(m2, key, rounds, opts).out;
      diff = new Uint8Array(16); for (let k = 0; k < 16; k++) diff[k] = a[k] ^ b[k]; }
    else { diff = new Uint8Array(16); for (let k = 0; k < 16; k++) diff[k] = (rand() * 256) | 0; }
    for (let k = 0; k < 16; k++) for (let t = 0; t < 8; t++) X[i * 128 + k * 8 + t] = (diff[k] >> t) & 1;
  }
  return { X, Y, N };
}
function trainNet(train, test, rand, epochs = 6, H = 64) {
  const D = 128, lr = 0.003, B = 64;
  const W1 = new Float32Array(D * H).map(() => (rand() * 2 - 1) * Math.sqrt(6 / (D + H))), b1 = new Float32Array(H);
  const W2 = new Float32Array(H).map(() => (rand() * 2 - 1) * Math.sqrt(6 / (H + 1))); let b2 = 0;
  // Adam state
  const mW1 = new Float32Array(D * H), vW1 = new Float32Array(D * H), mb1 = new Float32Array(H), vb1 = new Float32Array(H), mW2 = new Float32Array(H), vW2 = new Float32Array(H); let mb2 = 0, vb2 = 0, t = 0;
  const h = new Float32Array(H), gW1 = new Float32Array(D * H), gb1 = new Float32Array(H), gW2 = new Float32Array(H);
  const idx = Array.from({ length: train.N }, (_, i) => i);
  for (let ep = 0; ep < epochs; ep++) {
    for (let i = idx.length - 1; i > 0; i--) { const k = Math.floor(rand() * (i + 1)); [idx[i], idx[k]] = [idx[k], idx[i]]; }
    for (let s = 0; s < idx.length; s += B) {
      gW1.fill(0); gb1.fill(0); gW2.fill(0); let gb2 = 0; const bs = Math.min(B, idx.length - s);
      for (let q = 0; q < bs; q++) { const i = idx[s + q], off = i * D;
        for (let j = 0; j < H; j++) { let z = b1[j]; for (let d = 0; d < D; d++) if (train.X[off + d]) z += W1[d * H + j]; h[j] = z > 0 ? z : 0; }
        let o = b2; for (let j = 0; j < H; j++) o += W2[j] * h[j]; const p = 1 / (1 + Math.exp(-o)), g = (p - train.Y[i]) / bs;
        gb2 += g; for (let j = 0; j < H; j++) { gW2[j] += g * h[j]; if (h[j] > 0) { const gj = g * W2[j]; gb1[j] += gj; for (let d = 0; d < D; d++) if (train.X[off + d]) gW1[d * H + j] += gj; } } }
      t++; const b1c = 1 - 0.9 ** t, b2c = 1 - 0.999 ** t;
      const adam = (w, m, v, g, k) => { m[k] = 0.9 * m[k] + 0.1 * g; v[k] = 0.999 * v[k] + 0.001 * g * g; w[k] -= lr * (m[k] / b1c) / (Math.sqrt(v[k] / b2c) + 1e-8); };
      for (let k = 0; k < D * H; k++) adam(W1, mW1, vW1, gW1[k], k);
      for (let k = 0; k < H; k++) { adam(b1, mb1, vb1, gb1[k], k); adam(W2, mW2, vW2, gW2[k], k); }
      mb2 = 0.9 * mb2 + 0.1 * gb2; vb2 = 0.999 * vb2 + 0.001 * gb2 * gb2; b2 -= lr * (mb2 / b1c) / (Math.sqrt(vb2 / b2c) + 1e-8);
    }
  }
  let correct = 0;
  for (let i = 0; i < test.N; i++) { const off = i * D; let o = b2;
    for (let j = 0; j < H; j++) { let z = b1[j]; for (let d = 0; d < D; d++) if (test.X[off + d]) z += W1[d * H + j]; if (z > 0) o += W2[j] * z; }
    if ((o > 0 ? 1 : 0) === test.Y[i]) correct++; }
  return correct / test.N;
}

/* ---------- key stretcher: scrypt (RFC 7914), so every passphrase guess costs time and memory ---------- */
function pbkdf2(pass, salt, iters, dkLen) {
  pass = toBytes(pass, "passphrase"); salt = toBytes(salt, "salt");
  const out = new Uint8Array(dkLen), blocks = Math.ceil(dkLen / 32), s = new Uint8Array(salt.length + 4); s.set(salt);
  for (let b = 1; b <= blocks; b++) { s[salt.length] = b >>> 24; s[salt.length + 1] = b >>> 16; s[salt.length + 2] = b >>> 8; s[salt.length + 3] = b;
    let u = hmac(pass, s); const t = u.slice();
    for (let i = 1; i < iters; i++) { u = hmac(pass, u); for (let k = 0; k < 32; k++) t[k] ^= u[k]; }
    out.set(t.subarray(0, Math.min(32, dkLen - (b - 1) * 32)), (b - 1) * 32); }
  return out;
}
const SX = new Uint32Array(16);
function salsa8(B, o) {
  const x = SX; for (let i = 0; i < 16; i++) x[i] = B[o + i];
  const R = (v, c) => (v << c) | (v >>> (32 - c));
  for (let i = 0; i < 4; i++) {
    x[4] ^= R(x[0] + x[12], 7); x[8] ^= R(x[4] + x[0], 9); x[12] ^= R(x[8] + x[4], 13); x[0] ^= R(x[12] + x[8], 18);
    x[9] ^= R(x[5] + x[1], 7); x[13] ^= R(x[9] + x[5], 9); x[1] ^= R(x[13] + x[9], 13); x[5] ^= R(x[1] + x[13], 18);
    x[14] ^= R(x[10] + x[6], 7); x[2] ^= R(x[14] + x[10], 9); x[6] ^= R(x[2] + x[14], 13); x[10] ^= R(x[6] + x[2], 18);
    x[3] ^= R(x[15] + x[11], 7); x[7] ^= R(x[3] + x[15], 9); x[11] ^= R(x[7] + x[3], 13); x[15] ^= R(x[11] + x[7], 18);
    x[1] ^= R(x[0] + x[3], 7); x[2] ^= R(x[1] + x[0], 9); x[3] ^= R(x[2] + x[1], 13); x[0] ^= R(x[3] + x[2], 18);
    x[6] ^= R(x[5] + x[4], 7); x[7] ^= R(x[6] + x[5], 9); x[4] ^= R(x[7] + x[6], 13); x[5] ^= R(x[4] + x[7], 18);
    x[11] ^= R(x[10] + x[9], 7); x[8] ^= R(x[11] + x[10], 9); x[9] ^= R(x[8] + x[11], 13); x[10] ^= R(x[9] + x[8], 18);
    x[12] ^= R(x[15] + x[14], 7); x[13] ^= R(x[12] + x[15], 9); x[14] ^= R(x[13] + x[12], 13); x[15] ^= R(x[14] + x[13], 18);
  }
  for (let i = 0; i < 16; i++) B[o + i] = (B[o + i] + x[i]) | 0;
}
function blockMix(X, Y, r) {
  const n = 32 * r, last = n - 16, T = Y.subarray(n, n + 16);
  for (let k = 0; k < 16; k++) T[k] = X[last + k];
  for (let i = 0; i < 2 * r; i++) { for (let k = 0; k < 16; k++) T[k] ^= X[i * 16 + k]; salsa8(T, 0);
    const dst = (i & 1 ? r + (i >> 1) : i >> 1) * 16; for (let k = 0; k < 16; k++) Y[dst + k] = T[k]; }
  for (let k = 0; k < n; k++) X[k] = Y[k];
}
function scrypt(pass, salt, N, r, p, dkLen) {
  pass = toBytes(pass, "passphrase"); salt = toBytes(salt, "salt");
  const n = 32 * r, B = pbkdf2(pass, salt, 1, p * 128 * r), X = new Uint32Array(n), Y = new Uint32Array(n + 16), Vm = new Uint32Array(N * n);
  for (let i = 0; i < p; i++) { const off = i * 128 * r;
    for (let k = 0; k < n; k++) X[k] = B[off + 4 * k] | (B[off + 4 * k + 1] << 8) | (B[off + 4 * k + 2] << 16) | (B[off + 4 * k + 3] << 24);
    for (let j = 0; j < N; j++) { Vm.set(X, j * n); blockMix(X, Y, r); }
    for (let j = 0; j < N; j++) { const q = (X[n - 16] & (N - 1)) * n; for (let k = 0; k < n; k++) X[k] ^= Vm[q + k]; blockMix(X, Y, r); }
    for (let k = 0; k < n; k++) { const v = X[k]; B[off + 4 * k] = v; B[off + 4 * k + 1] = v >>> 8; B[off + 4 * k + 2] = v >>> 16; B[off + 4 * k + 3] = v >>> 24; } }
  return pbkdf2(pass, B, 1, dkLen);
}
const STRETCH = Object.freeze({ N: 32768, r: 8, p: 3 });                 // an OWASP-listed setting: 32 MB of memory, three passes
const MAX_MESSAGE = 4 * 1024 * 1024;                      // seal and open refuse anything larger than 4 MB (about 17 seconds of work)
/* The random source is picked once, when this file loads: Node's own crypto if this is Node, else the browser's. */
const RNG = (() => { try { if (typeof module !== "undefined" && module.exports && typeof require === "function") { const w = require("crypto").webcrypto; return w.getRandomValues.bind(w); } } catch (e) {}
  const c = (typeof globalThis !== "undefined" ? globalThis : globalObj).crypto; return c && typeof c.getRandomValues === "function" ? c.getRandomValues.bind(c) : null; })();
function randomBytes(n) { if (!RNG) throw new Error("no secure random source available"); const a = new Uint8Array(n); RNG(a);
  let any = 0; for (let i = 0; i < n; i++) any |= a[i]; if (!any) throw new Error("the random source returned all zeros"); return a; }
function scryptBase(pass, salt) { return scrypt(pass, cat(LABEL, salt), STRETCH.N, STRETCH.r, STRETCH.p, 32); }
/* A stretched key: slow to make on purpose. It is tied to its salt, and the two always travel together.
   passphrase is text or bytes and must not be empty. salt is 16 random bytes, made here unless one is given. */
const HANDLES = new WeakMap();
function stretchKey(passphrase, salt) {
  const pass = toBytes(passphrase, "passphrase"); if (!pass.length) throw new RangeError("passphrase must not be empty");
  salt = salt === undefined ? randomBytes(16) : needBytes(salt, "salt", 16);
  const handle = Object.freeze({ salt: salt.slice() }); HANDLES.set(handle, { salt, base: scryptBase(pass, salt) });   // the base key itself is not on the object
  return handle;
}
function keyFor(keyOrPass, salt) {      // returns the private {salt, base}, stretching if a passphrase was given
  const h = HANDLES.get(keyOrPass); if (h) return h;
  if (typeof keyOrPass === "string" || isBytes(keyOrPass)) return HANDLES.get(stretchKey(keyOrPass, salt));
  throw new TypeError("key must be a passphrase or a stretched key from stretchKey()");
}
const sameBytes = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; };
function messageRoots(base, nonce) {
  const mk = root(base, cat("msg|", nonce));
  return { scramble: root(mk, "scramble"), fingerprint: root(mk, "fingerprint") };
}
/* sealed = version (1 byte, 0x09) | salt (16) | random start value (16) | scrambled message | fingerprint (16).
   Always 8 rounds. The salt and the start value are made here; the caller cannot choose them. Returns the sealed bytes. */
function sealParts(message, keyOrPass, nonce, stages) {
  message = needBytes(message, "message"); if (message.length > MAX_MESSAGE) throw new RangeError("message is larger than 4 MB");
  const K = keyFor(keyOrPass), R = messageRoots(K.base, nonce), head = cat(new Uint8Array([VERSION]), K.salt, nonce);
  const o = Object.create(null); o.stages = stages;
  const r = scramble(message, R.scramble, 8, o);
  const tag = hmac(R.fingerprint, cat(head, r.out)).slice(0, 16);
  return { sealed: cat(head, r.out, tag), body: r.out, tag, stages: r.stages };
}
function seal(message, keyOrPass) { return sealParts(message, keyOrPass, randomBytes(16), false).sealed; }
/* For tests and the demo page only: a chosen start value, and the inner parts returned. Reusing a start value is unsafe. */
function sealForTest(message, keyOrPass, nonce) { return sealParts(message, keyOrPass, needBytes(nonce, "start value", 16), true); }
function open(sealed, keyOrPass) {
  sealed = needBytes(sealed, "sealed message");       // one private copy; everything below reads only this
  if (sealed.length < 49) return { ok: false, why: "too short" };
  if (sealed[0] !== VERSION) return { ok: false, why: "not a version 9 sealed message" };
  if (sealed.length - 49 > MAX_MESSAGE) return { ok: false, why: "too large" };
  const salt = sealed.slice(1, 17), nonce = sealed.slice(17, 33), body = sealed.slice(33, sealed.length - 16), tag = sealed.slice(sealed.length - 16);
  const given = HANDLES.get(keyOrPass);
  if (given && !sameBytes(given.salt, salt)) return { ok: false, why: "this stretched key was made for a different salt" };
  const K = given || keyFor(keyOrPass, salt), R = messageRoots(K.base, nonce);
  const want = hmac(R.fingerprint, sealed.subarray(0, sealed.length - 16)); let diff = 0; for (let i = 0; i < 16; i++) diff |= want[i] ^ tag[i];
  if (diff) return { ok: false, why: "fingerprint mismatch" };
  return { ok: true, bytes: unscramble(body, R.scramble, 8, NONE) };
}
/* Side roots: fresh keys for other jobs, grown from a stretched key. name is text. */
function branchOf(stretched, name) {
  const K = HANDLES.get(stretched); if (!K) throw new TypeError("branchOf needs a stretched key from stretchKey()");
  if (typeof name !== "string" || !name.length) throw new TypeError("branch name must be non-empty text");
  return root(K.base, cat("branch|", name));
}

const posInt = (v, what) => { if (!Number.isInteger(v) || v < 1) throw new RangeError(what + " must be a whole number of 1 or more"); };
const api = { get PINCH() { return PINCH.slice(); }, VERSION, MAX_MESSAGE, testScramble, testUnscramble, seal, sealForTest, open, stretchKey, branchOf, STRETCH,
  sha256: m => sha256(toBytes(m, "message")), hmac,
  scrypt: (pass, salt, N, r, p, dkLen) => { posInt(N, "N"); if (N < 2 || (N & (N - 1))) throw new RangeError("N must be a power of 2"); posInt(r, "r"); posInt(p, "p"); posInt(dkLen, "output length"); return scrypt(pass, salt, N, r, p, dkLen); },
  pbkdf2: (pass, salt, iters, dkLen) => { posInt(iters, "iterations"); posInt(dkLen, "output length"); return pbkdf2(pass, salt, iters, dkLen); },
  runTests, makeData, trainNet, mulberry32, LANES };
if (typeof module !== "undefined" && module.exports) module.exports = api; else globalObj.Vortex = api;
})(typeof self !== "undefined" ? self : this);
