// Writes fresh random test vectors from vortex.js, for reference/cross_check.py to compare against the Python implementation.
// Run: node test/make-vectors.js test/vectors.json
const V = require('../vortex.js'), c = require('crypto'), fs = require('fs');
const hex = b => Buffer.from(b).toString('hex'), out = [];
const lens = [0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 21, 24, 25, 31, 32, 33, 63, 64, 65, 100, 255, 256, 257, 1000, 4096, 65536, 70000, 200000];
for (const n of lens) for (let t = 0; t < (n > 5000 ? 2 : 8); t++) {
  const key = (t % 4 == 3 ? 'café-ключ-' : 'k') + c.randomBytes(6).toString('hex'), m = c.randomBytes(n);
  for (const R of (n > 5000 ? [8] : [1, 2, 8])) out.push({ key, R, m: hex(m), c: hex(V.testScramble(new Uint8Array(m), key, R).out) });
}
for (let t = 0; t < 6; t++) {
  const key = 'pass ' + t, m = c.randomBytes(t * 13), salt = c.randomBytes(16), nonce = c.randomBytes(16);
  const s = V.sealForTest(new Uint8Array(m), V.stretchKey(key, new Uint8Array(salt)), new Uint8Array(nonce)).sealed;
  out.push({ seal: 1, key, m: hex(m), salt: hex(salt), nonce: hex(nonce), c: hex(s) });
}
fs.writeFileSync(process.argv[2] || 'vectors.json', JSON.stringify(out)); console.log(out.length + ' vectors written');
