// Checks vortex.js against the reference outputs in SPEC.md. Run: node test/check.js
const V=require('../vortex.js'),crypto=require('crypto');const hex=b=>Buffer.from(b).toString('hex'),te=new TextEncoder();
const K='golden-spiral',salt=Uint8Array.from({length:16},(_,i)=>0xA0+i),nonce=Uint8Array.from({length:16},(_,i)=>i);
const base=V.scrypt(K,Buffer.concat([Buffer.from('vortex-v9|'),salt]),32768,8,3,32),H=V.stretchKey(K,salt);
const long=Uint8Array.from({length:70000},(_,i)=>(i*7+3)%256);
const o={ "stretched base":hex(base), "seal 'Vortex'":hex(V.sealForTest(te.encode('Vortex'),H,nonce).sealed), "seal empty message":hex(V.sealForTest(new Uint8Array(0),H,nonce).sealed), "branch 'phone'":hex(V.branchOf(H,'phone')),
 "raw, 16 zero bytes, 8 rounds":hex(V.testScramble(new Uint8Array(16),K).out), "raw, bytes 0..20 (21 bytes), 8 rounds":hex(V.testScramble(Uint8Array.from({length:21},(_,i)=>i),K).out),
 "raw, bytes 0..39 (40 bytes), 1 round":hex(V.testScramble(Uint8Array.from({length:40},(_,i)=>i),K,1).out), "raw unscramble of 16 zero bytes, 8 rounds":hex(V.testUnscramble(new Uint8Array(16),K)),
 "raw, 70,000 bytes (i*7+3 mod 256), 8 rounds, SHA-256 of output":crypto.createHash('sha256').update(V.testScramble(long,K).out).digest('hex'),
 "raw, the 1 byte 41, 8 rounds":hex(V.testScramble(Uint8Array.from([0x41]),K).out),
 "raw, 16 zero bytes, 8 rounds, key 'caf\u00e9' (composed)":hex(V.testScramble(new Uint8Array(16),'caf\u00e9').out),
 "raw, 16 zero bytes, 8 rounds, key 'cafe\u0301' (decomposed)":hex(V.testScramble(new Uint8Array(16),'cafe\u0301').out),
 "seal bytes 0..20 (21 bytes)":hex(V.sealForTest(Uint8Array.from({length:21},(_,i)=>i),H,nonce).sealed),
 "raw, bytes 0..8 (9 bytes), 8 rounds":hex(V.testScramble(Uint8Array.from({length:9},(_,i)=>i),K).out),
 "raw, bytes 0..6 (7 bytes), 8 rounds":hex(V.testScramble(Uint8Array.from({length:7},(_,i)=>i),K).out),
 "raw, bytes 0..8 (9 bytes), 1 round":hex(V.testScramble(Uint8Array.from({length:9},(_,i)=>i),K,1).out),
 "raw unscramble of bytes 0..20 (21 bytes), 8 rounds":hex(V.testUnscramble(Uint8Array.from({length:21},(_,i)=>i),K)),
 "raw unscramble of bytes 0..8 (9 bytes), 1 round":hex(V.testUnscramble(Uint8Array.from({length:9},(_,i)=>i),K,1))};
const want=require("./reference-outputs.json");let bad=0;for(const k of Object.keys(want)){const ok=o[k]===want[k];if(!ok)bad++;console.log((ok?"MATCH   ":"DIFFERS ")+k);}console.log(bad?bad+" differ":"All "+Object.keys(want).length+" reference outputs match.");process.exit(bad?1:0);
