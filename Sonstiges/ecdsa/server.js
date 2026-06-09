'use strict';

// ECDSA k-reuse CTF demo - NO npm dependencies, built-in Node.js only.
// Deliberately vulnerable: the same nonce k is reused for two signatures.
// Curve: secp256k1.

const http = require('http');
const url = require('url');
const crypto = require('crypto');

const HOST = '127.0.0.1';
const PORT = 3000;
const FLAG = 'FLAG{never_reuse_ecdsa_nonce_k}';

// secp256k1 parameters
const P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const G = { x: Gx, y: Gy };

// Fixed private key and intentionally reused nonce k.
// In a real system k MUST be unique/unpredictable or generated deterministically per RFC6979.
const d = 0x1E99423A4ED27608A15A2616D7D6748A15F0B925D7A5C3D3F2B719EB8B820F01n;
const reusedK = 0xBADF00D123456789ABCDEFFEDCBA9876543210ABCDEF1234567890ABCDEFn % N;

const msg1 = 'transfer=10&to=bob';
const msg2 = 'transfer=20&to=alice';
const adminMessage = 'role=admin';

function mod(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function invMod(a, m) {
  a = mod(a, m);
  if (a === 0n) throw new Error('inverse does not exist');
  let lm = 1n, hm = 0n;
  let low = a, high = m;
  while (low > 1n) {
    const r = high / low;
    let nm = hm - lm * r;
    let nw = high - low * r;
    hm = lm; high = low; lm = nm; low = nw;
  }
  return mod(lm, m);
}

function pointAdd(p, q) {
  if (p === null) return q;
  if (q === null) return p;
  if (p.x === q.x && mod(p.y + q.y, P) === 0n) return null;

  let lambda;
  if (p.x === q.x && p.y === q.y) {
    lambda = mod((3n * p.x * p.x) * invMod(2n * p.y, P), P);
  } else {
    lambda = mod((q.y - p.y) * invMod(q.x - p.x, P), P);
  }
  const rx = mod(lambda * lambda - p.x - q.x, P);
  const ry = mod(lambda * (p.x - rx) - p.y, P);
  return { x: rx, y: ry };
}

function scalarMult(k, point) {
  k = mod(k, N);
  let result = null;
  let addend = point;
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

function sha256Int(message) {
  return BigInt('0x' + crypto.createHash('sha256').update(message, 'utf8').digest('hex')) % N;
}

function hex(n) {
  return n.toString(16).padStart(64, '0');
}

function parseHex(s) {
  if (!/^[0-9a-fA-F]+$/.test(s || '')) throw new Error('invalid hex');
  return BigInt('0x' + s);
}

function signWithK(message, priv, k) {
  const z = sha256Int(message);
  const R = scalarMult(k, G);
  const r = mod(R.x, N);
  const s = mod(invMod(k, N) * (z + r * priv), N);
  return { r, s, z };
}

function verify(message, sig, pub) {
  const r = sig.r, s = sig.s;
  if (r <= 0n || r >= N || s <= 0n || s >= N) return false;
  const z = sha256Int(message);
  const w = invMod(s, N);
  const u1 = mod(z * w, N);
  const u2 = mod(r * w, N);
  const X = pointAdd(scalarMult(u1, G), scalarMult(u2, pub));
  if (X === null) return false;
  return mod(X.x, N) === r;
}

const pub = scalarMult(d, G);
const sig1 = signWithK(msg1, d, reusedK);
const sig2 = signWithK(msg2, d, reusedK);

function sendJson(res, obj, status = 200) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function startPayload() {
  return {
    challenge: 'ECDSA nonce reuse on secp256k1',
    goal: `Recover the private key from the two signatures, then sign exactly: ${adminMessage}`,
    curve: 'secp256k1',
    n: hex(N),
    publicKey: { x: hex(pub.x), y: hex(pub.y) },
    signature1: { message: msg1, z: hex(sig1.z), r: hex(sig1.r), s: hex(sig1.s) },
    signature2: { message: msg2, z: hex(sig2.z), r: hex(sig2.r), s: hex(sig2.s) },
    hint: 'r is identical in both signatures. That means the same ECDSA nonce k was reused.',
    claim: '/claim?message=role%3Dadmin&r=<hex>&s=<hex>'
  };
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  if (parsed.pathname === '/' || parsed.pathname === '/start') {
    return sendJson(res, startPayload());
  }

  if (parsed.pathname === '/claim') {
    try {
      const message = parsed.query.message || '';
      const r = parseHex(parsed.query.r);
      const s = parseHex(parsed.query.s);
      if (message !== adminMessage) {
        return sendJson(res, { ok: false, error: `message must be exactly '${adminMessage}'` }, 400);
      }
      const ok = verify(message, { r, s }, pub);
      if (!ok) return sendJson(res, { ok: false, error: 'invalid signature' }, 403);
      return sendJson(res, { ok: true, flag: FLAG });
    } catch (e) {
      return sendJson(res, { ok: false, error: e.message }, 400);
    }
  }

  sendJson(res, { error: 'not found', endpoints: ['/start', '/claim?message=role%3Dadmin&r=<hex>&s=<hex>'] }, 404);
});

server.listen(PORT, HOST, () => {
  console.log(`ECDSA k-reuse demo running at http://${HOST}:${PORT}/start`);
});
