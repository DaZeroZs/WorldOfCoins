'use strict';

// Educational CTF demo: ECDSA nonce reuse on secp256k1.
// DO NOT copy this signing logic into real systems.
// The bug is intentional: the same ECDSA nonce k is reused for two different messages.

const crypto = require('crypto');
const express = require('express');
const { ec: EC } = require('elliptic');

const ec = new EC('secp256k1');
const app = express();
const PORT = process.env.PORT || 3000;

// Curve order n for secp256k1.
const n = BigInt('0x' + ec.curve.n.toString(16));

// Fixed private key d. Students do NOT see this directly.
// This is intentionally static so the instructor solution is reproducible.
const PRIVATE_KEY_HEX = '1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd';
const d = BigInt('0x' + PRIVATE_KEY_HEX);

// Intentional vulnerability: same k reused for both signatures on /start.
const BAD_K_HEX = '0000000000000000000000000000000000000000000000000000000000001337';
const badK = BigInt('0x' + BAD_K_HEX);

const FLAG = 'FLAG{never_reuse_ecdsa_nonce_k}';
const ADMIN_MESSAGE = 'role=admin&action=get_flag';
const msg1 = 'transfer=10&to=bob';
const msg2 = 'transfer=20&to=alice';

function mod(a, m = n) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function egcd(a, b) {
  let oldR = a, r = b;
  let oldS = 1n, s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return [oldR, oldS];
}

function invMod(a, m = n) {
  const [g, x] = egcd(mod(a, m), m);
  if (g !== 1n) throw new Error('No modular inverse');
  return mod(x, m);
}

function sha256Hex(message) {
  return crypto.createHash('sha256').update(message, 'utf8').digest('hex');
}

function zFromMessage(message) {
  return BigInt('0x' + sha256Hex(message)) % n;
}

function to64Hex(x) {
  return mod(x).toString(16).padStart(64, '0');
}

function pointXFromK(k) {
  const P = ec.g.mul(k.toString(16));
  return BigInt('0x' + P.getX().toString(16));
}

function signWithK(message, priv, k) {
  const z = zFromMessage(message);
  const r = mod(pointXFromK(k));
  const s = mod(invMod(k) * (z + r * priv));
  if (r === 0n || s === 0n) throw new Error('Invalid signature parameters');
  return { message, z: to64Hex(z), r: to64Hex(r), s: to64Hex(s) };
}

function verifySignature(message, rHex, sHex) {
  try {
    const publicKey = ec.keyFromPrivate(PRIVATE_KEY_HEX, 'hex').getPublic('hex');
    const key = ec.keyFromPublic(publicKey, 'hex');
    const hashHex = sha256Hex(message);
    return ec.verify(hashHex, { r: rHex, s: sHex }, key);
  } catch (e) {
    return false;
  }
}

function publicInfo() {
  const key = ec.keyFromPrivate(PRIVATE_KEY_HEX, 'hex');
  const publicKeyCompressed = key.getPublic(true, 'hex');
  const publicKeyUncompressed = key.getPublic(false, 'hex');
  const sig1 = signWithK(msg1, d, badK);
  const sig2 = signWithK(msg2, d, badK);
  return {
    challenge: 'ECDSA nonce reuse on secp256k1',
    curve: 'secp256k1',
    hash: 'SHA-256(message), interpreted as integer z mod n',
    publicKeyCompressed,
    publicKeyUncompressed,
    curveOrderN: n.toString(16),
    adminMessageToSign: ADMIN_MESSAGE,
    signature1: sig1,
    signature2: sig2,
    hint: 'Notice that signature1.r == signature2.r. That usually means the same nonce k was reused.'
  };
}

app.get('/', (req, res) => {
  res.type('html').send(`
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>ECDSA k-Reuse CTF</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 980px; margin: 40px auto; line-height: 1.45; }
    code, pre { background: #f4f4f4; padding: 2px 4px; border-radius: 4px; }
    pre { padding: 16px; overflow-x: auto; }
    .warn { background: #fff3cd; border: 1px solid #ffe69c; padding: 12px; border-radius: 8px; }
  </style>
</head>
<body>
  <h1>ECDSA k-Reuse Demo</h1>
  <p class="warn"><b>Training:</b> Dieser Server ist absichtlich verwundbar. Er verwendet dieselbe ECDSA-Nonce <code>k</code> für zwei verschiedene Signaturen.</p>
  <h2>Ziel</h2>
  <p>Rekonstruiere den privaten Schlüssel aus den zwei Signaturen und signiere dann:</p>
  <pre>${ADMIN_MESSAGE}</pre>
  <p>Challenge-Daten als JSON:</p>
  <pre><a href="/start">/start</a></pre>
  <p>Flag-Endpoint:</p>
  <pre>/claim?message=${encodeURIComponent(ADMIN_MESSAGE)}&r=&lt;r_hex&gt;&s=&lt;s_hex&gt;</pre>
</body>
</html>`);
});

app.get('/start', (req, res) => {
  res.json(publicInfo());
});

app.get('/claim', (req, res) => {
  const message = String(req.query.message || '');
  const r = String(req.query.r || '').toLowerCase();
  const s = String(req.query.s || '').toLowerCase();

  if (message !== ADMIN_MESSAGE) {
    return res.status(400).json({ ok: false, error: `You must sign exactly: ${ADMIN_MESSAGE}` });
  }
  if (!/^[0-9a-f]{1,64}$/.test(r) || !/^[0-9a-f]{1,64}$/.test(s)) {
    return res.status(400).json({ ok: false, error: 'r and s must be hex integers.' });
  }

  const ok = verifySignature(message, r.padStart(64, '0'), s.padStart(64, '0'));
  if (!ok) {
    return res.status(403).json({ ok: false, error: 'Invalid ECDSA signature.' });
  }

  res.json({ ok: true, flag: FLAG });
});

app.listen(PORT, () => {
  console.log(`ECDSA k-reuse CTF running on http://127.0.0.1:${PORT}`);
  console.log(`Open http://127.0.0.1:${PORT}/start`);
});
