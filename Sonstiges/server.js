'use strict';

/**
 * Hash Length Extension CTF Demo
 *
 * Vulnerability on purpose:
 *   sig = MD5(secret || data)
 *
 * The server accepts data as HEX so binary MD5 padding can safely travel in a URL.
 * Students need to create a new data_hex + sig pair where data contains "role=admin".
 */

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);

// 16 bytes. In a real exercise, do not show this file to students.
// You may override it: SECRET='some-secret-value' npm start
const SECRET = Buffer.from(process.env.SECRET || 'YELLOW_SUBMARINE', 'utf8');
const FLAG = process.env.FLAG || 'FLAG{length_extension_is_not_hmac}';

const ORIGINAL_DATA = Buffer.from('user=student&role=user', 'utf8');

function md5SecretPrefixMac(dataBuffer) {
  return crypto
    .createHash('md5')
    .update(Buffer.concat([SECRET, dataBuffer]))
    .digest('hex');
}

function isHex(s) {
  return typeof s === 'string' && s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

function htmlEscape(s) {
  return String(s).replace(/[&<>'"]/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[c]));
}

function send(res, status, body, contentType = 'text/html; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': contentType });
  res.end(body);
}

function page() {
  const dataHex = ORIGINAL_DATA.toString('hex');
  const sig = md5SecretPrefixMac(ORIGINAL_DATA);

  return `<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Hash Length Extension CTF</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 980px; margin: 40px auto; line-height: 1.45; }
    code, pre { background: #f4f4f4; padding: 2px 5px; border-radius: 4px; }
    pre { padding: 14px; overflow-x: auto; }
    .box { border: 1px solid #ddd; padding: 16px; border-radius: 10px; margin: 18px 0; }
    .bad { border-color: #d77; background: #fff5f5; }
    .ok { border-color: #7b7; background: #f4fff4; }
  </style>
</head>
<body>
  <h1>Hash Length Extension CTF</h1>

  <div class="box bad">
    <b>Verwundbares Design:</b>
    <pre>sig = MD5(secret || data)</pre>
    <p>Deine Aufgabe: Erzeuge ein gültiges Token, bei dem <code>data</code> zusätzlich <code>role=admin</code> enthält.</p>
  </div>

  <h2>Startwerte</h2>
  <pre>data_ascii = ${ORIGINAL_DATA.toString('utf8')}
data_hex   = ${dataHex}
sig        = ${sig}</pre>

  <h2>Prüfung</h2>
  <p>Rufe die Challenge so auf:</p>
  <pre>http://${HOST}:${PORT}/check?data=${dataHex}&sig=${sig}</pre>

  <p>Die Serverprüfung ist absichtlich falsch:</p>
  <pre>MD5(secret || data_from_request) == sig_from_request</pre>

  <h2>Hinweise</h2>
  <ul>
    <li><code>data</code> wird als Hex übertragen, damit MD5-Paddingbytes wie <code>80 00 00 ...</code> im URL funktionieren.</li>
    <li>Nutze ein Open-Source-Tool wie <code>hash_extender</code>.</li>
    <li>Du musst die Länge von <code>secret</code> erraten.</li>
  </ul>
</body>
</html>`;
}

function check(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const dataHex = url.searchParams.get('data');
  const sig = (url.searchParams.get('sig') || '').toLowerCase();

  if (!isHex(dataHex) || !/^[0-9a-f]{32}$/.test(sig)) {
    return send(res, 400, `<h1>Bad Request</h1><p>Use: <code>/check?data=&lt;hex&gt;&sig=&lt;md5&gt;</code></p>`);
  }

  const data = Buffer.from(dataHex, 'hex');
  const expected = md5SecretPrefixMac(data);
  const valid = crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));

  // latin1 preserves bytes 0x00-0xff one-to-one for display/search.
  const visibleData = data.toString('latin1');
  const containsAdmin = visibleData.includes('role=admin');

  if (valid && containsAdmin) {
    return send(res, 200, `
      <h1>✅ Token gültig</h1>
      <div class="box ok"><b>Flag:</b> <code>${htmlEscape(FLAG)}</code></div>
      <h2>Empfangene Daten</h2>
      <pre>${htmlEscape(visibleData)}</pre>
      <h2>MD5(secret || data)</h2>
      <pre>${expected}</pre>
    `);
  }

  return send(res, 403, `
    <h1>❌ Kein Zugriff</h1>
    <p>Signatur gültig: <b>${valid}</b></p>
    <p>Enthält <code>role=admin</code>: <b>${containsAdmin}</b></p>
    <h2>Empfangene Daten</h2>
    <pre>${htmlEscape(visibleData)}</pre>
    <h2>Erwartete Signatur für diese Daten</h2>
    <pre>${expected}</pre>
  `);
}

const server = http.createServer((req, res) => {
  const path = req.url.split('?')[0];
  if (path === '/' || path === '/start') return send(res, 200, page());
  if (path === '/check') return check(req, res);
  return send(res, 404, '<h1>404</h1><p>Try <a href="/start">/start</a></p>');
});

server.listen(PORT, HOST, () => {
  console.log(`Hash Length Extension CTF running at http://${HOST}:${PORT}/start`);
  console.log(`Instructor note: SECRET length is ${SECRET.length} bytes.`);
});
