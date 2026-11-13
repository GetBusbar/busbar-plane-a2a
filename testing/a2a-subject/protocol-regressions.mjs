// Regression controls against the actual signing proxy and TCP binding shim.
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import http2 from 'node:http2';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const directory = fileURLToPath(new URL('.', import.meta.url));
const children = [];
const temporary = await mkdtemp(join(tmpdir(), 'a2a-protocol-'));
const received = [];
const backend = http.createServer((req, res) => {
  received.push(req.headers);
  res.setHeader('content-type', 'application/json');
  // U+FF61 sorts before U+10000 by code point and UTF-8 bytes, but after it by UTF-16 code units
  // (U+10000 is the surrogate pair D800 DC00): only these keys tell RFC 8785's order apart.
  res.end(JSON.stringify({ name: 'probe', '\uFF61': 1, '\u{10000}': 2 }));
});
async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}
async function unusedPort() {
  const server = net.createServer();
  const port = await listen(server);
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function httpStatus(url, headers) {
  return new Promise((resolve, reject) => {
    const request = http.request(url, { headers }, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode));
    });
    request.once('error', reject);
    request.setTimeout(3000, () => request.destroy(new Error('HTTP probe timed out')));
    request.end();
  });
}
// A raw HTTP/1.1 request line, so absolute-form and other non-origin-form targets reach the wire
// exactly as written (http.request and fetch normalize them).
async function rawStatus(port, requestTarget) {
  const socket = net.connect(port, '127.0.0.1');
  try {
    return await new Promise((resolve, reject) => {
      let text = '';
      socket.setEncoding('latin1');
      socket.on('error', reject);
      socket.setTimeout(3000, () => reject(new Error('raw HTTP probe timed out')));
      socket.on('data', chunk => {
        text += chunk;
        const status = /^HTTP\/1\.1 (\d{3}) /.exec(text);
        if (status) resolve(Number(status[1]));
      });
      socket.write(`GET ${requestTarget} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
    });
  } finally {
    socket.destroy();
  }
}
async function start(script, port, ...args) {
  const credential = script === 'binding-shim.mjs' ? args.pop() : null;
  if (credential !== null) args.push('-');
  const child = spawn(process.execPath, [join(directory, script), String(port), ...args.map(String)],
                      { stdio: [credential === null ? 'ignore' : 'pipe', 'ignore', 'inherit'] });
  if (credential !== null) child.stdin.end(credential);
  children.push(child);
  for (let attempt = 0; attempt < 100; attempt++) {
    if (child.exitCode !== null) throw new Error(`${script} exited ${child.exitCode}`);
    const connected = await new Promise(resolve => {
      const socket = net.connect(port, '127.0.0.1');
      socket.once('error', () => { socket.destroy(); resolve(false); });
      socket.once('connect', () => { socket.destroy(); resolve(true); });
    });
    if (connected) return;
    await delay(20);
  }
  throw new Error(`${script} did not listen`);
}
async function fragmentedPreface(port, firstLength) {
  const socket = net.connect(port, '127.0.0.1');
  try {
    const response = new Promise((resolve, reject) => {
      let received = Buffer.alloc(0);
      socket.on('error', reject);
      socket.setTimeout(3000, () => reject(new Error('no HTTP/2 SETTINGS response')));
      socket.on('data', bytes => {
        received = Buffer.concat([received, bytes]);
        if (received.length >= 9) resolve(received);
      });
    });
    const preface = Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
    socket.write(preface.subarray(0, firstLength));
    await delay(30); // Separate TCP writes; classification must wait for the full prefix.
    socket.write(Buffer.concat([preface.subarray(firstLength), Buffer.from([0,0,0,4,0,0,0,0,0])]));
    const bytes = await response;
    assert.equal(bytes[3], 4, 'first response must be an HTTP/2 SETTINGS frame, not HTTP/1');
    assert.equal(bytes.readUInt32BE(5), 0, 'SETTINGS uses stream zero');
  } finally {
    socket.destroy();
  }
}
try {
  const backendPort = await listen(backend);
  const vendorPort = await unusedPort();
  const keyFile = join(temporary, 'issuer.spki');
  await start('signing-vendor.mjs', vendorPort, backendPort, keyFile);
  const response = await fetch(`http://127.0.0.1:${vendorPort}/.well-known/agent-card.json`);
  assert.equal(response.status, 200);
  const signed = await response.json();
  const signature = signed.signatures[0];
  const payload = Buffer.from('{"name":"probe","\u{10000}":2,"\uFF61":1}').toString('base64url');
  const publicKey = crypto.createPublicKey({ key: Buffer.from(await readFile(keyFile, 'utf8'), 'base64'),
                                            format: 'der', type: 'spki' });
  assert(crypto.verify(null, Buffer.from(`${signature.protected}.${payload}`), publicKey,
                       Buffer.from(signature.signature, 'base64url')), 'signature must use UTF-16 key order');
  // The vendor is a reverse proxy to one origin: a request target that names another host must be
  // refused before any upstream connection, never forwarded (an open forward proxy is SSRF).
  let elsewhereHits = 0;
  const elsewhere = http.createServer((request, response) => {
    elsewhereHits++;
    response.writeHead(204);
    response.end();
  });
  try {
    const elsewherePort = await listen(elsewhere);
    const beforeTargets = received.length;
    for (const requestTarget of [
      `http://127.0.0.1:${elsewherePort}/.well-known/agent-card.json`,
      `http://127.0.0.1:${elsewherePort}/probe`,
      `//127.0.0.1:${elsewherePort}/probe`,
      `/\\127.0.0.1:${elsewherePort}/probe`,
    ]) {
      assert.equal(await rawStatus(vendorPort, requestTarget), 400, `vendor must refuse ${requestTarget}`);
    }
    assert.equal(elsewhereHits, 0, 'a refused request target must never reach another origin');
    assert.equal(received.length, beforeTargets, 'a refused request target must never reach the backend');
    assert.equal(await rawStatus(vendorPort, '/probe?x=1'), 200, 'origin-form targets still proxy');
    assert.equal(received.length, beforeTargets + 1);
  } finally {
    elsewhere.closeAllConnections();
    await new Promise(resolve => elsewhere.close(resolve));
  }
  const shimPort = await unusedPort();
  await start('binding-shim.mjs', shimPort, backendPort, 'fixture-token');
  const local = `http://127.0.0.1:${shimPort}`;
  assert.equal((await fetch(local)).status, 200);
  assert.equal(received.at(-1).authorization, 'Bearer fixture-token');
  assert.equal((await fetch(local, { headers: { authorization: 'Bearer explicit' } })).status, 200);
  assert.equal(received.at(-1).authorization, 'Bearer explicit');
  const beforeRefusal = received.length;
  // Observe the probe's actual wire header independently: fetch can replace an explicit Host.
  let observedHost;
  const observer = http.createServer((request, response) => {
    observedHost = request.headers.host;
    response.writeHead(204);
    response.end();
  });
  try {
    const observerPort = await listen(observer);
    assert.equal(await httpStatus(`http://127.0.0.1:${observerPort}`, { host: 'attacker.invalid' }), 204);
    assert.equal(observedHost, 'attacker.invalid', 'the hostile Host must reach the wire');
  } finally {
    await new Promise(resolve => observer.close(resolve));
  }
  assert.equal(await httpStatus(local, { host: 'attacker.invalid' }), 403);
  assert.equal((await fetch(local, { headers: { origin: 'https://attacker.invalid' } })).status, 403);
  assert.equal(received.length, beforeRefusal, 'rejected HTTP/1 requests must never reach upstream');
  const session = http2.connect(local);
  try {
    const status = await new Promise((resolve, reject) => {
      const stream = session.request({ ':path': '/', ':authority': 'attacker.invalid' });
      stream.on('error', reject);
      stream.on('response', headers => resolve(headers[':status']));
      stream.resume();
      stream.end();
    });
    assert.equal(status, 403);
    assert.equal(received.length, beforeRefusal, 'rejected HTTP/2 requests must never reach upstream');
  } finally {
    session.close();
  }
  for (const length of [1, 2, 3, 23, 24]) await fragmentedPreface(shimPort, length);
  console.log('A2A subject protocol regressions passed');
} finally {
  await Promise.all(children.map(child => new Promise(resolve => {
    if (child.exitCode !== null) return resolve();
    child.once('exit', resolve);
    child.kill();
  })));
  backend.closeAllConnections();
  await new Promise(resolve => backend.close(resolve));
  await rm(temporary, { recursive: true, force: true });
}
