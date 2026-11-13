// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE VENDOR, in the A2A conformance rig: a signed-card front for the pinned `a2a-go` control agent.
//
// WHY IT HAS TO EXIST, and why it is not a fixture that fakes anything.
//
// busbar will not APPROVE an `unpinned` registration, by construction — `a2a/pin.rs` caps it, and
// that cap is correct: an approval with no authenticity root is trust on first use wearing a
// ceremony. Of the three roots busbar accepts, two (`cert_spki`, `mtls`) are transport-layer and
// need a certificate the PLATFORM trusts, which a hermetic loopback rig cannot arrange without
// touching the machine's trust store. The third works over plaintext and is the one a real vendor
// with no PKI relationship uses: a JWS-signed Agent Card under an Ed25519 issuer key the operator
// holds out of band.
//
// So this process IS that vendor. It generates the issuer key, signs the control agent's OWN card
// with it — the same RFC 8785 canonicalization and the same detached-JWS shape `a2a/sign.rs`
// produces and `a2a/jws.rs` verifies — and proxies every other request through untouched. Nothing
// about busbar is relaxed to accommodate it: busbar performs the full fetch, the full signature
// verification against the operator-supplied key, and the full fingerprint pin, and REFUSES if any
// of them fails. The alternative — handing busbar a synthetic card, or weakening the approval cap
// for the rig — would be reporting conformance for a busbar nobody can run.
//
// usage: node signing-vendor.mjs <listen-port> <backend-port> <issuer-key-out>
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";

const [listenPort, backendPort, keyOut] = process.argv.slice(2);

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const spkiDer = publicKey.export({ type: "spki", format: "der" });
fs.writeFileSync(keyOut, spkiDer.toString("base64"));

const b64url = (b) => Buffer.from(b).toString("base64url");

// RFC 8785, the subset a card needs. Matches a2a/canonical.rs.
function jcs(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite");
    if (Number.isInteger(v) && Math.abs(v) < 1e21) return String(v);
    return JSON.stringify(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const names = Object.keys(v).sort(); // JavaScript compares UTF-16 code units, as JCS requires.
  return "{" + names.map((n) => JSON.stringify(n) + ":" + jcs(v[n])).join(",") + "}";
}

function signCard(card) {
  const stripped = { ...card };
  delete stripped.signatures;
  const payload = b64url(jcs(stripped));
  const protectedB64 = b64url(jcs({ alg: "EdDSA", kid: "conformance-vendor" }));
  const sig = crypto.sign(null, Buffer.from(`${protectedB64}.${payload}`), privateKey);
  return { ...card, signatures: [{ protected: protectedB64, signature: b64url(sig) }] };
}

const CARD_PATHS = new Set(["/.well-known/agent-card.json", "/.well-known/agent.json"]);

// Optional operator-owned routing for the bounded relay fixture. The boot process owns this
// vendor's lifetime and issuer key. A relay configuration command changes only this private
// route, then asks the real subject to fetch/verify and approve the newly signed peer card.
// No challenge or operation body is interpreted here; the card is signed as fetched.
const ROUTE_FILE = process.env.A2A_VENDOR_ROUTE_FILE || "";

// THIS PROCESS IS A REVERSE PROXY TO ONE FIXED ORIGIN, NEVER A FORWARD PROXY. An absolute-form
// request line (`GET http://169.254.169.254/... HTTP/1.1`) or a scheme-relative target (`//host/`)
// would replace the base in `new URL(target, base)` and send the request anywhere. Only an
// origin-form target is accepted, and the resolved URL must still have the base's origin (WHATWG
// parsing also turns `/\host` into a host change, which the origin check refuses).
class RefusedTarget extends Error {}
function within(reqPath, base) {
  if (typeof reqPath !== "string" || !reqPath.startsWith("/") || reqPath.startsWith("//")) {
    throw new RefusedTarget("request target must be origin-form");
  }
  const fixed = new URL(base);
  const url = new URL(reqPath, fixed);
  if (url.origin !== fixed.origin) {
    throw new RefusedTarget("request target must stay on the fixed backend origin");
  }
  return url;
}

function target(reqPath) {
  if (!ROUTE_FILE || !fs.existsSync(ROUTE_FILE)) {
    return within(reqPath, `http://127.0.0.1:${backendPort}`);
  }
  const route = JSON.parse(fs.readFileSync(ROUTE_FILE, "utf8"));
  const downstream = new URL(route.downstream);
  const card = new URL(route.card_url);
  for (const url of [downstream, card]) {
    if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.username || url.password) {
      throw new Error("relay fixture route must be explicit loopback HTTP");
    }
  }
  if (downstream.origin !== card.origin || downstream.pathname !== "/" || downstream.search || downstream.hash) {
    throw new Error("relay fixture card must belong to its downstream origin");
  }
  const requested = within(reqPath, downstream.origin);
  return CARD_PATHS.has(requested.pathname) ? card : requested;
}


// OPTIONAL: RECORD WHAT THE SUBJECT ORIGINATES, for the requirements about the CLIENT role.
//
// SPEC 3.6.1 ("Clients MUST send the A2A-Version header with each request") is a requirement on
// the party MAKING a request, and no amount of probing a server's front door can decide it. A
// gateway is an A2A client on its upstream leg, and this process already sits on exactly that leg
// — so one append-only JSONL of what arrived here is the observation, taken from a vantage point
// that already existed rather than by adding a hop to the rig.
//
// OFF BY DEFAULT AND INERT WHEN OFF. Every other leg's topology is byte-for-byte what it was: no
// header is added, removed or reordered, and nothing about the response path changes. Recording is
// a side effect on a file descriptor, which is why it is safe to leave in the shared vendor rather
// than forking a second one.
const RECORD_TO = process.env.A2A_VENDOR_RECORD || "";
const recordStream = RECORD_TO ? fs.createWriteStream(RECORD_TO, { flags: "a", mode: 0o600 }) : null;

function record(req, url) {
  if (!recordStream) return;
  const query = {};
  for (const [k, v] of url.searchParams) query[k] = v;
  const headers = { ...req.headers };
  for (const name of Object.keys(headers)) {
    if (['authorization', 'proxy-authorization', 'cookie', 'set-cookie'].includes(name.toLowerCase())) {
      headers[name] = '[redacted]';
    }
  }
  recordStream.write(
    JSON.stringify({
      at: new Date().toISOString(),
      method: req.method,
      path: url.pathname,
      query,
      headers,
    }) + "\n",
  );
}

http
  .createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    record(req, url);
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      let destination;
      try { destination = target(req.url); }
      catch (error) { res.writeHead(error instanceof RefusedTarget ? 400 : 502).end(String(error)); return; }
      const up = http.request(
        {
          host: destination.hostname,
          port: Number(destination.port || 80),
          path: destination.pathname + destination.search,
          method: req.method,
          headers: { ...req.headers, host: destination.host },
        },
        (ur) => {
          if (!CARD_PATHS.has(url.pathname)) {
            // HOP-BY-HOP HEADERS DO NOT CROSS A PROXY (RFC 9110 section 7.6.1). Copying them is not
            // untidiness, it is a corrupt response: this process DECODES the upstream's chunked
            // body and re-encodes its own, so re-announcing `transfer-encoding: chunked` tells the
            // client to parse an already-decoded body as chunk framing. A lenient client tolerates
            // it; a strict one reads zero frames from a stream that plainly has some — which is
            // exactly how an SSE relay downstream reports "the backend's stream carried no event"
            // about a backend that sent four.
            const forwarded = { ...ur.headers };
            for (const h of ["transfer-encoding", "connection", "keep-alive", "content-length"]) {
              delete forwarded[h];
            }
            res.writeHead(ur.statusCode, forwarded);
            ur.pipe(res);
            return;
          }
          const bufs = [];
          ur.on("data", (c) => bufs.push(c));
          ur.on("end", () => {
            let out;
            try {
              out = JSON.stringify(signCard(JSON.parse(Buffer.concat(bufs).toString())));
            } catch (e) {
              res.writeHead(502).end(String(e));
              return;
            }
            res.writeHead(ur.statusCode, {
              "content-type": "application/json",
              "content-length": Buffer.byteLength(out),
            });
            res.end(out);
          });
        },
      );
      up.on("error", (e) => res.writeHead(502).end(String(e)));
      if (body.length) up.write(body);
      up.end();
    });
  })
  .listen(Number(listenPort), "127.0.0.1", () => console.log("signing proxy up"));
