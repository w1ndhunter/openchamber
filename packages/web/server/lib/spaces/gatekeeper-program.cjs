'use strict';

// The program of the gatekeeper container: the space's only way out.
//
// It runs on the Node of the base image, with nothing but the standard library, and it is
// delivered over `exec` on stdin into the container's tmpfs. Nothing about it is written to
// disk on the host side of a space, and it holds every secret in memory only.
//
// Three listeners:
//   corridor  an HTTP CONNECT proxy for the space, on the space-facing interface
//   window    a reverse proxy that adds a secret the space never sees, on the same interface
//   control   the host's channel, on the gatekeeper's own loopback, which the space cannot reach
//
// Arguments: <space-facing bind host> <corridor port> <window port> <control port>
// [<window deadline in ms>]. They are arguments so that the container command and the tests run
// the very same program; the last one lets a test watch a deadline pass without waiting five
// minutes for it. None of them changes a decision this program makes. The bind host is an
// address, or the path of a file that holds one: the container command names the file, and the
// host writes the gatekeeper's own address on the space's network into it before the program,
// because the host knows that address and this program has no say in where it listens.
//
// Everything the space sends is hostile input. Nothing it can send may end the process:
// a crash of the gatekeeper is a denial of service the agent could trigger at will.

const crypto = require('node:crypto');
const dns = require('node:dns');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const os = require('node:os');
const tls = require('node:tls');

const [bindArgument, corridorPort, windowPort, controlPort, windowDeadline, corridorCap, windowCap, controlCap, tunnelIdle, approvalTimeout] = process.argv.slice(2);

/**
 * A cap given on the command line, or the production number when there is none.
 *
 * The caps are arguments for the same reason the window's deadline is: they are lengths, not
 * decisions, and a test that has to exceed one needs it small. A drop only happens when more
 * connections are *accepted* than the cap allows, and a busy machine accepts slowly while the
 * kernel's backlog keeps taking handshakes — so a flood of 300 clients against a cap of 128 can
 * leave every one of them connected and nothing accepted past the cap, and the flood goes
 * unrecorded. At a cap of 4 that cannot happen. The container command carries the production
 * numbers and the hardening test asserts the command, so nothing here can raise them.
 */
const cap = (given, production) => (Number.isInteger(Number(given)) && Number(given) > 0 ? Number(given) : production);
const CONTROL_HOST = '127.0.0.1';

// 443 and nothing else, in both modes, for two reasons.
//
// A space that could reach any port could attack a third party from the user's address: a port
// scan, an SSH brute-force, mail abuse, with the user as the apparent origin. Data can leave over
// 443 whatever anyone does here, but attacking a service that does not listen on 443 cannot, so
// this is a real restriction and not a speed bump.
//
// And it costs almost nothing. Services on other ports are overwhelmingly private ones, internal
// registries and internal git, and the private-address block already refuses those in both modes
// at every port. Public HTTPS is essentially all 443. When a port is genuinely needed, it belongs
// in the grant dialog as an explicit `address:port` the user opens, never in a mode-wide rule.
const ALLOWED_PORT = 443;
// Refused in both modes, whatever the allowlist says. In allowlist mode that makes it
// unreachable. In open mode it only makes it harder: the space reaches every public host on 443,
// so it can go through a third-party intermediary and the corridor sees only that name. What
// holds in both modes is that the long-lived refresh token is never inside the space at all.
const ALWAYS_REFUSED = ['auth.openai.com'];

// The space can open connections without end, so all of these are caps it cannot lift.
const MAX_TUNNELS = 64;
// Sockets that are not tunnels yet: a client has ten seconds to send its request line, and
// MAX_TUNNELS counts only what is established. Twice the tunnel cap leaves room for every
// handshake a working space makes and still refuses a flood, which the space can otherwise use
// to have this process killed and the journal of what it tried killed with it.
const MAX_CORRIDOR_CONNECTIONS = cap(corridorCap, 2 * MAX_TUNNELS);
// The window serves one request per connection at a time, and each one holds a socket out.
// The same number in and out, so the outgoing side can never grow past the incoming one.
const MAX_WINDOW_CONNECTIONS = cap(windowCap, 64);
// No byte from the upstream for this long and the request is over. The same number as a tunnel's
// idle limit and for the same reason: a model answer streams, so what matters is silence, not
// how long the whole answer takes. Without it an upstream that accepts and never answers holds
// its socket in and its socket out for the life of the space, and 64 of those are every slot
// the window has. The space cannot choose a grant's upstream, so this is about one provider
// going quiet rather than about the agent.
const WINDOW_IDLE_MS = Number(windowDeadline) > 0 ? Number(windowDeadline) : 300_000;
// Only the host talks to the control channel, one request at a time.
const MAX_CONTROL_CONNECTIONS = cap(controlCap, 8);
// Traffic that never reached a decision is journalled at most this often, per listener and per
// kind. The flood is the point of the record, and 500 records of it would erase everything else.
const NOTE_INTERVAL_MS = 60_000;
// No byte in either direction for this long and the tunnel goes. A model answer streams,
// and a long turn can be quiet for minutes, so this is generous on purpose. It is the last
// argument, a length like the window's deadline, so a test can watch it pass.
const TUNNEL_IDLE_MS = Number(tunnelIdle) > 0 ? Number(tunnelIdle) : 300_000;
const CONNECT_TIMEOUT_MS = 15_000;

const MAX_HEADER_BYTES = 16 * 1024;
const HEADERS_TIMEOUT_MS = 10_000;
const REQUEST_TIMEOUT_MS = 60_000;
const CONTROL_BODY_BYTES = 1024 * 1024;

// The journal is small on purpose: it is a record of attempts, not a log.
const JOURNAL_RECORDS = 500;
// The same field caps the host channel reads back with, so a full ring always fits its answer.
const MAX_JOURNAL_HOST = 256;
const MAX_JOURNAL_DECISION = 64;
const MAX_ALLOWED_DOMAINS = 500;

// The methods that cannot change anything out there. Every other method is a write as far as this
// proxy is concerned: the corridor cannot tell `POST /issues` from `POST /search`, so the user
// decides about the method as a whole.
// QUERY is the RFC 10008 answer to a read that needs a body: safe and idempotent like GET, with
// the request content of POST. A server that does not know it answers for itself.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'QUERY']);
// The methods the user may approve for a destination. Anything outside this list is refused
// outright: a custom method is not something a tool needs, and approving it would only widen the
// set of ways the space can act on a host.
const WRITABLE_METHODS = ['DELETE', 'PATCH', 'POST', 'PUT'];
const MAX_WRITE_ENTRIES = 200;
// How long a write waits for the user's answer before the gatekeeper refuses it. A length like the
// tunnel's idle limit, so a test can watch it pass; the host shows a prompt meanwhile.
const APPROVAL_TIMEOUT_MS = Number(approvalTimeout) > 0 ? Number(approvalTimeout) : 60_000;
// A space can start writes faster than a person can read them. Past this the next one is refused
// at once, so writer holds cannot fill the corridor and take the user's attention with them.
const MAX_PENDING_APPROVALS = 8;
// Certificates are issued per destination on demand. The cache is bounded so a space in open mode
// cannot make the gatekeeper hold a certificate for every name it invents.
const MAX_CERTIFICATES = 512;
const METHOD_PATTERN = /^[A-Z]{1,16}$/;

const DOMAIN_PATTERN = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
// A last label that is a number or hex is an address in one of the spellings `getaddrinfo` takes.
const NUMERIC_LABEL = /^(\d+|0x[0-9a-f]+)$/;
const GRANT_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const HEADER_NAME_PATTERN = /^[A-Za-z0-9-]{1,64}$/;
const MAX_SECRET_LENGTH = 8192;
// The headers of the user's own a grant may add beside its credential, for a provider that wants
// them on every request. Capped like the rest; the names the window owns are never among them.
const MAX_GRANT_HEADERS = 32;
const HEADER_VALUE_PATTERN = /^[\t\x20-\x7e\x80-\xff]+$/;
const RESERVED_HEADER_NAMES = ['host', 'content-length', 'transfer-encoding', 'connection', 'te', 'upgrade', 'keep-alive', 'proxy-connection', 'authorization', 'x-api-key', 'proxy-authorization'];

/**
 * The address the corridor and the window listen on. An argument that starts with `/` is the
 * file the host wrote beside this program, holding the gatekeeper's own address on the space's
 * network; anything else is the address itself, which is what the tests pass. Whichever it is,
 * it must be the address of one interface: a file that is missing or empty, or anything that is
 * not an address or names every interface, ends the program. On a Linux Docker host every local
 * process can reach the bridge, and a window that listens there spends the user's key for anyone
 * on the machine. That includes a gatekeeper made before stage 5b, whose command still says
 * `0.0.0.0` and whose checker never compared the command: it no longer starts, and such a
 * space has to be made again. Failing to start is the safe answer.
 */
function readBindHost(argument) {
  const given = String(argument ?? '');
  let text = given;
  if (given.startsWith('/')) {
    try {
      text = fs.readFileSync(given, 'utf8').trim();
    } catch (error) {
      console.error(`gatekeeper: cannot read the bind address from ${given} (${error.code || error.message})`);
      process.exit(2);
    }
  }
  if (net.isIP(text) === 0 || text === '0.0.0.0' || text === '::') {
    console.error(`gatekeeper: ${given} is not the address of one interface`);
    process.exit(2);
  }
  return text;
}
// Everything the host sets, in memory only. Never a file, never an environment variable,
// never an argument, never a label. A restart starts from "nothing is allowed".
let networkMode = 'allowlist';
// Whether a write the user has not approved for its destination still waits for an answer. `ask`
// is the default a gatekeeper starts from and what a record without the choice says.
let writePolicy = 'ask';
let allowedDomains = new Set();
const grants = new Map();
// The methods the user approved, per destination: `{ methods, paths }`, the methods for every path
// of the host and the methods for one exact path. Absent means GET, HEAD and OPTIONS only.
let writeAccess = new Map();
// The methods the user denied, in the same shape. A repeat is refused at once, without a wait:
// the answer stands until the user clears it in the access dialog.
let deniedWrites = new Map();
// Refusals of one write the user did not want to keep: same shape, and refused the same way, but
// memory only and never in `/policy`. They end when the host says the chat's turn is over, so the
// agent's next turn asks again. Kept apart from `deniedWrites` because the host reads that list
// back and saves it for the next start.
let turnDenials = new Map();
// The host may never say that turn ended: the app was closed, or the chat that answered is not
// the one shown. A refusal must not become invisible and unliftable then, so the whole list stops
// standing after this long, longer than a turn usually runs and short enough that a forgotten
// answer costs one prompt.
const TURN_DENIAL_MS = 10 * 60_000;
let turnDenialsUntil = 0;
// The last time a standing denial was journalled, per destination and method: a retry loop is not
// evidence, and 500 of its records would erase everything else the journal holds.
const lastDenialNote = new Map();
// Writes waiting for the user's answer, by the number this gatekeeper gave them. Each holds the
// space's own request and socket: nothing of it is read until the answer arrives.
const pendingApprovals = new Map();
// Hosts waiting on `GET /pending` for one of those to appear or to time out.
const approvalWaiters = new Set();
let approvalSeq = 0;

// When this program started, for the journal: nothing before it is on record.
const STARTED_AT = new Date().toISOString();
const journal = [];
let journalDropped = 0;

/**
 * One record per attempt: when, which listener, where to, and what was decided. Never a path,
 * never a query, never a body, never a header value, never a grant's secret. When the ring is
 * full the oldest record goes and `dropped` counts it, so the host can say that it is not
 * looking at the whole story.
 *
 * The host is cut to the length the host channel reads back. A plain proxy request may carry a
 * 16 KiB request line, and without this cut a space could make the whole journal too large to
 * read and hold it that way, which would take the user's only view of what it tried.
 */
function record(listener, host, port, decision, method = '') {
  journal.push({
    at: new Date().toISOString(),
    listener,
    host: String(host || '').slice(0, MAX_JOURNAL_HOST),
    port: Number(port) || 0,
    method: String(method || '').slice(0, 20),
    decision: String(decision).slice(0, MAX_JOURNAL_DECISION),
  });
  if (journal.length > JOURNAL_RECORDS) {
    journal.shift();
    journalDropped += 1;
  }
}

// ---------------------------------------------------------------------------------------------
// Addresses
//
// Refusal is by resolved address, in both network modes. The list covers the ranges that lead
// back to the user's own machine, to their network, or to a cloud metadata service.
// ---------------------------------------------------------------------------------------------

function parseIPv4(text) {
  const parts = String(text).split('.');
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    bytes.push(value);
  }
  return bytes;
}

/** 16 bytes, or null when this is not an IPv6 address. A zone id is cut off first. */
function parseIPv6(text) {
  const address = String(text).split('%')[0];
  if (!address.includes(':')) return null;
  const [head, tail, ...rest] = address.split('::');
  if (rest.length > 0) return null;
  const readGroups = (part) => {
    if (part === undefined || part === '') return [];
    const groups = [];
    const pieces = part.split(':');
    for (let index = 0; index < pieces.length; index += 1) {
      const piece = pieces[index];
      // The last group may be a dotted IPv4 address: ::ffff:127.0.0.1 and friends.
      if (index === pieces.length - 1 && piece.includes('.')) {
        const embedded = parseIPv4(piece);
        if (!embedded) return null;
        groups.push(embedded[0] * 256 + embedded[1], embedded[2] * 256 + embedded[3]);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
      groups.push(Number.parseInt(piece, 16));
    }
    return groups;
  };
  const left = readGroups(head);
  const right = tail === undefined ? [] : readGroups(tail);
  if (left === null || right === null) return null;
  const missing = 8 - left.length - right.length;
  if (tail === undefined ? missing !== 0 : missing < 0) return null;
  const groups = [...left, ...new Array(tail === undefined ? 0 : missing).fill(0), ...right];
  if (groups.length !== 8) return null;
  const bytes = [];
  for (const group of groups) bytes.push((group >> 8) & 0xff, group & 0xff);
  return bytes;
}

function blockedIPv4(bytes) {
  const [a, b, c] = bytes;
  return a === 0 // 0.0.0.0/8, "this network"
    || a === 10 // 10.0.0.0/8
    || (a === 100 && b >= 64 && b <= 127) // 100.64.0.0/10, carrier-grade NAT
    || a === 127 // 127.0.0.0/8, loopback
    || (a === 169 && b === 254) // 169.254.0.0/16, link-local and the cloud metadata address
    || (a === 172 && b >= 16 && b <= 31) // 172.16.0.0/12
    || (a === 192 && b === 0 && c === 0) // 192.0.0.0/24, IETF protocol assignments
    || (a === 192 && b === 168) // 192.168.0.0/16
    || (a === 198 && (b === 18 || b === 19)) // 198.18.0.0/15, benchmarking
    || a >= 224; // 224.0.0.0/4 multicast and 240.0.0.0/4 reserved, broadcast included
}

/** The IPv4 address inside an IPv6 one, for the three forms that carry one, or null. */
function embeddedIPv4(bytes) {
  const zeros = (from, to) => bytes.slice(from, to).every((byte) => byte === 0);
  // ::ffff:0:0/96, the IPv4-mapped form, and the deprecated IPv4-compatible ::a.b.c.d.
  if (zeros(0, 10) && ((bytes[10] === 0xff && bytes[11] === 0xff) || (bytes[10] === 0 && bytes[11] === 0 && !zeros(12, 16)))) {
    return bytes.slice(12, 16);
  }
  // 64:ff9b::/96, NAT64.
  if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b && zeros(4, 12)) {
    return bytes.slice(12, 16);
  }
  // 2002::/16, 6to4: the IPv4 address sits in the next four bytes.
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    return bytes.slice(2, 6);
  }
  return null;
}

function blockedIPv6(bytes) {
  const embedded = embeddedIPv4(bytes);
  if (embedded) return blockedIPv4(embedded);
  if (bytes.every((byte) => byte === 0)) return true; // ::
  if (bytes.slice(0, 15).every((byte) => byte === 0) && bytes[15] === 1) return true; // ::1
  if ((bytes[0] & 0xfe) === 0xfc) return true; // fc00::/7, unique local
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true; // fe80::/10, link-local
  if (bytes[0] === 0xff) return true; // ff00::/8, multicast
  return false;
}

/** True for an address that leads back to the user's machine, their network, or a metadata service. */
function isBlockedAddress(text) {
  const v4 = parseIPv4(text);
  if (v4) return blockedIPv4(v4);
  const v6 = parseIPv6(text);
  if (v6) return blockedIPv6(v6);
  // Not an address we can read is not an address we let through.
  return true;
}

const lookupAll = (host) => new Promise((resolve) => {
  dns.lookup(host, { all: true, verbatim: true }, (error, answers) => {
    if (error || !Array.isArray(answers) || answers.length === 0) {
      resolve({ addresses: [], reason: error ? String(error.code || error.message) : 'no address' });
      return;
    }
    resolve({ addresses: answers, reason: '' });
  });
});

/**
 * Which of the resolved answers to connect to. IPv4 first, whatever order the resolver gave them,
 * because the gatekeeper's outer network is created with `--ipv6=false` and an IPv6 address there
 * is a connection that cannot be made. A resolver that answers AAAA first would otherwise turn a
 * perfectly allowed host into a 502 that names nothing. An IPv6-only host is still attempted, and
 * fails with a message that says what happened.
 *
 * This changes which checked address is used and never whether it was checked: every answer goes
 * through the block list before any of them is chosen.
 */
const chooseAddress = (addresses) => addresses.find((answer) => answer.family === 4) ?? addresses[0];

/**
 * Resolves the name itself and refuses when any answer is a blocked address, then hands back the
 * one address the caller must connect to. The caller never resolves the name again: a second
 * lookup is where DNS rebinding gets in.
 */
async function resolveAllowedAddress(host) {
  const { addresses, reason } = await lookupAll(host);
  if (addresses.length === 0) return { error: `unresolved:${reason}` };
  if (addresses.some((answer) => isBlockedAddress(answer.address))) return { error: 'blocked-address' };
  const chosen = chooseAddress(addresses);
  return { address: chosen.address, family: chosen.family };
}

/** A lookup that answers with the one address that was already checked, in either shape Node asks for. */
const fixedLookup = (address, family) => (hostname, options, callback) => {
  if (options && options.all) callback(null, [{ address, family }]);
  else callback(null, address, family);
};

// One TLS connection is kept per destination, so a page with a dozen requests does not pay a
// dozen handshakes and the space's own keep-alive finds its match here. The socket still goes to
// the address each tunnel checked: `lookup` is fixed and `servername` is the checked name.
const UPSTREAM_AGENT = new https.Agent({ keepAlive: true, maxSockets: 128, maxFreeSockets: 8 });

// ---------------------------------------------------------------------------------------------
// Certificates
//
// The corridor has to read the method of a request, and a TLS tunnel hides it. So the corridor
// ends the space's TLS and starts its own: a certificate authority made here, in memory, signs
// one certificate per destination, and the space trusts that authority through its environment.
// The authority never leaves this process, and the certificate it signs is public.
//
// The DER below is written by hand because the program has nothing but the standard library.
// Node can read X.509 but not make it, and the image's openssl would add a process per new host.
// ---------------------------------------------------------------------------------------------

/** DER length bytes. */
function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value = Math.floor(value / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const derTlv = (tag, content) => Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
const derSequence = (...items) => derTlv(0x30, Buffer.concat(items));
const derSet = (...items) => derTlv(0x31, Buffer.concat(items));
const derInteger = (bytes) => derTlv(0x02, Buffer.from(bytes));
const derBoolean = (value) => derTlv(0x01, Buffer.from([value ? 0xff : 0x00]));
const derOctets = (bytes) => derTlv(0x04, bytes);
const derBitString = (bytes) => derTlv(0x03, Buffer.concat([Buffer.from([0]), bytes]));
const derUtf8 = (text) => derTlv(0x0c, Buffer.from(text, 'utf8'));

/** An object identifier, in the base-128 form DER uses after the first two arcs. */
function derOid(text) {
  const parts = String(text).split('.').map(Number);
  const bytes = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [];
    let value = part;
    do {
      chunk.unshift(value & 0x7f);
      value = Math.floor(value / 128);
    } while (value > 0);
    for (let index = 0; index < chunk.length - 1; index += 1) chunk[index] |= 0x80;
    bytes.push(...chunk);
  }
  return derTlv(0x06, Buffer.from(bytes));
}

/** A certificate name with one common name, which is all either side needs. */
const derName = (commonName) => derSequence(derSet(derSequence(derOid('2.5.4.3'), derUtf8(commonName))));
const derUtcTime = (date) => {
  const two = (value) => String(value).padStart(2, '0');
  const text = `${two(date.getUTCFullYear() % 100)}${two(date.getUTCMonth() + 1)}${two(date.getUTCDate())}${two(date.getUTCHours())}${two(date.getUTCMinutes())}${two(date.getUTCSeconds())}Z`;
  return derTlv(0x17, Buffer.from(text, 'ascii'));
};
// ecdsa-with-SHA256, the one algorithm used here.
const derSignatureAlgorithm = () => derSequence(derOid('1.2.840.10045.4.3.2'));
const derExtension = (id, critical, value) => derSequence(derOid(id), ...(critical ? [derBoolean(true)] : []), derOctets(value));
const derPem = (der) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

/** A serial number that is positive in DER: the high bit of the first byte is never used, and a
 * zero first byte is raised to one, because a leading zero would not be the shortest encoding. */
function derSerial() {
  const bytes = crypto.randomBytes(16);
  bytes[0] = (bytes[0] & 0x7f) || 1;
  return bytes;
}

/**
 * One certificate. `ca` makes the self-signed authority; otherwise the leaf names `host` and
 * carries it in the subject alternative name, which is the field every client checks today.
 */
function buildCertificate({ subject, issuer, key, signerKey, ca, host = null, serial }) {
  const now = Date.now();
  const extensions = [
    derExtension('2.5.29.19', true, derSequence(...(ca ? [derBoolean(true)] : []))),
    derExtension('2.5.29.15', true, derBitString(ca ? Buffer.from([0x06]) : Buffer.from([0x80]))),
  ];
  if (host) {
    extensions.push(derExtension('2.5.29.17', false, derSequence(derTlv(0x82, Buffer.from(host, 'ascii')))));
    extensions.push(derExtension('2.5.29.37', false, derSequence(derOid('1.3.6.1.5.5.7.3.1'))));
  }
  const tbs = derSequence(
    derTlv(0xa0, derInteger([2])),
    derInteger(serial),
    derSignatureAlgorithm(),
    derName(issuer),
    derSequence(derUtcTime(new Date(now - 300_000)), derUtcTime(new Date(now + (ca ? 3650 : 825) * 24 * 3600_000))),
    derName(subject),
    key.export({ type: 'spki', format: 'der' }),
    derTlv(0xa3, derSequence(...extensions)),
  );
  return derSequence(tbs, derSignatureAlgorithm(), derBitString(crypto.sign('sha256', tbs, signerKey)));
}

/** A fresh authority, with one leaf key shared by every certificate it signs. */
function createCertificateAuthority() {
  const keys = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const leaf = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const certificate = buildCertificate({
    subject: 'OpenChamber space gatekeeper',
    issuer: 'OpenChamber space gatekeeper',
    key: keys.publicKey,
    signerKey: keys.privateKey,
    ca: true,
    serial: derSerial(),
  });
  return {
    certificate,
    certificatePem: derPem(certificate),
    privateKey: keys.privateKey,
    leafPrivateKey: leaf.privateKey,
    leafKeyPem: leaf.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    leafPublicKey: leaf.publicKey,
  };
}

/** The certificate for one destination, signed by the authority. */
function issueCertificate(authority, host) {
  return buildCertificate({
    subject: host,
    issuer: 'OpenChamber space gatekeeper',
    key: authority.leafPublicKey,
    signerKey: authority.privateKey,
    ca: false,
    host,
    serial: derSerial(),
  });
}

let authority = null;
let authorityCertificatePem = '';
const certificateContexts = new Map();

/** The TLS context for a destination, made once and kept while the cache has room. */
function contextFor(host) {
  const known = certificateContexts.get(host);
  if (known) return known;
  const certificate = derPem(issueCertificate(authority, host));
  const context = tls.createSecureContext({ key: authority.leafKeyPem, cert: certificate });
  if (certificateContexts.size >= MAX_CERTIFICATES) certificateContexts.clear();
  certificateContexts.set(host, context);
  return context;
}


// ---------------------------------------------------------------------------------------------
// Corridor
// ---------------------------------------------------------------------------------------------

/** `host:port` or `[v6]:port` from a CONNECT line. Null for anything else. */
function splitTarget(text) {
  const value = String(text || '');
  const separator = value.lastIndexOf(':');
  if (separator <= 0) return null;
  const port = Number(value.slice(separator + 1));
  let host = value.slice(0, separator);
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (!Number.isInteger(port) || port < 1 || port > 65535 || host.length === 0 || host.length > 255) return null;
  if (/[\s/@]/.test(host)) return null;
  return { host, port };
}

const normalizeName = (host) => String(host).trim().toLowerCase().replace(/\.$/, '');

/**
 * Why this target may not pass, or null when it may. Names match exactly: no wildcards, no suffixes.
 *
 * The corridor takes names and never addresses, in both modes. A literal address walks past
 * every rule that is about a name: `auth.openai.com` is refused and its address was not, and a
 * space can learn that address from a public DNS-over-HTTPS resolver through this same corridor.
 * Comparing resolved addresses instead would be unreliable in both directions, because a CDN's
 * answers rotate. The space has no public resolver of its own, so every CONNECT it can make on
 * purpose is already by name and nothing it needs is lost.
 *
 * Reading four dotted octets is not enough to know an address when you see one. `getaddrinfo`
 * on this image's C library also takes `1746020849`, `0x01010101`, `1.1.257` and
 * `0x1.0x1.0x1.0x1`, and the block list only catches private ranges, so a public address in one
 * of those spellings went straight out. So the target must look like a domain name instead: the
 * same name rule the allowlist uses, and a last label that is not a number and not hex, because
 * no top-level domain is either. That closes every one of those spellings at once, and it keeps
 * non-ASCII out as well: `auth.openai.com。` with an ideographic full stop resolves on this C
 * library exactly like the name it imitates, and today only the HTTP parser stands in the way.
 */
function refuseTarget(host, port) {
  const name = normalizeName(host);
  if (ALWAYS_REFUSED.includes(name)) return 'deny:always-refused';
  if (parseIPv4(name) || parseIPv6(name) || !isDomainName(name)) return 'deny:not-a-name';
  if (port !== ALLOWED_PORT) return 'deny:port';
  if (networkMode === 'open') return null;
  return allowedDomains.has(name) ? null : 'deny:not-on-allowlist';
}

/** A name with an ordinary last label: not a number, not hex, and the label rules of a domain. */
const isDomainName = (name) => DOMAIN_PATTERN.test(name) && !NUMERIC_LABEL.test(name.slice(name.lastIndexOf('.') + 1));

let openTunnels = 0;

/**
 * The idle limit on a socket that is a tunnel, or is about to become one. Armed as soon as the
 * corridor answers the CONNECT, not only after the TLS handshake: a client that asks for a tunnel
 * and sends nothing must not keep its place, or sixty-four of them close the corridor for the
 * space.
 */
function guardTunnelIdle(socket) {
  socket.setTimeout(TUNNEL_IDLE_MS, () => socket.destroy());
}

// The two things the space is told apart, and the only two. `refused` covers every reason the
// gatekeeper said no; `unreachable` means it said yes and the connection out did not happen.
//
// The reason why it said no stays in the journal, where the user reads it. Telling the space
// would hand it a resolver oracle: walking a list of names and sorting `deny:blocked-address`
// from `deny:unresolved` would map the user's internal DNS without reaching any of it, and
// telling `deny:not-on-allowlist` from `deny:not-a-name` says which mode the space is in.
// How many refused clients may be waited on at once, against the corridor's cap of 128. Small
// on purpose: waiting is a courtesy to a client that is still talking, not a place it can hold.
const MAX_LINGERING_REFUSALS = 16;
const lingeringRefusals = new Set();

const REFUSED = 'refused';
const UNREACHABLE = 'unreachable';
// What the space reads when one of its writes is refused. A refusal is a decision, not a failure:
// an agent that reads it as transient retries it, and each retry is another wasted round, so the
// body says plainly that it will not change. A wait nobody answered is the exception: the user did
// not decide, and the agent may ask again.
const REFUSED_BY_USER = 'the user refused this write: do not retry it';
const UNANSWERED = 'the user did not answer this write in time';

/**
 * The corridor's answer to a client it will not serve. The reason header is what tells a reader
 * "the gatekeeper refused this" from "the gatekeeper allowed it and the connection out failed",
 * which is a difference nobody could see in a bare 502, and nothing more than that.
 */
function refuse(socket, status, text, reason) {
  try {
    socket.end(`HTTP/1.1 ${status} ${text}\r\nx-gatekeeper-reason: ${reason}\r\nConnection: close\r\n\r\n`);
    // Drain whatever the client is still sending, and wait for it to finish before closing.
    // Closing a socket that still has unread bytes in its receive queue sends a reset, and a
    // reset throws away what the client has received and not yet read: measured, a client that
    // wrote a megabyte after its CONNECT lost its 403 to it in three runs out of five. The
    // refusal stands either way — nothing gets through — but the reason header is the only
    // thing that tells the space why, so it should arrive.
    socket.resume();
    // And the socket still has to be let go, or this is the wedge again: an `http.Server` socket
    // allows half-open, the request timeouts stop applying once a CONNECT has been handed over,
    // and the tunnel's idle timeout is only armed on a tunnel that exists, so a client that never
    // closes keeps its socket for as long as it likes. Measured before this: 140 of those filled
    // the connection cap and the corridor answered nothing, with nothing at all open. So a client
    // that finishes gets its socket closed properly, and only the last few are ever waited on:
    // past that the oldest goes, which costs it a readable reason and costs the corridor nothing.
    const release = () => { lingeringRefusals.delete(socket); if (!socket.destroyed) socket.destroySoon(); };
    lingeringRefusals.add(socket);
    socket.on('close', () => lingeringRefusals.delete(socket));
    socket.on('error', release);
    socket.on('end', release);
    while (lingeringRefusals.size > MAX_LINGERING_REFUSALS) {
      const oldest = lingeringRefusals.values().next().value;
      lingeringRefusals.delete(oldest);
      oldest.destroy();
    }
  } catch {
    socket.destroy();
  }
}

async function openTunnel(request, clientSocket, head) {
  // Without this an error on a socket we are not reading yet ends the process. Stage 0 lost a
  // corridor to a client that reset the connection after a refusal.
  clientSocket.on('error', () => {});
  // A client that leaves while its name is being resolved, or while the connection out is still
  // being made, must free its place at once. `end` matters as much as `close`: a socket the
  // corridor has not started reading from stays half-open after the client's FIN, and without
  // this the space could hold every place in the corridor by opening and leaving.
  let release = () => {};
  const clientLeft = () => release();
  clientSocket.on('close', clientLeft);
  clientSocket.on('end', clientLeft);

  const target = splitTarget(request.url);
  if (!target) {
    record('corridor', '', 0, 'deny:malformed');
    refuse(clientSocket, 400, 'Bad Request', REFUSED);
    return;
  }
  const { host, port } = target;
  const refusal = refuseTarget(host, port);
  if (refusal) {
    record('corridor', normalizeName(host), port, refusal);
    refuse(clientSocket, 403, 'Forbidden', REFUSED);
    return;
  }
  if (openTunnels >= MAX_TUNNELS) {
    record('corridor', normalizeName(host), port, 'deny:too-many-tunnels');
    refuse(clientSocket, 503, 'Service Unavailable', REFUSED);
    return;
  }
  // The place is taken before the name is looked up, not after. Otherwise a burst of clients
  // would all pass the check while they wait for DNS, and the cap would be one in name only.
  openTunnels += 1;
  let counted = true;
  const releasePlace = () => {
    if (counted) {
      counted = false;
      openTunnels -= 1;
    }
  };
  release = releasePlace;

  // The name that was checked is the name that is resolved. Anything else leaves a gap between
  // the two for input that normalises into something else.
  const resolved = await resolveAllowedAddress(normalizeName(host));
  if (resolved.error) {
    releasePlace();
    record('corridor', normalizeName(host), port, `deny:${resolved.error}`);
    refuse(clientSocket, 403, 'Forbidden', REFUSED);
    return;
  }
  const name = normalizeName(host);
  record('corridor', name, port, 'allow');

  // A raw tunnel hides the method, and the method is what the user decides about. So the corridor
  // ends the space's TLS here and speaks HTTP/1.1 to it. The certificate names the destination
  // that was checked a moment ago, and the authority that signs it never leaves this process.
  let secure;
  try {
    const context = contextFor(name);
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length > 0) clientSocket.unshift(head);
    // Armed here and not only after the handshake: a client that asks for a tunnel and then sends
    // nothing must not keep its place for the life of the gatekeeper. Sixty-four of those would
    // close the corridor for the space. The TLS and HTTP layers reset this timer on activity.
    guardTunnelIdle(clientSocket);
    secure = new tls.TLSSocket(clientSocket, { isServer: true, secureContext: context });
  } catch (error) {
    record('corridor', name, port, `failed:${String(error.code || 'tls').slice(0, 32)}`);
    clientSocket.destroy();
    releasePlace();
    return;
  }
  // The place belongs to this connection until it is gone, not only until the handshake.
  release = () => {};
  const finished = () => releasePlace();
  secure.on('close', finished);
  secure.on('error', () => { secure.destroy(); });
  secure.on('secure', () => {
    // The certificate was issued for the name that was checked. A different server name in the
    // handshake would let an allowed name carry another one on the same address.
    const servername = normalizeName(secure.servername || name);
    if (secure.servername && servername !== name) {
      record('corridor', name, port, 'deny:sni-mismatch', '');
      secure.destroy();
      return;
    }
    secure.openchamberTarget = { host: name, port, address: resolved.address, family: resolved.family };
    guardTunnelIdle(secure);
    decrypted.emit('connection', secure);
  });
  // The client may have left while its name was being resolved.
  if (clientSocket.destroyed || clientSocket.readableEnded) {
    secure.destroy();
    releasePlace();
  }
}

// What may not be copied to the upstream or back to the space: it describes one connection, and
// the two connections are different ones.
const HOP_BY_HOP_HEADERS = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

/** The answer to a decrypted request that never reached an upstream. */
function refuseDecrypted(response, status, reason, message) {
  if (response.destroyed) return;
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, { 'content-type': 'application/json', 'x-gatekeeper-reason': reason, 'cache-control': 'no-store' });
  response.end(JSON.stringify({ error: message }));
}

/** The host the request says it is for, which must be the name the corridor checked. */
function requestHostOf(request, target) {
  const header = request.headers?.host;
  if (!header) return target.host;
  const text = String(header).trim();
  const host = text.startsWith('[') ? text : text.replace(/:\d+$/, '');
  return normalizeName(host);
}

/** The origin-form path, or `{ mismatch: true }` for an absolute-form URL naming another host. */
function requestPathOf(request, target) {
  const url = String(request.url || '/');
  if (!/^https?:\/\//i.test(url)) return { path: url === '' ? '/' : url };
  try {
    const parsed = new URL(url);
    if (normalizeName(parsed.hostname) !== target.host) return { mismatch: true };
    return { path: `${parsed.pathname}${parsed.search}` };
  } catch {
    return { mismatch: true };
  }
}

/**
 * GraphQL over HTTP sends reads and writes as the same POST, and the operation type is inside the
 * document, not the method. This classifies a body so a document that can only read goes out like
 * a GET, while anything that could mutate (or that this cannot read with certainty) still waits
 * for the user. `application/graphql` carries the document itself; everything else is the JSON
 * envelope the guide at graphql.org describes.
 */
const GRAPHQL_BODY_LIMIT = 1024 * 1024;
const GRAPHQL_PATH_PATTERN = /\/graphql(\.json)?\/?$/i;
const GRAPHQL_MEDIA_TYPE = 'application/graphql';

function isGraphqlRequest(request, path) {
  if (GRAPHQL_PATH_PATTERN.test(path.split('?')[0])) return true;
  const type = String(request.headers['content-type'] ?? '').toLowerCase().split(';')[0].trim();
  return type === GRAPHQL_MEDIA_TYPE;
}

function isRawGraphqlRequest(request) {
  return String(request.headers['content-type'] ?? '').toLowerCase().split(';')[0].trim() === GRAPHQL_MEDIA_TYPE;
}

/** The index after a GraphQL string or block string, or -1 when it never closes. */
function skipGraphqlString(text, start) {
  const length = text.length;
  if (text.startsWith('"""', start)) {
    let at = start + 3;
    while (at < length) {
      if (text.startsWith('\\"""', at)) { at += 4; continue; }
      if (text.startsWith('"""', at)) return at + 3;
      at += 1;
    }
    return -1;
  }
  let at = start + 1;
  while (at < length) {
    const character = text[at];
    if (character === '\\') { at += 2; continue; }
    if (character === '"') return at + 1;
    // A normal string cannot span a line; a newline means the document is not what it claims.
    if (character === '\n' || character === '\r') return -1;
    at += 1;
  }
  return -1;
}

const NAME_START = /[A-Za-z_]/;
const NAME_PART = /[A-Za-z0-9_]/;

/**
 * The operation types a document defines: 'query', 'mutation', 'subscription', or null when the
 * document is not something this can read with certainty. Only the top level is read; nothing
 * inside a selection set can start a second operation. Fragments are skipped (a fragment alone
 * is not executable), and so are comments, commas and block strings.
 */
function operationTypesOf(text) {
  const types = new Set();
  const length = text.length;
  let at = 0;
  // 'between' expects a definition, 'header' is past its keyword, 'body' is inside `{...}`.
  let phase = 'between';
  // The closers still owed. A header may open `(` and `[` (variable types, default values,
  // directive arguments) before the body's `{`; only falling back to empty ends a definition.
  const closers = [];
  while (at < length) {
    const character = text[at];
    if (character === ' ' || character === '\t' || character === '\n' || character === '\r' || character === ',' || character === '\ufeff') { at += 1; continue; }
    if (character === '#') {
      while (at < length && text[at] !== '\n' && text[at] !== '\r') at += 1;
      continue;
    }
    if (character === '"') {
      at = skipGraphqlString(text, at);
      if (at < 0) return null;
      continue;
    }
    if (closers.length > 0) {
      if (character === '{') closers.push('}');
      else if (character === '(') closers.push(')');
      else if (character === '[') closers.push(']');
      else if (character === '}' || character === ')' || character === ']') {
        if (closers.pop() !== character) return null;
        if (closers.length === 0 && phase === 'body') phase = 'between';
      }
      at += 1;
      continue;
    }
    if (character === '{') {
      if (phase === 'between') types.add('query');
      else if (phase !== 'header') return null;
      closers.push('}');
      phase = 'body';
      at += 1;
      continue;
    }
    if (character === '(' || character === '[') {
      // A group that is not part of a definition header is not a document this understands.
      if (phase !== 'header') return null;
      closers.push(character === '(' ? ')' : ']');
      at += 1;
      continue;
    }
    if (character === '}' || character === ')' || character === ']') return null;
    if (NAME_START.test(character)) {
      let end = at;
      while (end < length && NAME_PART.test(text[end])) end += 1;
      const word = text.slice(at, end);
      if (phase === 'between') {
        if (word === 'query' || word === 'mutation' || word === 'subscription') {
          types.add(word);
          phase = 'header';
        } else if (word === 'fragment') {
          phase = 'header';
        } else {
          return null;
        }
      }
      // In a header the operation name, 'on', type names and directives say nothing about the type.
      at = end;
      continue;
    }
    // Punctuation of a header (`$ ! = : @ | &` and variable names' digits) is harmless there.
    if (phase === 'header' || phase === 'between') { at += 1; continue; }
    return null;
  }
  if (closers.length !== 0 || phase === 'header' || types.size === 0) return null;
  return types;
}

/**
 * 'read' when every operation the body can execute is a query, 'write' when it names a mutation
 * or a subscription, 'unknown' for anything else: a body that does not parse, a batch with a bad
 * item, a persisted query with no document, or a document this tokenizer does not follow. Only
 * 'read' is let through without the user; every other answer waits for it.
 */
function classifyGraphqlBody(body, { raw = false } = {}) {
  const text = body.toString('utf8').replace(/^\ufeff/, '');
  let documents;
  if (raw) {
    documents = [text];
  } else {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      return 'unknown';
    }
    const items = Array.isArray(parsed) ? parsed : [parsed];
    if (items.length === 0) return 'unknown';
    documents = [];
    for (const item of items) {
      // JSON.parse gives only plain objects here, so `instanceof` is enough; a string is asked
      // for by its tag because a primitive string has no prototype of its own to test.
      if (!(item instanceof Object) || Array.isArray(item)) return 'unknown';
      if (Object.prototype.toString.call(item.query) !== '[object String]') return 'unknown';
      documents.push(item.query);
    }
  }
  for (const document of documents) {
    const types = operationTypesOf(document);
    if (types === null) return 'unknown';
    if (types.has('mutation') || types.has('subscription')) return 'write';
  }
  return 'read';
}

/**
 * The body of a request, up to a limit. `complete` carries every byte; `prefix` is what was read
 * before the limit passed, with the rest still unread on the request; `failed` means the client
 * left. A classified read is forwarded from `body`; a held write keeps it for the forward that
 * follows the user's yes.
 */
function readRequestBody(request, limit) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      request.removeListener('data', onData);
      request.removeListener('end', onEnd);
      request.removeListener('error', onError);
      request.removeListener('aborted', onError);
      if (value.prefix) request.pause();
      resolve(value);
    };
    const onData = (chunk) => {
      size += chunk.length;
      chunks.push(chunk);
      if (size > limit) finish({ prefix: Buffer.concat(chunks) });
    };
    const onEnd = () => finish({ body: Buffer.concat(chunks) });
    const onError = () => finish({ failed: true });
    request.on('data', onData);
    request.on('end', onEnd);
    request.on('error', onError);
    request.on('aborted', onError);
  });
}

/**
 * One request, forwarded over a TLS connection the gatekeeper makes itself, to the address that
 * was checked when the tunnel was opened. The name is never resolved again.
 *
 * `buffered` is set when the body was already read to decide on it: `body` holds every byte and
 * the request is ended, `prefix` holds the bytes read before a limit with the rest still on the
 * request. Otherwise the request streams as it arrives, as a raw tunnel did. A complete body gets
 * the length it actually has: the gateway drops `transfer-encoding`, so a chunked request would
 * otherwise go out with no length at all.
 */
function forwardRequest(request, response, target, path, buffered) {
  const headers = {};
  for (const [name, value] of Object.entries(request.headers)) {
    const lower = name.toLowerCase();
    // `expect: 100-continue` would wait for an answer this request never sends: the body streams
    // as it is, and the upstream answers without the interim response.
    if (HOP_BY_HOP_HEADERS.has(lower) || lower === 'proxy-authorization' || lower === 'expect') continue;
    headers[lower] = value;
  }
  headers.host = request.headers.host || target.host;
  if (buffered?.body) headers['content-length'] = String(buffered.body.length);
  // A GraphQL document read as a query is ordinary traffic, as a GET is: its failures are not a
  // restriction the user has to look at, so `quiet` keeps them out of the journal.
  const notable = buffered?.quiet ? false : !SAFE_METHODS.has(String(request.method || '').toUpperCase());
  let given = false;
  const outgoing = https.request({
    hostname: target.host,
    port: target.port,
    method: request.method,
    path,
    headers,
    servername: target.host,
    lookup: fixedLookup(target.address, target.family),
    agent: UPSTREAM_AGENT,
  }, (answer) => {
    clearTimeout(connectTimer);
    const answerHeaders = {};
    for (const [name, value] of Object.entries(answer.headers)) {
      if (HOP_BY_HOP_HEADERS.has(name.toLowerCase())) continue;
      answerHeaders[name] = value;
    }
    response.writeHead(answer.statusCode || 502, answerHeaders);
    answer.on('error', () => { response.destroy(); });
    answer.pipe(response);
  });
  // A host that accepts nothing at all is given the same 15 seconds a raw tunnel had. Once the
  // connection is up the idle limit applies instead, so a long upload or a streaming answer is
  // bounded by silence and not by its total length.
  const connectTimer = setTimeout(() => {
    if (given) return;
    given = true;
    if (notable) record('corridor', target.host, target.port, 'failed:timeout', String(request.method || ''));
    if (!response.headersSent) refuseDecrypted(response, 504, UNREACHABLE, 'the upstream did not answer in time');
    else response.destroy();
    outgoing.destroy();
  }, CONNECT_TIMEOUT_MS);
  outgoing.on('socket', (socket) => {
    socket.once(socket.encrypted ? 'secureConnect' : 'connect', () => clearTimeout(connectTimer));
  });
  outgoing.setTimeout(TUNNEL_IDLE_MS, () => {
    given = true;
    if (notable) record('corridor', target.host, target.port, 'failed:timeout', String(request.method || ''));
    if (!response.headersSent) refuseDecrypted(response, 504, UNREACHABLE, 'the upstream did not answer in time');
    else response.destroy();
    outgoing.destroy();
  });
  outgoing.on('error', (error) => {
    if (given) return;
    given = true;
    const code = String(error.code || 'error').slice(0, 32);
    // Allowed, and the connection out did not happen. Only a write is worth the ring space here;
    // a read that failed is not a restriction the user has to look at.
    if (notable) record('corridor', target.host, target.port, `failed:${code}`, String(request.method || ''));
    if (!response.headersSent) refuseDecrypted(response, 502, UNREACHABLE, 'the upstream did not answer');
    else response.destroy();
  });
  response.on('close', () => {
    if (!response.writableFinished) outgoing.destroy();
  });
  writeForwardedBody(outgoing, request, buffered);
}

/**
 * Sends the body a forward has left to send. Without a buffer the request streams as it arrived;
 * `body` was read whole for classification and nothing is left on the request; `prefix` holds what
 * a limit read, with the rest still coming. Kept apart so the byte order has its own test.
 */
function writeForwardedBody(outgoing, request, buffered) {
  if (!buffered) {
    request.pipe(outgoing);
    return;
  }
  if (buffered.body) {
    outgoing.end(buffered.body);
    return;
  }
  if (buffered.prefix.length > 0) outgoing.write(buffered.prefix);
  request.pipe(outgoing);
}

// ---------------------------------------------------------------------------------------------
// Waiting for the user
//
// A write the user has not approved does not fail: it waits, its body unread and its socket held,
// until the answer comes or the limit passes. The host learns of it from `GET /pending`, shows a
// prompt, and answers `POST /approvals`. Approving the method for the destination from the grant
// dialog releases every wait for it, so both ways of saying yes do the same thing.
// ---------------------------------------------------------------------------------------------

// What the user is approving, in one line: the destination, the port the corridor opened, and the
// path and query the space wrote. Bounded like every other string that leaves this process, so a
// query of a megabyte cannot travel to the host.
const MAX_APPROVAL_URL_CHARACTERS = 2048;

const approvalUrlOf = (entry) => {
  const port = entry.target.port === 443 ? '' : `:${entry.target.port}`;
  const url = `https://${entry.target.host}${port}${entry.path}`;
  return url.length > MAX_APPROVAL_URL_CHARACTERS ? `${url.slice(0, MAX_APPROVAL_URL_CHARACTERS)}…` : url;
};

// A write rule's path: the request's path without its query or fragment, exactly as the space wrote
// it. Never normalized: `/a/../b`, `/%61` and `/a/` are other paths than `/a`, so a rule never covers
// more than the user saw, and a path the space dressed up to look alike asks again.
const MAX_RULE_PATH_CHARACTERS = 2048;
const RULE_PATH = /^\/[\x21\x22\x24-\x3e\x40-\x7e]*$/;
const rulePathOf = (path) => String(path ?? '').split(/[?#]/)[0];
const isRulePath = (value) => value !== null && value !== undefined && String(value) === value && value.length <= MAX_RULE_PATH_CHARACTERS && RULE_PATH.test(value);

const approvalOf = (entry) => {
  const path = rulePathOf(entry.path);
  const approval = {
    id: entry.id,
    host: entry.target.host,
    port: entry.target.port,
    method: entry.method,
    url: approvalUrlOf(entry),
    expiresAt: entry.expiresAt,
  };
  // What an answer for this path would name; absent when the path cannot be a rule.
  if (isRulePath(path)) approval.path = path;
  return approval;
};

/** The waits a host that last saw `since` has not heard of. Ids only grow while this process lives. */
const approvalsSince = (since) => Array.from(pendingApprovals.values())
  .filter((entry) => entry.id > since)
  .map(approvalOf);

function answerApprovals(response, since) {
  answerJson(response, 200, { since: Math.max(approvalSeq, since), requests: approvalsSince(since) });
}

function finishWaiter(waiter) {
  if (!approvalWaiters.delete(waiter)) return;
  clearTimeout(waiter.timer);
  if (!waiter.response.writableEnded && !waiter.response.destroyed) answerApprovals(waiter.response, waiter.since);
}

/** Tells every waiting host that something it has not heard of is there. */
function wakeApprovalWaiters() {
  for (const waiter of Array.from(approvalWaiters)) {
    if (approvalsSince(waiter.since).length > 0) finishWaiter(waiter);
  }
}

/** The rules of one destination in a write list, made when missing. */
const rulesOf = (list, host) => {
  let rules = list.get(host);
  if (!rules) {
    rules = { methods: new Set(), paths: new Map() };
    list.set(host, rules);
  }
  return rules;
};

/**
 * What the user's standing answers say about one write: `allow`, `deny`, or null when nothing
 * stands and the write asks. The more specific answer wins, a path before its host, and on the
 * same level a standing denial before an approval. A refusal that ends with the turn is weaker
 * than either standing answer: the user making "Always allow" for the same rule is a newer
 * decision, and it must be able to lift what they refused once.
 */
function writeVerdict(host, requestPath, method) {
  const path = rulePathOf(requestPath);
  const denied = deniedWrites.get(host);
  const turned = Date.now() < turnDenialsUntil ? turnDenials.get(host) : null;
  const allowed = writeAccess.get(host);
  if (denied?.paths.get(path)?.has(method)) return 'deny';
  if (allowed?.paths.get(path)?.has(method)) return 'allow';
  if (turned?.paths.get(path)?.has(method)) return 'deny';
  if (denied?.methods.has(method)) return 'deny';
  if (allowed?.methods.has(method)) return 'allow';
  if (turned?.methods.has(method)) return 'deny';
  return null;
}

/** A write list as the host reads it back: a host-wide entry and one per path, sorted. */
const writeEntriesFrom = (list) => Array.from(list).flatMap(([host, rules]) => [
  ...(rules.methods.size > 0 ? [{ host, methods: Array.from(rules.methods).sort() }] : []),
  ...Array.from(rules.paths, ([path, methods]) => ({ host, path, methods: Array.from(methods).sort() })),
]);

/** A destination and method the user refused, for the host or one path of it, in either write
 * list. A destination at the cap makes room for the answer just given: the newest answer is the
 * user's, and refusing to keep it would deny a write without remembering the decision. */
function rememberDeniedWrite(list, host, method, path = null) {
  if (!list.has(host) && list.size >= MAX_WRITE_ENTRIES) {
    list.delete(list.keys().next().value);
  }
  const rules = rulesOf(list, host);
  if (path === null) {
    rules.methods.add(method);
    return;
  }
  const methods = rules.paths.get(path) ?? new Set();
  methods.add(method);
  rules.paths.set(path, methods);
}

/**
 * The outcome of a wait: the request goes out, or it is refused with the reason. `rememberDeny` is
 * set only for the user's standing answer, `turnDeny` for a refusal that ends with the chat's
 * turn: `host` or `path` says what the refusal stands for. A wait that ran out of time is refused,
 * not decided, and must not silence that destination for the rest of the process. A path that
 * cannot be a rule is remembered for the host, the stricter side.
 */
function settleApproval(entry, allow, { rememberDeny = null, turnDeny = null, message = UNANSWERED } = {}) {
  if (pendingApprovals.get(entry.id) !== entry) return;
  pendingApprovals.delete(entry.id);
  clearTimeout(entry.timer);
  if (allow) {
    record('corridor', entry.target.host, entry.target.port, 'allow', entry.method);
    forwardRequest(entry.request, entry.response, entry.target, entry.path, entry.buffered);
    return;
  }
  const path = rulePathOf(entry.path);
  const rulePath = (scope) => (scope === 'path' && isRulePath(path) ? path : null);
  // The answer stands for the destination: the next identical write is refused without asking.
  if (rememberDeny !== null) rememberDeniedWrite(deniedWrites, entry.target.host, entry.method, rulePath(rememberDeny));
  // And this one only until the turn ends: a retry inside the same turn meets this, not a prompt.
  if (turnDeny !== null) {
    // A path the space chose but this gatekeeper cannot store is not widened to the host: the
    // refusal covers this write alone, which is what the prompt said it covers.
    const turnedPath = rulePath(turnDeny);
    if (turnDeny === 'host' || turnedPath !== null) {
      rememberDeniedWrite(turnDenials, entry.target.host, entry.method, turnedPath);
      turnDenialsUntil = Date.now() + TURN_DENIAL_MS;
    }
  }
  // Nothing of a refused write has been read: a request the user did not allow is not stored.
  entry.request.resume();
  record('corridor', entry.target.host, entry.target.port, 'deny:method', entry.method);
  refuseDecrypted(entry.response, 403, REFUSED, message);
}

function holdForApproval(request, response, target, path, method, buffered) {
  if (pendingApprovals.size >= MAX_PENDING_APPROVALS) {
    request.resume();
    record('corridor', target.host, target.port, 'deny:too-many-approvals', method);
    refuseDecrypted(response, 403, REFUSED, 'too many writes are already waiting for the user');
    return;
  }
  approvalSeq += 1;
  const entry = {
    id: approvalSeq,
    method,
    target,
    path,
    request,
    response,
    buffered,
    expiresAt: new Date(Date.now() + APPROVAL_TIMEOUT_MS).toISOString(),
    timer: null,
  };
  entry.timer = setTimeout(() => settleApproval(entry, false), APPROVAL_TIMEOUT_MS);
  pendingApprovals.set(entry.id, entry);
  // A space that leaves takes its wait with it; the place is given back by the response's own close.
  response.on('close', () => {
    if (pendingApprovals.delete(entry.id)) clearTimeout(entry.timer);
  });
  wakeApprovalWaiters();
}

/**
 * A GraphQL write that the user has not approved: read it (bounded), and send it on only when the
 * whole document reads. A body past the limit is held, not refused: the bytes read travel with
 * the wait and the rest streams after them on the user's yes.
 *
 * `denied` is the destination and method already refused: a document that still reads is
 * ordinary traffic and goes out, while a mutation or an unreadable body is refused at once
 * without asking again. A denial is about writes, not about reads that happen to use POST.
 */
function decideGraphqlRequest(request, response, target, path, method, { denied = false } = {}) {
  readRequestBody(request, GRAPHQL_BODY_LIMIT).then((read) => {
    if (read.failed) {
      request.resume();
      record('corridor', target.host, target.port, 'deny:unreadable-request', method);
      refuseDecrypted(response, 400, REFUSED, 'the gatekeeper could not read this request');
      return;
    }
    const verdict = read.body ? classifyGraphqlBody(read.body, { raw: isRawGraphqlRequest(request) }) : 'unknown';
    if (verdict === 'read') {
      forwardRequest(request, response, target, path, { body: read.body, quiet: true });
      return;
    }
    if (denied) {
      request.resume();
      noteStandingDenial(target.host, target.port, method);
      refuseDecrypted(response, 403, REFUSED, REFUSED_BY_USER);
      return;
    }
    if (read.body) {
      holdForApproval(request, response, target, path, method, { body: read.body });
      return;
    }
    holdForApproval(request, response, target, path, method, { prefix: read.prefix });
  }).catch(() => {
    if (!response.headersSent) refuseDecrypted(response, 502, UNREACHABLE, 'the gatekeeper could not serve this request');
    else response.destroy();
  });
}

/**
 * The host's answer for one wait. `{ status }` is what the control listener answers with. A
 * refusal stands unless `remember` is false, when the user denied this one write: for the wait's
 * exact path when `scope` is `path`, for the whole destination otherwise. A refusal the user did
 * not want to keep still stands for the rest of the turn, so the agent's retry meets it rather
 * than another prompt; `/turn-end` ends it.
 */
function decideApproval(body) {
  const id = Number(body.id);
  if (!Number.isSafeInteger(id) || id <= 0) return { status: 400, error: 'id is the number the gatekeeper gave the wait' };
  const entry = pendingApprovals.get(id);
  if (!entry) return { status: 404, error: 'no write is waiting with that id; it was answered or its time passed' };
  const refused = body.allow !== true;
  const scope = body.scope === 'path' ? 'path' : 'host';
  const remembers = refused && body.remember !== false;
  const thisTurnOnly = refused && body.remember === false;
  settleApproval(entry, body.allow === true, {
    rememberDeny: remembers ? scope : null,
    turnDeny: thisTurnOnly ? scope : null,
    message: REFUSED_BY_USER,
  });
  // A refusal for this turn covers writes already waiting for the same destination and method.
  if (thisTurnOnly) settleDecidedWaits();
  return { status: 200 };
}

/**
 * A request that came through the corridor's TLS. Everything outside SAFE_METHODS is a write here,
 * and a write passes only when the user approved that method for this destination. The journal
 * records the method beside the host, so the dialog can offer the one the agent tried.
 */
function serveDecryptedRequest(request, response) {
  const target = request.socket?.openchamberTarget;
  if (!target) {
    request.resume();
    refuseDecrypted(response, 502, UNREACHABLE, 'the gatekeeper lost the destination of this connection');
    return;
  }
  const method = String(request.method || '').toUpperCase();
  if (!METHOD_PATTERN.test(method)) {
    request.resume();
    record('corridor', target.host, target.port, 'deny:method', method.slice(0, 20));
    refuseDecrypted(response, 403, REFUSED, 'the gatekeeper does not take this method');
    return;
  }
  if (requestHostOf(request, target) !== target.host) {
    // The tunnel was opened for one name. A different `Host`, or an absolute URL naming another
    // host, would use that name's route to reach a service the user never approved.
    request.resume();
    record('corridor', target.host, target.port, 'deny:host-mismatch', method);
    refuseDecrypted(response, 403, REFUSED, 'the gatekeeper does not take this destination');
    return;
  }
  const { path, mismatch } = requestPathOf(request, target);
  if (mismatch) {
    request.resume();
    record('corridor', target.host, target.port, 'deny:host-mismatch', method);
    refuseDecrypted(response, 403, REFUSED, 'the gatekeeper does not take this destination');
    return;
  }
  if (SAFE_METHODS.has(method)) {
    forwardRequest(request, response, target, path);
    return;
  }
  const verdict = writeVerdict(target.host, path, method);
  if (verdict === 'allow') {
    record('corridor', target.host, target.port, 'allow', method);
    forwardRequest(request, response, target, path);
    return;
  }
  // A method the user already denied there is refused at once: the answer stands until cleared.
  // One record a minute for the destination: a retrying agent would otherwise fill the journal.
  if (verdict === 'deny') {
    // The denial covers writes there, not reads that arrive as one: a GraphQL document that
    // only queries is classified as usual and goes out; a mutation is refused without asking.
    if ((method === 'POST' || method === 'PUT') && isGraphqlRequest(request, path)) {
      decideGraphqlRequest(request, response, target, path, method, { denied: true });
      return;
    }
    request.resume();
    noteStandingDenial(target.host, target.port, method);
    refuseDecrypted(response, 403, REFUSED, REFUSED_BY_USER);
    return;
  }
  // The user chose an open internet whose writes go out on their own: no wait, no prompt.
  if (writePolicy === 'allow' && WRITABLE_METHODS.includes(method)) {
    record('corridor', target.host, target.port, 'allow', method);
    forwardRequest(request, response, target, path);
    return;
  }
  if (WRITABLE_METHODS.includes(method)) {
    // A GraphQL document that can only read is a GET in a POST's clothing (GitHub and most
    // servers take reads this way), so it is read and sent on; a mutation, or anything the
    // classifier cannot read with certainty, still waits for the user.
    if ((method === 'POST' || method === 'PUT') && isGraphqlRequest(request, path)) {
      decideGraphqlRequest(request, response, target, path, method);
      return;
    }
    // The user decides, and the request waits for the answer: see "Waiting for the user".
    holdForApproval(request, response, target, path, method);
    return;
  }
  // A method the user could not approve even if asked: there is nothing to wait for.
  request.resume();
  record('corridor', target.host, target.port, 'deny:method', method);
  refuseDecrypted(response, 403, REFUSED, 'the gatekeeper does not take this method');
}

const decrypted = http.createServer({ maxHeaderSize: MAX_HEADER_BYTES }, (request, response) => {
  try {
    serveDecryptedRequest(request, response);
  } catch {
    refuseDecrypted(response, 502, UNREACHABLE, 'the gatekeeper could not serve this request');
  }
});
decrypted.headersTimeout = HEADERS_TIMEOUT_MS;
// A body may take as long as it takes, as a raw tunnel allowed. Silence is bounded by the same
// idle limit the socket had before a request: `requestTimeout` disables the whole-exchange
// deadline, and `timeout` is re-applied by the HTTP server at the start of every request, so a
// keep-alive connection is not left with the server default of no timeout.
decrypted.timeout = TUNNEL_IDLE_MS;
decrypted.requestTimeout = 0;
decrypted.on('clientError', (error, socket) => {
  // A client that leaves in the middle of a body is ordinary traffic, not a probe. That reset is
  // already journalled as `failed:<code>` for a write, and a second blank `deny:unreadable-request`
  // would put an empty row in the user's blocked list after every cancelled upload.
  const code = String(error?.code ?? '');
  if (code !== 'ECONNRESET' && code !== 'EPIPE' && code !== 'ERR_STREAM_PREMATURE_CLOSE') {
    noteRefusedTraffic('corridor', 'deny:unreadable-request');
  }
  if (!socket.destroyed && socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  socket.destroy();
});
decrypted.on('upgrade', (request, socket) => {
  // A WebSocket is a GET on the wire and can change everything after it. The method policy
  // cannot see those frames, so this corridor does not carry them.
  record('corridor', request.socket?.openchamberTarget?.host ?? '', request.socket?.openchamberTarget?.port ?? 0, 'deny:upgrade', String(request.method || ''));
  if (!socket.destroyed && socket.writable) socket.end('HTTP/1.1 403 Forbidden\r\nx-gatekeeper-reason: refused\r\nConnection: close\r\n\r\n');
});

/** Anything but CONNECT. Stage 0 proved that OpenCode, curl, npm and git all use CONNECT for https. */
function refusePlainProxy(request, response) {
  let host = '';
  try {
    host = normalizeName(new URL(request.url).hostname);
  } catch {
    host = '';
  }
  record('corridor', host, 0, 'deny:not-connect');
  response.writeHead(403, { 'content-type': 'application/json' });
  response.end('{"error":"the corridor takes CONNECT only"}');
}

// ---------------------------------------------------------------------------------------------
// Window
//
// Built for any upstream and any header name, because git over https and a private npm registry
// go through the same mechanism later. Only the model-provider path is wired and tested here.
// ---------------------------------------------------------------------------------------------

const WINDOW_PATH = /^\/model\/([A-Za-z0-9._-]{1,64})([/?][^]*)?$/;

/**
 * Does the rest of a window path walk out of its grant?
 *
 * A grant opens a place on a host, not the host, so a rest that climbs above it has to go. A
 * literal `..` is the least of it: the rest reaches the upstream verbatim, and a server that
 * decodes before it resolves reads `%2e%2e`, `.%2e`, `..%2f`, `..%5c` and `..;` as the same
 * climb. Refusing every rest carrying a `%` would be simpler and would be wrong, because a
 * scoped npm package is fetched as `/@scope%2fname` and that window is half the reason this
 * rule exists. So the rest is decoded until decoding changes nothing, and each round is split on
 * every separator a server might honour before `..` is compared. A rest that will not decode is
 * refused: nothing legitimate sends a `%` that is not an escape, and the alternative is guessing
 * which of two readings the upstream will take.
 *
 * Decoding to a fixed point rather than a fixed number of rounds, because a bound on the rounds
 * is a hole at the round after it: at three, a four-times-encoded `..` went through verbatim.
 * The loop ends on its own — every round that changes anything replaces at least one three-byte
 * escape with one byte, so the rest strictly shortens until a round decodes to itself.
 *
 * Not an escape today — a grant's upstream and its key belong together — and a trap left armed
 * for the stage that puts git and a private registry behind the same window.
 */
function walksOutOfGrant(rest) {
  let form = String(rest ?? '');
  for (;;) {
    if (form.split(/[/\\;?#]/).includes('..')) return true;
    if (!form.includes('%')) return false;
    let decoded;
    try {
      decoded = decodeURIComponent(form);
    } catch {
      return true;
    }
    if (decoded === form) return false;
    form = decoded;
  }
}

// The window's own sockets out, capped the same way its sockets in are. Requests past the cap
// wait for a socket instead of opening one, and the listener's own cap bounds how many can wait.
const agentOptions = { keepAlive: false, maxSockets: MAX_WINDOW_CONNECTIONS, maxTotalSockets: MAX_WINDOW_CONNECTIONS };
const windowAgents = { 'http:': new http.Agent(agentOptions), 'https:': new https.Agent(agentOptions) };

const answerJson = (response, status, body) => {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
};

/**
 * The gatekeeper's own listeners are not an upstream. A grant is the host's decision, and the
 * user's private network is a legitimate place for one, so only this refusal stands in the way.
 *
 * Every address this container has, not only loopback: the corridor and the window listen on
 * the gatekeeper's address on the inner network, and a grant pointing there, or at any other
 * address of its own, would feed the window into itself until its 64 sockets out were gone.
 */
const ownListenerPorts = new Set([Number(corridorPort), Number(windowPort), Number(controlPort)]);
const ownAddresses = new Set(Object.values(os.networkInterfaces())
  .flat()
  .filter(Boolean)
  .map((entry) => String(entry.address).toLowerCase()));

function isLoopback(address) {
  const v4 = parseIPv4(address);
  if (v4) return v4[0] === 127;
  const v6 = parseIPv6(address);
  if (!v6) return false;
  const embedded = embeddedIPv4(v6);
  if (embedded) return embedded[0] === 127;
  return v6.slice(0, 15).every((byte) => byte === 0) && v6[15] === 1;
}

const isOwnListener = (address, port) => (isLoopback(address) || ownAddresses.has(String(address).toLowerCase())) && ownListenerPorts.has(Number(port));

async function serveWindow(request, response) {
  request.on('error', () => {});
  // The space fetches the certificate the corridor signs with, before its own server starts. It
  // is public, and the path is reserved: no grant id may be `ca`.
  if (request.method === 'GET' && (request.url === '/ca' || request.url === '/ca.pem')) {
    if (!authorityCertificatePem) {
      answerJson(response, 503, { error: 'the gatekeeper has no certificate yet' });
      return;
    }
    response.writeHead(200, { 'content-type': 'application/x-pem-file', 'cache-control': 'no-store' });
    response.end(authorityCertificatePem);
    return;
  }
  const match = WINDOW_PATH.exec(request.url || '');
  if (match && walksOutOfGrant(match[2] || '')) {
    // Its own decision, because the journal is the user's only view: "tried to walk out of its
    // path" and "guessed a grant id" are different things and should not read as one. The answer
    // to the space stays identical to the one below, so it cannot sort a real id from a wrong one.
    record('window', 'grant-path', 0, 'deny:path-walks-out');
    answerJson(response, 403, { error: 'no such grant' });
    return;
  }
  const grant = match ? grants.get(match[1]) : null;
  if (!grant) {
    // The id is not a secret, and the journal keeps no path, so the destination is all it says.
    record('window', 'unknown-grant', 0, 'deny:no-grant');
    answerJson(response, 403, { error: 'no such grant' });
    return;
  }

  const upstream = new URL(grant.upstream);
  const port = Number(upstream.port || (upstream.protocol === 'https:' ? 443 : 80));
  if (ALWAYS_REFUSED.includes(normalizeName(upstream.hostname))) {
    record('window', normalizeName(upstream.hostname), port, 'deny:always-refused');
    answerJson(response, 403, { error: 'refused destination' });
    return;
  }
  const resolved = await lookupAll(upstream.hostname);
  if (resolved.addresses.length === 0) {
    record('window', normalizeName(upstream.hostname), port, `deny:unresolved:${resolved.reason}`);
    answerJson(response, 502, { error: 'the upstream of this grant does not resolve' });
    return;
  }
  const chosen = chooseAddress(resolved.addresses);
  if (isOwnListener(chosen.address, port)) {
    record('window', normalizeName(upstream.hostname), port, 'deny:own-listener');
    answerJson(response, 403, { error: 'refused destination' });
    return;
  }

  // Whatever the space sent as credentials goes, and the grant's own header takes its place. A
  // grant without a secret, an opened domain, adds nothing: the upstream sees the request as the
  // space made it, less the credential headers. The grant's own extra headers are set last, over
  // whatever the space sent under their names (Node lowercases and joins incoming names, so the
  // names match), and the space can neither read nor override them.
  const headers = { ...request.headers };
  for (const name of Object.keys(headers)) {
    const lower = name.toLowerCase();
    if (['authorization', 'x-api-key', 'proxy-authorization'].includes(lower) || lower === grant.header) delete headers[name];
  }
  headers.host = upstream.host;
  if (grant.secret !== null) {
    headers[grant.header] = grant.header === 'authorization' ? `Bearer ${grant.secret}` : grant.secret;
  }
  Object.assign(headers, grant.headers);

  record('window', normalizeName(upstream.hostname), port, 'allow');
  const transport = upstream.protocol === 'https:' ? https : http;
  const outgoing = transport.request({
    hostname: upstream.hostname,
    port,
    method: request.method,
    path: upstream.pathname.replace(/\/$/, '') + (match[2] || ''),
    headers,
    agent: windowAgents[upstream.protocol],
    // The address was checked a moment ago, and this is the address the request goes to.
    lookup: fixedLookup(chosen.address, chosen.family),
  }, (answer) => {
    response.writeHead(answer.statusCode || 502, answer.headers);
    answer.on('error', () => { response.destroy(); });
    answer.pipe(response);
  });
  // The deadline covers the whole exchange, silence by silence. `given` keeps the record to one
  // per request: the destroy below makes the socket error, and that is this timeout, not news.
  let given = false;
  outgoing.setTimeout(WINDOW_IDLE_MS, () => {
    given = true;
    record('window', normalizeName(upstream.hostname), port, 'failed:timeout');
    if (!response.headersSent) answerJson(response, 504, { error: 'the upstream did not answer in time' });
    else response.destroy();
    outgoing.destroy();
  });
  outgoing.on('error', (error) => {
    if (given) return;
    given = true;
    // Allowed, and the connection out did not happen, which is not the same as a refusal.
    // The message can hold the upstream's name, never a header or a body.
    const code = String(error.code || 'error').slice(0, 32);
    record('window', normalizeName(upstream.hostname), port, `failed:${code}`);
    if (!response.headersSent) answerJson(response, 502, { error: 'the upstream did not answer' });
    else response.destroy();
  });
  response.on('close', () => {
    // A finished answer has already ended this socket; destroying then would be the same defect
    // the corridor had. This is for an answer that stopped short, where the client went away.
    if (!response.writableFinished) outgoing.destroy();
  });
  request.pipe(outgoing);
}

// ---------------------------------------------------------------------------------------------
// Control, on loopback only
// ---------------------------------------------------------------------------------------------

const readBody = (request) => new Promise((resolve) => {
  let text = '';
  let tooLarge = false;
  request.on('data', (chunk) => {
    if (tooLarge) return;
    text += chunk;
    if (text.length > CONTROL_BODY_BYTES) {
      tooLarge = true;
      text = '';
    }
  });
  request.on('error', () => resolve(null));
  request.on('end', () => resolve(tooLarge ? null : text));
});

/**
 * One field of a control request as text. A name, a header name and a secret are text; a list,
 * an object or nothing at all is none of those, and comes out as the empty string that every
 * check below refuses.
 */
const asText = (value) => (value === null || value === undefined || value instanceof Object ? '' : String(value));

function setNetwork(body) {
  if (body.mode !== 'allowlist' && body.mode !== 'open') return 'mode is "allowlist" or "open"';
  const domains = Array.isArray(body.domains) ? body.domains : [];
  if (domains.length > MAX_ALLOWED_DOMAINS) return `at most ${MAX_ALLOWED_DOMAINS} domains`;
  const names = domains.map((domain) => normalizeName(asText(domain)));
  // The same rule a target passes, so the host never puts an entry on the list that the corridor
  // would always refuse. An address on it would be a way around the ranges this refuses anyway.
  const wrong = names.find((name) => !isDomainName(name) || parseIPv4(name) || parseIPv6(name));
  if (wrong !== undefined) return `'${wrong}' is not a domain name. The allowlist holds exact names, no wildcards and no addresses.`;
  if (body.writes !== undefined && body.writes !== 'ask' && body.writes !== 'allow') return 'writes is "ask" or "allow"';
  networkMode = body.mode;
  allowedDomains = new Set(names);
  writePolicy = body.writes === 'allow' ? 'allow' : 'ask';
  return null;
}

/**
 * The methods the user approved or denied, per destination and optionally per exact path. A name
 * and the four methods that can change something out there; anything else is refused, and a list
 * that is not one is never read as an empty one. The host sends the whole list every time, so a
 * destination the user has not decided cannot linger from an earlier request.
 */
/** A `{ entries }` body as a map of host to rules, or an error naming what is wrong with it. */
function writeEntriesOf(body) {
  const entries = Array.isArray(body.entries) ? body.entries : null;
  if (entries === null) return { problem: 'entries must be a list of { host, methods, path? }' };
  if (entries.length > MAX_WRITE_ENTRIES) return { problem: `at most ${MAX_WRITE_ENTRIES} rules` };
  const next = new Map();
  for (const entry of entries) {
    if (!(entry instanceof Object) || Array.isArray(entry)) return { problem: 'a destination is an object with a host and methods' };
    const name = normalizeName(asText(entry.host));
    if (!isDomainName(name) || parseIPv4(name) || parseIPv6(name)) {
      return { problem: `'${name}' is not a domain name. A write rule names an exact host, no wildcard and no address.` };
    }
    const methods = Array.isArray(entry.methods) ? entry.methods.map((method) => String(method).toUpperCase()) : null;
    if (methods === null || methods.length === 0 || methods.length > WRITABLE_METHODS.length) {
      return { problem: `the methods of '${name}' are one to ${WRITABLE_METHODS.length} of ${WRITABLE_METHODS.join(', ')}` };
    }
    const wrong = methods.find((method) => !WRITABLE_METHODS.includes(method));
    if (wrong !== undefined) return { problem: `'${wrong}' is not a method a user can decide. The methods are ${WRITABLE_METHODS.join(', ')}.` };
    if (entry.path !== undefined && entry.path !== null && !isRulePath(entry.path)) {
      return { problem: `the path of '${name}' is a path as a request writes it: a /, no query, no fragment, no space, at most ${MAX_RULE_PATH_CHARACTERS} characters` };
    }
    const rules = rulesOf(next, name);
    const known = entry.path === undefined || entry.path === null ? rules.methods : (rules.paths.get(entry.path) ?? new Set());
    for (const method of methods) known.add(method);
    if (known !== rules.methods) rules.paths.set(entry.path, known);
  }
  return { next };
}

/** The waits the standing answers now decide: an approval sends them, a denial refuses them. */
function settleDecidedWaits() {
  for (const entry of Array.from(pendingApprovals.values())) {
    const verdict = writeVerdict(entry.target.host, entry.path, entry.method);
    if (verdict !== null) settleApproval(entry, verdict === 'allow', { message: REFUSED_BY_USER });
  }
}

function setWrites(body) {
  const parsed = writeEntriesOf(body);
  if (parsed.problem) return parsed.problem;
  writeAccess = parsed.next;
  // A standing approval from the dialog is an answer too: every wait it covers goes out now.
  settleDecidedWaits();
  return null;
}

function setDenials(body) {
  const parsed = writeEntriesOf(body);
  if (parsed.problem) return parsed.problem;
  deniedWrites = parsed.next;
  // The answer now covers waits that were opened before it: they are refused, not asked again.
  settleDecidedWaits();
  return null;
}

/**
 * The extra headers of a grant as the window will set them, lowercased, or a refusal: text values
 * under header names that the window does not own itself, at most MAX_GRANT_HEADERS of them.
 */
function grantHeadersOf(value) {
  if (value === undefined) return { headers: {} };
  if (value === null || !(value instanceof Object) || Array.isArray(value)) return { refusal: 'the headers of a grant are an object of names to text' };
  const entries = Object.entries(value);
  if (entries.length > MAX_GRANT_HEADERS) return { refusal: `at most ${MAX_GRANT_HEADERS} headers on a grant` };
  const headers = {};
  for (const [name, text] of entries) {
    const lower = name.toLowerCase();
    if (!HEADER_NAME_PATTERN.test(lower)) return { refusal: 'a header name is 1 to 64 letters, digits or dashes' };
    if (RESERVED_HEADER_NAMES.includes(lower)) return { refusal: `the header '${lower}' is the window's own` };
    const asString = asText(text);
    if (asString.length === 0 || asString.length > MAX_SECRET_LENGTH) return { refusal: 'a header of a grant is text, 1 to 8192 characters' };
    // Node's own rule for a header value; one it refuses would break every request through this window after the grant said yes.
    if (!HEADER_VALUE_PATTERN.test(asString)) return { refusal: 'a header of a grant is Latin-1 text without line breaks' };
    headers[lower] = asString;
  }
  return { headers };
}

/**
 * A grant with a secret names the header that carries it; a grant without one, an opened domain,
 * names no header and the window adds nothing. A body with a header and no secret, or a secret
 * and no header, is refused: either the grant hides a credential or it does not. Either kind may
 * carry `headers`, the provider's own, set on every request beside the credential.
 */
function addGrant(body) {
  const id = asText(body.id);
  if (!GRANT_ID_PATTERN.test(id)) return 'a grant id is 1 to 64 letters, digits, dots, dashes or underscores';
  const withSecret = body.secret !== undefined || body.header !== undefined;
  const header = withSecret ? asText(body.header).toLowerCase() : null;
  const secret = withSecret ? asText(body.secret) : null;
  if (withSecret && !HEADER_NAME_PATTERN.test(header)) return 'a header name is 1 to 64 letters, digits or dashes';
  if (withSecret && (secret.length === 0 || secret.length > MAX_SECRET_LENGTH)) return 'a grant with a header needs a secret';
  const extra = grantHeadersOf(body.headers);
  if (extra.refusal) return extra.refusal;
  if (header !== null && header in extra.headers) return `the header '${header}' carries the secret and cannot be set twice`;
  let upstream;
  try {
    upstream = new URL(asText(body.upstream));
  } catch {
    return 'the upstream of a grant is a URL';
  }
  if (upstream.protocol !== 'http:' && upstream.protocol !== 'https:') return 'the upstream of a grant is http or https';
  grants.set(id, { upstream: upstream.toString(), header, secret, headers: extra.headers });
  return null;
}

async function serveControl(request, response) {
  request.on('error', () => {});
  const path = String(request.url || '').split('?')[0];
  if (request.method === 'GET' && path === '/health') {
    answerJson(response, 200, { ready: true, mode: networkMode, domains: allowedDomains.size, grants: grants.size });
    return;
  }
  if (request.method === 'GET' && path === '/policy') {
    // What the host last said, so it can tell a gatekeeper that forgot from one that remembers.
    // Ids and names only: a secret is never read back, not even by the host.
    answerJson(response, 200, {
      mode: networkMode,
      domains: Array.from(allowedDomains),
      grants: Array.from(grants.keys()),
      writes: writeEntriesFrom(writeAccess),
      denials: writeEntriesFrom(deniedWrites),
      // This program reads a path in a write rule. One from before would read such a rule as one
      // for the whole host, so the host sends paths only where this says so.
      pathRules: true,
    });
    return;
  }
  if (request.method === 'GET' && path === '/ca') {
    // The certificate the space trusts. It is public: only the gatekeeper's memory holds the key.
    if (!authorityCertificatePem) {
      answerJson(response, 503, { error: 'the gatekeeper has no certificate yet' });
      return;
    }
    response.writeHead(200, { 'content-type': 'application/x-pem-file', 'cache-control': 'no-store' });
    response.end(authorityCertificatePem);
    return;
  }
  if (request.method === 'GET' && path === '/pending') {
    // A long poll: the host waits here for a write that needs the user, and is answered the moment
    // one appears, or when the wait it asked for ends. `since` is the highest id it has seen.
    const url = new URL(request.url || '/', 'http://127.0.0.1');
    const since = Number(url.searchParams.get('since'));
    const waitMs = Number(url.searchParams.get('wait'));
    const from = Number.isSafeInteger(since) && since > 0 ? since : 0;
    if (approvalsSince(from).length > 0 || !(waitMs > 0)) {
      answerApprovals(response, from);
      return;
    }
    const waiter = { response, since: from, timer: null };
    waiter.timer = setTimeout(() => finishWaiter(waiter), Math.min(waitMs, 30_000));
    approvalWaiters.add(waiter);
    response.on('close', () => {
      clearTimeout(waiter.timer);
      approvalWaiters.delete(waiter);
    });
    return;
  }
  if (request.method === 'GET' && path === '/journal') {
    // Since when: the journal is memory only, so the host says that nothing older exists.
    answerJson(response, 200, { records: journal.slice(), dropped: journalDropped, since: STARTED_AT });
    return;
  }
  if (request.method !== 'POST' || (path !== '/network' && path !== '/grants' && path !== '/writes' && path !== '/denials' && path !== '/approvals' && path !== '/turn-end')) {
    answerJson(response, 404, { error: 'no such control endpoint' });
    return;
  }
  const text = await readBody(request);
  let body = null;
  try {
    body = JSON.parse(text ?? '');
  } catch {
    answerJson(response, 400, { error: 'the body is not JSON' });
    return;
  }
  if (!(body instanceof Object) || Array.isArray(body)) {
    answerJson(response, 400, { error: 'the body is not an object' });
    return;
  }
  if (path === '/approvals') {
    const decision = decideApproval(body);
    if (decision.error) answerJson(response, decision.status, { error: decision.error });
    else answerJson(response, 200, { ok: true });
    return;
  }
  if (path === '/turn-end') {
    // The chat's turn is over, so a refusal the user did not want to keep ends here: the next
    // turn asks again. A standing answer is untouched, and nothing waiting is affected.
    turnDenials = new Map();
    turnDenialsUntil = 0;
    answerJson(response, 200, { ok: true });
    return;
  }
  const problem = path === '/network' ? setNetwork(body)
    : path === '/writes' ? setWrites(body)
      : path === '/denials' ? setDenials(body)
        : addGrant(body);
  if (problem) answerJson(response, 400, { error: problem });
  else answerJson(response, 200, { ok: true });
}

// ---------------------------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------------------------

let listening = false;
const lastNote = new Map();

/**
 * Traffic that never reached a decision: a connection the socket cap refused, or a request the
 * HTTP parser threw out. Recorded at most once a minute per listener and per kind, because the
 * flood is the point of the record and 500 notes of it would erase everything else.
 */
/** A standing denial of one method at one destination, noted at most once a minute per pair. */
function noteStandingDenial(host, port, method) {
  const key = `${host}\u0000${method}`;
  const now = Date.now();
  const last = lastDenialNote.get(key) ?? 0;
  if (now - last < NOTE_INTERVAL_MS) return;
  lastDenialNote.set(key, now);
  record('corridor', host, port, 'deny:method', method);
}

function noteRefusedTraffic(listener, decision) {
  const key = `${listener}:${decision}`;
  const last = lastNote.get(key) ?? 0;
  if (Date.now() - last < NOTE_INTERVAL_MS) return;
  lastNote.set(key, Date.now());
  record(listener, '', 0, decision);
}

function makeServer(listener, maxConnections, handler) {
  const server = http.createServer({ maxHeaderSize: MAX_HEADER_BYTES }, handler);
  server.headersTimeout = HEADERS_TIMEOUT_MS;
  server.requestTimeout = REQUEST_TIMEOUT_MS;
  // Sockets, not requests. Without this the space can hold thousands of connections open in the
  // header window and have the process killed for its memory, which would take the journal too.
  server.maxConnections = maxConnections;
  server.on('drop', () => noteRefusedTraffic(listener, 'deny:too-many-connections'));
  // A client that sends nonsense gets an answer and its own socket destroyed, and no other client
  // notices. It is journalled the same way a refused connection is, rate-limited: a request the
  // parser threw out never reaches a decision, and without a record here a space could probe with
  // targets the parser rejects and leave the user's view of its attempts blind by construction.
  server.on('clientError', (error, socket) => {
    noteRefusedTraffic(listener, 'deny:unreadable-request');
    if (!socket.destroyed && socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    socket.destroy();
  });
  server.on('error', (error) => {
    // A port that cannot be taken must end the start. Afterwards, a failed accept is the
    // space's doing, for example by running the process out of file descriptors, and
    // ending the gatekeeper on that would be a denial of service it can trigger at will.
    console.error(`gatekeeper: listener error ${error.code || error.message}`);
    if (!listening) process.exit(1);
  });
  return server;
}

const corridor = makeServer('corridor', MAX_CORRIDOR_CONNECTIONS, refusePlainProxy);
corridor.on('connect', (request, socket, head) => {
  openTunnel(request, socket, head).catch(() => { socket.destroy(); });
});
const windowServer = makeServer('window', MAX_WINDOW_CONNECTIONS, (request, response) => {
  serveWindow(request, response).catch(() => {
    if (!response.headersSent) answerJson(response, 502, { error: 'the window could not serve this request' });
    else response.destroy();
  });
});
const control = makeServer('control', MAX_CONTROL_CONNECTIONS, (request, response) => {
  serveControl(request, response).catch(() => {
    if (!response.headersSent) answerJson(response, 500, { error: 'the control channel could not serve this request' });
    else response.destroy();
  });
});

const listen = (server, port, host) => new Promise((resolve) => { server.listen(Number(port), host, resolve); });

async function main() {
  // Here and not at the top: requiring this file from a test must not read the runner's argv.
  const bindHost = readBindHost(bindArgument);
  if (!bindHost || !corridorPort || !windowPort || !controlPort) {
    console.error('gatekeeper: arguments are <bind host> <corridor port> <window port> <control port>');
    process.exit(2);
  }
  try {
    // Before anything listens: a corridor that cannot make the certificate its space trusts has
    // no way to read a method, and failing to start is the safe answer.
    authority = createCertificateAuthority();
    authorityCertificatePem = authority.certificatePem;
  } catch {
    console.error('gatekeeper: could not create the certificate for its corridor');
    process.exit(2);
  }
  await listen(corridor, corridorPort, bindHost);
  await listen(windowServer, windowPort, bindHost);
  // Last, and on loopback only: an answer from here means all three are up.
  await listen(control, controlPort, CONTROL_HOST);
  listening = true;
  // Only now. A listener that cannot bind must still end the process.
  //
  // What this line may say is limited on purpose. An error's message can carry what the space
  // sent, a header value or a piece of a body among it, and the container log is not a place for
  // that. The name, the code and the frame where it happened say where to look without it.
  process.on('uncaughtException', (error) => {
    console.error(`gatekeeper: kept running after ${describeFailure(error)}`);
  });
  process.on('unhandledRejection', (reason) => {
    console.error(`gatekeeper: kept running after a rejected promise, ${describeFailure(reason)}`);
  });
  console.log(`gatekeeper: corridor ${corridorPort}, window ${windowPort}, control ${CONTROL_HOST}:${controlPort}`);
}

/** The kind of failure and where it happened, and nothing that came from outside. */
function describeFailure(error) {
  if (!(error instanceof Error)) return 'something that is not an error';
  const frame = String(error.stack ?? '').split('\n').find((line) => line.trim().startsWith('at ')) ?? '';
  return `${error.name}${error.code ? ` (${error.code})` : ''}${frame ? ` ${frame.trim()}` : ''}`;
}

// The container runs this file as its main module. A test can require it instead and call the
// rules directly, so every range and every target form is covered without a listener and without
// a switch that changes a decision.
if (require.main === module) {
  main();
} else {
  module.exports = { APPROVAL_TIMEOUT_MS, MAX_PENDING_APPROVALS, SAFE_METHODS, TUNNEL_IDLE_MS, WRITABLE_METHODS, addGrant, approvalsSince, chooseAddress, classifyGraphqlBody, createCertificateAuthority, decideApproval, guardTunnelIdle, holdForApproval, isBlockedAddress, isDomainName, issueCertificate, parseIPv4, parseIPv6, refuseTarget, setNetwork, setWrites, splitTarget, walksOutOfGrant, writeForwardedBody };
}
