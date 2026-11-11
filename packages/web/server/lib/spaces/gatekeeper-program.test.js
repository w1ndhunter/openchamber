// The gatekeeper's program, run with Node on this machine, the way tools-filler.test.js runs
// the filler. Everything here is a decision the program makes, read back from its own journal.
//
// The corridor refuses every address that leads back to a machine, so a tunnel that really
// carries bytes cannot be tested from here. The escape suite does that inside real containers.

import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import os from 'node:os';
import fs, { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { PassThrough, Readable } from 'node:stream';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

const PROGRAM = fileURLToPath(new URL('./gatekeeper-program.cjs', import.meta.url));
const SECRET = 'sk-the-real-key-the-space-never-sees';
// TEST-NET-3, reserved for documentation and not on our block list, so a decision can be `allow`
// without any connection ever being made.
const PUBLIC_ADDRESS = '203.0.113.7';

/**
 * The connection caps this gatekeeper runs with, and they are as small as the assertions allow.
 *
 * Small because a test has to exceed one, and a drop only happens when a connection is *accepted*
 * past the cap: a loaded machine accepts slowly while the kernel's backlog keeps completing
 * handshakes, so a flood of 300 clients against the production cap of 128 can leave every client
 * connected, nothing accepted past the cap, and the flood unrecorded. Measured that way with the
 * program stopped: 128 connected, no note, ever.
 *
 * And small because sockets are the scarce thing on a Windows host, where a closed port waits two
 * minutes in TIME_WAIT before it comes back. Beside the three live Docker files, which hold the
 * daemon for five to six minutes each, this file's worker died there. A flood proves "the cap
 * refuses beyond it, and the refusal is noted once" at four as well as at a hundred, so the whole
 * two loops that dominate this file now cost 124 sockets instead of 240: 60 for the refusals
 * that must outnumber the cap, against 144, and 64 across the three floods, against 96.
 *
 * The corridor's is the one that cannot go lower: the program waits on up to 16 refused clients
 * at once, and a cap at or under that would be filled by refusals alone, which is the opposite of
 * what the test beside it proves. 20 leaves room for the handshake in flight.
 *
 * The production numbers, 128, 64 and 8, are in the container command, which `docker.test.js`
 * asserts whole, so nothing here can raise them.
 */
const CAPS = { corridor: 20, window: 4, control: 4 };

/** An address of this machine that is not loopback, as a container's own address is not. */
const ownAddress = () => Object.values(os.networkInterfaces())
  .flat()
  .filter(Boolean)
  .map((entry) => entry.address)
  .find((address) => net.isIPv4(address) && !address.startsWith('127.')) ?? '127.0.0.1';

const freePort = () => new Promise((resolve) => {
  const server = net.createServer();
  server.listen(0, '127.0.0.1', () => {
    const { port } = server.address();
    server.close(() => resolve(port));
  });
});

/**
 * Starts the program on three free ports of 127.0.0.1 and waits for it to listen. A port from
 * `freePort()` is free only until another process takes it, and the suites run in parallel, so
 * a start that lost a port to someone else is repeated on new ones. Both pipes stay read: a
 * full stderr pipe blocks the child.
 */
const startGatekeeper = async (tail) => {
  for (let attempt = 1; ; attempt += 1) {
    const ports = { corridor: await freePort(), window: await freePort(), control: await freePort() };
    const child = spawn(process.execPath, [PROGRAM, '127.0.0.1', String(ports.corridor), String(ports.window), String(ports.control), ...tail], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const keep = (chunk) => { output = `${output}${chunk}`.slice(-4_000); };
    child.stdout.on('data', keep);
    child.stderr.on('data', keep);
    const ended = await new Promise((resolve, reject) => {
      const late = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`the gatekeeper did not start: ${output}`)); }, 10_000);
      child.stdout.on('data', (chunk) => { if (String(chunk).includes('gatekeeper:')) { clearTimeout(late); resolve(null); } });
      // `close`, not `exit`: by then both pipes are drained, so `output` holds the reason.
      child.once('close', (code, signal) => { clearTimeout(late); resolve(code ?? signal); });
    });
    if (ended === null) return { child, ports };
    if (attempt === 3 || !output.includes('EADDRINUSE')) throw new Error(`the gatekeeper ended with ${ended}: ${output}`);
  }
};

describe('gatekeeper program', () => {
  let child;
  let ports;
  let upstream;
  let upstreamPort;
  let seen = [];

  // Every socket and every request this file opens, so that a test that throws still leaves the
  // worker with nothing running. A leaked socket is how a test file takes a vitest worker down,
  // and this file opens hundreds of them on purpose.
  const opened = new Set();
  const track = (thing) => {
    opened.add(thing);
    thing.on('close', () => opened.delete(thing));
    return thing;
  };

  const closeEverything = () => {
    for (const thing of opened) {
      try {
        if (thing.destroy) thing.destroy();
        else if (thing.abort) thing.abort();
      } catch {
        // Already gone.
      }
    }
    opened.clear();
  };

  afterEach(() => {
    closeEverything();
  });

  /**
   * One request to the control channel. It never rejects: a rejection that lands after its test
   * has finished is an unhandled rejection, which ends the worker rather than the test.
   */
  const control = (method, path, body) => new Promise((resolve) => {
    const request = track(http.request({ host: '127.0.0.1', port: ports.control, method, path }, (answer) => {
      let text = '';
      answer.on('data', (chunk) => { text += chunk; });
      answer.on('end', () => resolve({ status: answer.statusCode, body: text }));
      answer.on('error', () => resolve({ status: 0, body: '' }));
    }));
    request.on('error', () => resolve({ status: 0, body: '' }));
    request.end(body === undefined ? undefined : JSON.stringify(body));
  });

  const journal = async () => JSON.parse((await control('GET', '/journal')).body);

  /**
   * Where the journal stands now, counted in records ever written: what the ring holds plus what
   * has already fallen out of it. Monotonic, and with no clock in it anywhere.
   *
   * A time was the obvious thing to mark a test's place with and it was the wrong thing, because
   * the two clocks are not one clock: the test reads its own process's, the record carries the
   * program's, and neither is better than the platform's timer. On Windows that tick is about
   * 15 ms, which is an age next to a refusal that needs no name resolved and nothing connected,
   * so a record written after the mark can carry a stamp from before it and be filtered away as
   * somebody else's. Seven tests failed that way there, every one of them an instant decision,
   * while every test whose decision took real time passed. A count cannot do that on any machine.
   */
  const journalMark = async () => { const { records, dropped } = await journal(); return records.length + dropped; };

  /**
   * The last decision about this destination among the records written since `mark`. It waits for
   * the record, because the program journals a decision when it has made up its mind and not when
   * the client hears about it. The mark is what keeps an earlier test's record out of the answer,
   * and it has to: `127.0.0.1`, `example.com` and `blocked.test` are each decided about many
   * times in this file, and an assertion that reads the wrong one passes for the wrong reason.
   */
  const recordsSince = async (mark) => {
    const { records, dropped } = await journal();
    // The ring is in order, so the records written since the mark are the last of it. More than
    // the ring holds and this is every record there is, which is the most that can be said.
    const since = Math.max(0, records.length + dropped - mark);
    return records.slice(Math.max(0, records.length - since));
  };

  /** Every note of this kind written since the mark, whatever listener made it. */
  const notesSince = async (decision, mark) => (await recordsSince(mark)).filter((entry) => entry.decision === decision);

  /**
   * A note of this kind from this listener, written since the mark. Waited for, like every other
   * record this file reads: a flood is noted when the program drops a connection, which is not
   * the moment the client's socket reported itself connected.
   */
  const noteFor = async (listener, decision, mark) => {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const found = (await notesSince(decision, mark)).filter((entry) => entry.listener === listener);
      if (found.length > 0) return found.at(-1);
      await new Promise((resolve) => { setTimeout(resolve, 50); });
    }
    throw new Error(`the gatekeeper never noted ${decision} on the ${listener} after its record ${mark}`);
  };

  const decisionFor = async (host, mark = 0) => {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      const fresh = (await recordsSince(mark)).filter((entry) => entry.host === host);
      if (fresh.length > 0) return fresh.at(-1);
      await new Promise((resolve) => { setTimeout(resolve, 50); });
    }
    throw new Error(`the gatekeeper never decided anything about ${host} after its record ${mark}`);
  };

  /** A raw CONNECT, as any client in the space would send it. Resolves the status line. */
  const connect = (line, { keepOpen = false, wait = 5_000 } = {}) => new Promise((resolve) => {
    const socket = track(net.connect({ host: '127.0.0.1', port: ports.corridor }));
    let answer = '';
    const done = (text) => {
      if (!keepOpen) socket.destroy();
      resolve({ status: text, socket });
    };
    socket.on('connect', () => socket.write(`${line}\r\n\r\n`));
    socket.on('data', (chunk) => {
      answer += chunk;
      if (answer.includes('\r\n')) done(answer.split('\r\n')[0]);
    });
    socket.on('error', () => done('socket error'));
    socket.on('close', () => done(answer.split('\r\n')[0] ?? ''));
    // A target the program allows is never answered, because nothing is there to connect to.
    setTimeout(() => done('no answer'), wait);
  });

  const tunnelTo = (target) => connect(`CONNECT ${target} HTTP/1.1`);

  /** The whole answer to a CONNECT the corridor refuses, headers included. */
  const connectFully = (line) => new Promise((resolve) => {
    const socket = track(net.connect({ host: '127.0.0.1', port: ports.corridor }));
    let answer = '';
    const done = () => { socket.destroy(); resolve(answer); };
    socket.on('connect', () => socket.write(`${line}\r\n\r\n`));
    socket.on('data', (chunk) => { answer += chunk; });
    socket.on('error', done);
    socket.on('close', done);
    setTimeout(done, 5_000);
  });

  /** A plain proxy request, the form the corridor refuses. Its target rides in the request line. */
  const throughPlainProxy = (url) => new Promise((resolve) => {
    const request = track(http.request({ host: '127.0.0.1', port: ports.corridor, method: 'GET', path: url }, (answer) => {
      answer.resume();
      answer.on('end', () => resolve({ status: answer.statusCode }));
      answer.on('error', () => resolve({ status: 0 }));
    }));
    request.on('error', () => resolve({ status: 0 }));
    request.end();
  });

  /** One request through the window, as a tool in the space would send it. */
  const throughWindow = (path, headers = {}) => new Promise((resolve) => {
    const request = track(http.request({ host: '127.0.0.1', port: ports.window, path, headers }, (answer) => {
      let text = '';
      answer.on('data', (chunk) => { text += chunk; });
      answer.on('end', () => resolve({ status: answer.statusCode, body: text }));
      answer.on('error', () => resolve({ status: 0, body: '' }));
    }));
    request.on('error', () => resolve({ status: 0, body: '' }));
    request.end();
  });

  /**
   * One request as the space's client makes it now: a CONNECT, the gatekeeper's certificate
   * trusted through the authority the window serves, then HTTP on that TLS connection.
   */
  const secureRequest = (method, path, { host = 'example.com', hostHeader = host, servername = host, body = null, headers = {} } = {}) => new Promise((resolve) => {
    const socket = track(net.connect({ host: '127.0.0.1', port: ports.corridor }));
    const payload = body === null ? null : Buffer.from(body);
    const extra = Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`).join('');
    let head = '';
    const answer = (status, body = '') => resolve({ status, body });
    socket.on('connect', () => socket.write(`CONNECT ${host}:443 HTTP/1.1\r\n\r\n`));
    socket.on('error', () => answer('socket error'));
    socket.on('data', function onHead(chunk) {
      head += chunk;
      if (!head.includes('\r\n\r\n')) return;
      socket.removeListener('data', onHead);
      control('GET', '/ca').then(({ body: ca }) => {
        const secure = tls.connect({ socket, servername, ca }, () => {
          secure.write(`${method} ${path} HTTP/1.1\r\nHost: ${hostHeader}\r\n${extra}Connection: close\r\nContent-Length: ${payload === null ? 0 : payload.length}\r\n\r\n`);
          if (payload !== null) secure.write(payload);
        });
        let text = '';
        secure.on('data', (chunk) => { text += chunk; });
        secure.on('end', () => answer(text.split('\r\n')[0] ?? '', text));
        secure.on('error', (error) => answer(`tls error ${error.message}`, text));
      });
    });
    setTimeout(() => answer('no answer'), 20_000);
  });

  beforeAll(async () => {
    // The upstream of a grant. It answers with what it received, minus the secret itself.
    upstream = http.createServer((request, response) => {
      seen.push({ url: request.url, headers: request.headers });
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ upstreamSaw: request.url }));
    });
    await new Promise((resolve) => { upstream.listen(0, '127.0.0.1', resolve); });
    upstreamPort = upstream.address().port;

    // The last argument is the window's deadline: 1.5 seconds here so a test can watch it
    // pass, 300000 in the container command, which the hardening test asserts.
    // The tunnel's idle limit and the approval timeout come after the caps: a test that has to
    // watch the approval timeout pass uses 1.5 seconds.
    ({ child, ports } = await startGatekeeper(['1500', String(CAPS.corridor), String(CAPS.window), String(CAPS.control), '300000', '1500']));
  }, 40_000);

  afterAll(async () => {
    closeEverything();
    if (child && child.exitCode === null) {
      const ended = new Promise((resolve) => { child.once('exit', resolve); setTimeout(resolve, 5_000); });
      child.kill('SIGKILL');
      await ended;
    }
    // A server with a connection still on it does not close, and a hook that never returns is
    // the other way a worker dies. So the connections go first, and the wait has an end.
    upstream?.closeAllConnections?.();
    await new Promise((resolve) => {
      const done = setTimeout(resolve, 5_000);
      upstream?.close(() => { clearTimeout(done); resolve(); });
    });
  });

  describe('forwarded bodies', () => {
    const { writeForwardedBody } = createRequire(import.meta.url)(PROGRAM);
    // The request is a real stream and the outgoing request is one too, so this reads the bytes
    // the upstream would read, in order, not a call list of the implementation.
    const carried = (buffered, tail) => new Promise((resolve) => {
      const outgoing = new PassThrough();
      const chunks = [];
      outgoing.on('data', (chunk) => chunks.push(chunk));
      outgoing.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      writeForwardedBody(outgoing, Readable.from(tail), buffered);
    });

    it('streams an unread request, writes a buffered body whole, and prefixes an oversized one', async () => {
      expect(await carried(undefined, ['query ', '{ a }'])).toBe('query { a }');
      // A fully read body has no tail left, so what follows is not part of the request.
      expect(await carried({ body: Buffer.from('query { a }') }, ['not a body'])).toBe('query { a }');
      expect(await carried({ body: Buffer.alloc(0) }, [])).toBe('');
      // A body past the classification limit travels as read bytes plus the unread rest.
      expect(await carried({ prefix: Buffer.from('{"query":"') }, ['{ viewer { login }', ' }"}'])).toBe('{"query":"{ viewer { login } }"}');
      expect(await carried({ prefix: Buffer.alloc(0) }, ['whole', ' body'])).toBe('whole body');
    });
  });

  describe('GraphQL bodies', () => {
    const { classifyGraphqlBody } = createRequire(import.meta.url)(PROGRAM);
    const envelope = (value) => Buffer.from(JSON.stringify(value));
    const verdict = (query) => classifyGraphqlBody(envelope({ query }));

    it('reads queries, shorthand, named operations, fragments, comments and block strings', () => {
      expect(verdict('{ viewer { login } }')).toBe('read');
      expect(verdict('query Viewer { viewer { login } }')).toBe('read');
      expect(verdict('query Q($id: ID!) { node(id: $id) { ...F } } fragment F on Node { id }')).toBe('read');
      expect(verdict('# mutation { evil }\nquery { viewer { login } }')).toBe('read');
      expect(verdict('query { search(text: """mutation { evil }""") { id } }')).toBe('read');
      // The word in a variable is not a document: only `query` is read.
      expect(classifyGraphqlBody(envelope({ query: 'query { a }', variables: { mutation: 'evil' } }))).toBe('read');
      expect(classifyGraphqlBody(Buffer.from(JSON.stringify([{ query: '{ a }' }, { query: 'query { b }' }])))).toBe('read');
    });

    it('sees a mutation or subscription in any document of a batch', () => {
      expect(verdict('mutation { addStar(input: {}) { clientMutationId } }')).toBe('write');
      expect(verdict('subscription { events { id } }')).toBe('write');
      expect(verdict('query { a } mutation { evil }')).toBe('write');
      expect(classifyGraphqlBody(Buffer.from(JSON.stringify([{ query: '{ a }' }, { query: 'mutation { evil }' }])))).toBe('write');
    });

    it('answers unknown for anything it cannot read, so the user is asked', () => {
      expect(classifyGraphqlBody(Buffer.from('not json'))).toBe('unknown');
      expect(classifyGraphqlBody(Buffer.from(''))).toBe('unknown');
      expect(verdict('query { a')).toBe('unknown');
      expect(verdict('fragment F on Node { id }')).toBe('unknown');
      expect(verdict('')).toBe('unknown');
      expect(classifyGraphqlBody(envelope({ variables: {} }))).toBe('unknown');
      expect(classifyGraphqlBody(envelope({ query: 42 }))).toBe('unknown');
      expect(classifyGraphqlBody(Buffer.from('[]'))).toBe('unknown');
      expect(classifyGraphqlBody(Buffer.from('""'))).toBe('unknown');
    });

    it('reads a raw application/graphql document', () => {
      expect(classifyGraphqlBody(Buffer.from('query { a }'), { raw: true })).toBe('read');
      expect(classifyGraphqlBody(Buffer.from('mutation { a }'), { raw: true })).toBe('write');
      expect(classifyGraphqlBody(Buffer.from('mutation'), { raw: true })).toBe('unknown');
    });
  });

  describe('JSON-RPC bodies', () => {
    const { classifyJsonRpcBody } = createRequire(import.meta.url)(PROGRAM);
    const envelope = (value) => Buffer.from(JSON.stringify(value));
    const request = (method, extra = {}) => envelope({ jsonrpc: '2.0', id: 1, method, ...extra });

    it('reads the handshake, discovery and reading a resource or a prompt', () => {
      for (const method of ['initialize', 'ping', 'tools/list', 'resources/list', 'resources/templates/list', 'resources/read', 'prompts/list', 'prompts/get', 'completion/complete', 'logging/setLevel']) {
        expect(classifyJsonRpcBody(request(method)), method).toBe('read');
      }
      // The handshake's notification carries no id, which is not what makes it a write.
      expect(classifyJsonRpcBody(envelope({ jsonrpc: '2.0', method: 'notifications/initialized' }))).toBe('read');
      expect(classifyJsonRpcBody(envelope([{ jsonrpc: '2.0', id: 1, method: 'tools/list' }, { jsonrpc: '2.0', id: 2, method: 'resources/read', params: { uri: 'file:///a' } }]))).toBe('read');
    });

    it('never reads a tool call, a subscription, or a method it does not know', () => {
      expect(classifyJsonRpcBody(request('tools/call', { params: { name: 'delete_everything', arguments: {} } }))).toBe('unknown');
      expect(classifyJsonRpcBody(request('resources/subscribe'))).toBe('unknown');
      expect(classifyJsonRpcBody(request('sampling/createMessage'))).toBe('unknown');
      expect(classifyJsonRpcBody(envelope([{ jsonrpc: '2.0', id: 1, method: 'tools/list' }, { jsonrpc: '2.0', id: 2, method: 'tools/call' }]))).toBe('unknown');
    });

    it('is only the endpoint itself, never a path below a folder called mcp', () => {
      // The corridor asks this of the space's own path before reading anything.
      const { isJsonRpcRequest } = createRequire(import.meta.url)(PROGRAM);
      const json = { headers: { 'content-type': 'application/json' } };
      expect(isJsonRpcRequest(json, '/mcp')).toBe(true);
      expect(isJsonRpcRequest(json, '/mcp/')).toBe(true);
      expect(isJsonRpcRequest(json, '/mcp?x=1')).toBe(true);
      expect(isJsonRpcRequest(json, '/mcp/charges')).toBe(false);
      expect(isJsonRpcRequest(json, '/api/mcp')).toBe(false);
      // The media type is part of it: a form post to the same path is not JSON-RPC.
      expect(isJsonRpcRequest({ headers: { 'content-type': 'text/plain' } }, '/mcp')).toBe(false);
    });

    it('answers unknown for anything it cannot read, so the user is asked', () => {
      expect(classifyJsonRpcBody(Buffer.from('not json'))).toBe('unknown');
      expect(classifyJsonRpcBody(Buffer.from(''))).toBe('unknown');
      expect(classifyJsonRpcBody(Buffer.from('[]'))).toBe('unknown');
      // Not JSON-RPC 2.0, no method, or a reply rather than a request.
      expect(classifyJsonRpcBody(envelope({ jsonrpc: '1.0', id: 1, method: 'tools/list' }))).toBe('unknown');
      expect(classifyJsonRpcBody(envelope({ jsonrpc: '2.0', id: 1 }))).toBe('unknown');
      expect(classifyJsonRpcBody(envelope({ jsonrpc: '2.0', id: 1, method: 42 }))).toBe('unknown');
      expect(classifyJsonRpcBody(envelope({ jsonrpc: '2.0', id: 1, method: 'tools/list', result: {} }))).toBe('unknown');
      expect(classifyJsonRpcBody(envelope({ jsonrpc: '2.0', id: 1, method: 'tools/list', error: { code: -32600, message: 'no' } }))).toBe('unknown');
    });
  });

  describe('corridor, in allowlist mode', () => {
    beforeAll(async () => {
      expect((await control('POST', '/network', { mode: 'allowlist', domains: ['example.com', 'blocked.test'] })).status).toBe(200);
    });

    it('resolves a name itself, and refuses it when nothing comes back', async () => {
      // `.test` never resolves. The list rules are covered directly, further down.
      expect((await tunnelTo('blocked.test:443')).status).toMatch(/403/);
      expect(await decisionFor('blocked.test')).toMatchObject({ listener: 'corridor', port: 443, decision: expect.stringMatching(/^deny:unresolved:/) });
    });

    it('refuses a name that is not on the list, with no suffix or wildcard matching', async () => {
      for (const name of ['sub.example.com', 'notexample.com', 'example.com.evil.test', 'example.co']) {
        expect((await tunnelTo(`${name}:443`)).status).toMatch(/403/);
        expect(await decisionFor(name)).toMatchObject({ decision: 'deny:not-on-allowlist' });
      }
    });

    it('reads a name in any case and with a trailing dot as the same name', async () => {
      for (const written of ['EXAMPLE.COM', 'example.com.']) {
        const at = await journalMark();
        await tunnelTo(`${written}:443`);
        expect((await decisionFor('example.com', at)).decision).not.toBe('deny:not-on-allowlist');
      }
    });

    it('allows port 443 only', async () => {
      for (const port of [80, 22, 8080, 3128]) {
        const at = await journalMark();
        expect((await tunnelTo(`example.com:${port}`)).status).toMatch(/403/);
        expect(await decisionFor('example.com', at)).toMatchObject({ port, decision: 'deny:port' });
      }
    });
  });

  describe('corridor, in open mode', () => {
    beforeAll(async () => {
      expect((await control('POST', '/network', { mode: 'open', domains: [] })).status).toBe(200);
    });

    it('tells the space refused from unreachable, and nothing else about why', async () => {
      // A bare 502 reads like a broken allowlist, so the two are told apart. The reason why it
      // was refused is not: sorting `blocked-address` from `unresolved` would let an agent map
      // the user's internal DNS from inside, and the mode it is in from the other reasons.
      const anAddress = await connectFully('CONNECT 203.0.113.7:443 HTTP/1.1');
      const notOnTheList = await connectFully('CONNECT some.example.org:443 HTTP/1.1');
      const doesNotResolve = await connectFully('CONNECT blocked.test:443 HTTP/1.1');

      for (const answer of [anAddress, notOnTheList, doesNotResolve]) {
        expect(answer).toMatch(/^HTTP\/1\.1 403 /);
        expect(answer).toContain('x-gatekeeper-reason: refused');
      }
      // Every refusal reads the same from inside, whatever the journal says about it.
      expect(new Set([anAddress, notOnTheList, doesNotResolve]).size).toBe(1);
      for (const leak of ['not-a-name', 'blocked-address', 'unresolved', 'allowlist', 'ENOTFOUND']) {
        expect(anAddress + notOnTheList + doesNotResolve).not.toContain(leak);
      }
      // And the journal still holds the reason, which is where the user reads it.
      expect((await decisionFor('blocked.test')).decision).toMatch(/^deny:unresolved:/);
    });

    it('resolves the name itself before it decides anything about the address', async () => {
      // The two halves of the rebinding defence are covered apart: that a name passes the name
      // rules and is then resolved, and that the resolved address is judged. Both are below,
      // against the rules directly. The join, a public name that resolves to 127.0.0.1, needs a
      // resolver that answers, so it lives in the escape suite with `localtest.me`.
      const at = await journalMark();
      await tunnelTo('blocked.test:443');
      expect(await decisionFor('blocked.test', at)).toMatchObject({ decision: expect.stringMatching(/^deny:unresolved:/) });
    });

    it('allows port 443 only here too, so a space can attack nothing else from the user\'s address', async () => {
      // `.test` never resolves, so 443 comes back as the decision after the name and port rules
      // have passed. Every other port is refused before any of that.
      const at = await journalMark();
      await tunnelTo('blocked.test:443');
      expect(await decisionFor('blocked.test', at)).toMatchObject({ port: 443, decision: expect.stringMatching(/^deny:unresolved:/) });

      for (const port of [80, 22, 8443, 9418]) {
        const when = await journalMark();
        expect((await tunnelTo(`blocked.test:${port}`)).status).toMatch(/403/);
        expect(await decisionFor('blocked.test', when)).toMatchObject({ port, decision: 'deny:port' });
      }
    });

    // The escape the reviewer found: `auth.openai.com` was refused and its address was not, and a
    // space can learn that address from a DNS-over-HTTPS resolver through this same corridor.
    it.each([
      ['an IPv4 literal', '104.18.41.241:443'],
      ['an IPv4 literal on another port, refused before the port rule', '104.18.41.241:8443'],
      ['an IPv4-mapped IPv6 literal', '[::ffff:104.18.41.241]:443'],
      ['an IPv4-mapped literal in hex', '[::ffff:6812:29f1]:443'],
      ['a bracketed IPv6 literal', '[2606:4700::6812:29f1]:443'],
      ['a NAT64 literal', '[64:ff9b::6812:29f1]:443'],
      ['a 6to4 literal', '[2002:6812:29f1::1]:443'],
      ['a documentation address', `${PUBLIC_ADDRESS}:443`],
      // Everything below is an address to `getaddrinfo` and was not one to this program.
      // The first of them carried a real TLS session to the refused host in the first draft.
      ['the same address as one integer', '1746020849:443'],
      ['another address as one integer', '16843009:443'],
      ['an address in hex', '0x01010101:443'],
      ['an address in three parts', '1.1.257:443'],
      ['an address in four hex parts', '0x1.0x1.0x1.0x1:443'],
      ['an address with an octal part', '0177.0.0.1:443'],
      ['a name with no dot at all', 'localhost:443'],
    ])('refuses %s, because the corridor takes names only', async (title, target) => {
      const at = await journalMark();
      const answer = await tunnelTo(target);
      const host = target.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
      expect(answer.status).toMatch(/403/);
      expect((await decisionFor(host, at)).decision).toBe('deny:not-a-name');
    });

    // `auth.openai.com。` and its two siblings resolve on this C library exactly like the name they
    // imitate. They never reach the corridor's rules, because Node's parser refuses a non-ASCII
    // request target first, so this test says that plainly and then checks the rule itself, which
    // is what would have to hold if a client ever got such a target past the parser.
    it.each([
      ['an ideographic full stop', 'auth.openai.com\u3002'],
      ['a fullwidth full stop', 'auth.openai\uff0ecom'],
      ['a halfwidth ideographic full stop', 'auth\uff61openai.com'],
    ])('never lets a name with %s reach the corridor, and refuses it by rule as well', async (title, host) => {
      const answer = await tunnelTo(`${host}:443`);
      expect(answer.status).toMatch(/400|socket error|closed/);

      const { refuseTarget, setNetwork } = createRequire(import.meta.url)(PROGRAM);
      setNetwork({ mode: 'open', domains: [] });
      expect(refuseTarget(host, 443)).toBe('deny:not-a-name');
    });

    it('records that the parser threw something out, so probing with such targets is not invisible', async () => {
      await tunnelTo('auth.openai.com\u3002:443');
      // Waited for, not read once: the program journals when it decides. The note is not asked to
      // be this attempt's own, because notes are rate-limited to one a minute per listener and
      // per kind, and an earlier malformed line in this file may already have spent the minute.
      // That is the limiter working, and it is why this is one test and not three. What this
      // proves is that the parser's refusals reach the journal at all, so a space cannot probe
      // with targets the parser throws out and leave the user's view blind by construction.
      expect(await noteFor('corridor', 'deny:unreadable-request', 0)).toMatchObject({ host: '', port: 0 });
    });

    it('refuses auth.openai.com, whatever the mode and whatever the list says', async () => {
      await tunnelTo('auth.openai.com:443');
      expect(await decisionFor('auth.openai.com')).toMatchObject({ decision: 'deny:always-refused' });

      const at = await journalMark();
      await control('POST', '/network', { mode: 'allowlist', domains: ['auth.openai.com', 'example.com'] });
      await tunnelTo('auth.openai.com:443');
      expect((await decisionFor('auth.openai.com', at)).decision).toBe('deny:always-refused');
      await control('POST', '/network', { mode: 'open', domains: [] });
    });

    it('takes CONNECT only, and keeps the path of a plain proxy request out of its journal', async () => {
      const at = await journalMark();
      const answer = await throughPlainProxy(`http://${PUBLIC_ADDRESS}/secret/path?token=leak`);
      expect(answer.status).toBe(403);
      const record = await decisionFor(PUBLIC_ADDRESS, at);
      expect(record).toMatchObject({ listener: 'corridor', host: PUBLIC_ADDRESS, decision: 'deny:not-connect' });
      expect(JSON.stringify(record)).not.toContain('secret');
      expect(JSON.stringify(record)).not.toContain('token');
    });

  });

  describe('corridor, method approval', () => {
    beforeAll(async () => {
      expect((await control('POST', '/network', { mode: 'open', domains: [] })).status).toBe(200);
      expect((await control('POST', '/writes', { entries: [] })).status).toBe(200);
    });

    const pendingNow = async (since = 0) => {
      const answer = await control('GET', `/pending?since=${since}&wait=0`);
      expect(answer.status).toBe(200);
      return JSON.parse(answer.body).requests;
    };
    const waitForPending = async (count = 1) => {
      for (let attempt = 0; attempt < 120; attempt += 1) {
        const requests = await pendingNow();
        if (requests.length >= count) return requests;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      throw new Error(`no write started waiting: ${JSON.stringify(await pendingNow())}`);
    };
    const answerPending = (id, allow) => control('POST', '/approvals', { id, allow });
    const clearPending = async () => {
      for (const request of await pendingNow()) await answerPending(request.id, false);
    };

    afterEach(async () => {
      await clearPending();
      // A refusal now stands for its destination, or for the turn; each test starts from asking again.
      expect((await control('POST', '/denials', { entries: [] })).status).toBe(200);
      expect((await control('POST', '/writes', { entries: [] })).status).toBe(200);
      expect((await control('POST', '/turn-end', {})).status).toBe(200);
    });

    it('carries a GET without any approval', async () => {
      const at = await journalMark();
      const answer = await secureRequest('GET', '/');
      // The upstream may be unreachable in a sandboxed run; that is a 502 from this proxy, and
      // still proves the request passed the method gate. Only a 403 would mean it did not.
      expect(answer.status).not.toMatch(/403/);
      expect((await recordsSince(at)).some((record) => record.decision === 'deny:method')).toBe(false);
    });

    it('holds a write until the user allows it, and sends it on after the answer', async () => {
      const at = await journalMark();
      const held = secureRequest('POST', '/');
      const [waiting] = await waitForPending();
      expect(waiting).toMatchObject({ host: 'example.com', port: 443, method: 'POST', url: 'https://example.com/' });
      expect(Date.parse(waiting.expiresAt)).toBeGreaterThan(Date.now());

      // Nothing has gone out and nothing has been decided: no allow, no refusal, yet. The
      // corridor's own `allow` for the CONNECT carries no method and is not a decision about it.
      expect((await recordsSince(at)).some((record) => record.method !== '' && (record.decision === 'allow' || record.decision === 'deny:method'))).toBe(false);
      expect((await answerPending(waiting.id, true)).status).toBe(200);

      const answer = await held;
      expect(answer.status).not.toMatch(/403/);
      expect((await recordsSince(at)).some((record) => record.decision === 'allow' && record.method === 'POST')).toBe(true);
      // The same answer twice: the wait is gone.
      expect((await answerPending(waiting.id, true)).status).toBe(404);
    });

    it('sends a write on without a wait when the network allows writes', async () => {
      expect((await control('POST', '/network', { mode: 'open', domains: [], writes: 'allow' })).status).toBe(200);
      try {
        const at = await journalMark();
        const answer = await secureRequest('POST', '/');
        // Unreachable upstream is a 502 from this proxy and still proves the request passed; only a 403 would mean it waited.
        expect(answer.status).not.toMatch(/403/);
        expect(await pendingNow()).toEqual([]);
        expect((await recordsSince(at)).some((record) => record.decision === 'allow' && record.method === 'POST')).toBe(true);
      } finally {
        expect((await control('POST', '/network', { mode: 'open', domains: [], writes: 'ask' })).status).toBe(200);
      }
    });

    it('refuses a write the user denies, and reads nothing of its body', async () => {
      const at = await journalMark();
      const held = secureRequest('PUT', '/');
      const [waiting] = await waitForPending();
      expect(waiting).toMatchObject({ host: 'example.com', method: 'PUT' });
      expect((await answerPending(waiting.id, false)).status).toBe(200);

      expect((await held).status).toMatch(/403/);
      expect((await recordsSince(at)).some((record) => record.decision === 'deny:method' && record.method === 'PUT')).toBe(true);
    });

    it('stands a denial for the destination, and asks again once it is cleared', async () => {
      const at = await journalMark();
      const held = secureRequest('POST', '/');
      const [waiting] = await waitForPending();
      expect((await answerPending(waiting.id, false)).status).toBe(200);
      expect((await held).status).toMatch(/403/);

      // The same write again: refused at once, and nothing starts waiting.
      expect((await secureRequest('POST', '/')).status).toMatch(/403/);
      expect(await pendingNow()).toEqual([]);
      expect((await recordsSince(at)).filter((record) => record.decision === 'deny:method' && record.method === 'POST')).toHaveLength(2);
      expect((await control('GET', '/policy').then((answer) => JSON.parse(answer.body))).denials).toEqual([{ host: 'example.com', methods: ['POST'] }]);

      // Clearing it gives the prompt back.
      expect((await control('POST', '/denials', { entries: [] })).status).toBe(200);
      const again = secureRequest('POST', '/');
      const [second] = await waitForPending();
      expect((await answerPending(second.id, true)).status).toBe(200);
      expect((await again).status).not.toMatch(/403/);
    });

    it('stands a deny once for the rest of the turn, and asks again once the turn ends', async () => {
      const held = secureRequest('POST', '/');
      const [waiting] = await waitForPending();
      expect((await control('POST', '/approvals', { id: waiting.id, allow: false, remember: false })).status).toBe(200);
      const refused = await held;
      expect(refused.status).toMatch(/403/);
      // The body tells the agent it is a decision, so a retry is not worth another round.
      expect(refused.body).toContain('do not retry');
      // Not a standing answer: the dialog has nothing to clear, and the record keeps nothing.
      expect((await control('GET', '/policy').then((answer) => JSON.parse(answer.body))).denials).toEqual([]);

      // The agent's retry in the same turn meets the refusal at once, without a prompt.
      const retry = await secureRequest('POST', '/');
      expect(retry.status).toMatch(/403/);
      expect(await pendingNow()).toEqual([]);

      // The turn ends: the next try waits for the user again.
      expect((await control('POST', '/turn-end', {})).status).toBe(200);
      const again = secureRequest('POST', '/');
      const [second] = await waitForPending();
      expect(second.id).not.toBe(waiting.id);
      expect((await answerPending(second.id, true)).status).toBe(200);
      expect((await again).status).not.toMatch(/403/);
    });

    it('stands a deny once for the path or the host the space chose', async () => {
      // The space's scope is the path: only that path stops asking for the turn.
      const heldA = secureRequest('POST', '/a');
      const [waitingA] = await waitForPending();
      expect((await control('POST', '/approvals', { id: waitingA.id, allow: false, remember: false, scope: 'path' })).status).toBe(200);
      expect((await heldA).status).toMatch(/403/);
      expect((await secureRequest('POST', '/a')).status).toMatch(/403/);
      const heldB = secureRequest('POST', '/b');
      const [waitingB] = await waitForPending();
      expect(waitingB.path).toBe('/b');
      expect((await answerPending(waitingB.id, true)).status).toBe(200);
      expect((await heldB).status).not.toMatch(/403/);

      // The host scope: one path refused, every path of the host refused for the turn.
      expect((await control('POST', '/turn-end', {})).status).toBe(200);
      const heldC = secureRequest('POST', '/c');
      const [waitingC] = await waitForPending();
      expect((await control('POST', '/approvals', { id: waitingC.id, allow: false, remember: false, scope: 'host' })).status).toBe(200);
      expect((await heldC).status).toMatch(/403/);
      expect((await secureRequest('POST', '/d')).status).toMatch(/403/);
      expect(await pendingNow()).toEqual([]);
    });

    it('keeps a deny once on its own write when the path is too long to remember', async () => {
      // A target the space can write but this gatekeeper cannot store as a rule. The refusal must
      // cover that write only: widening it to the whole host refuses paths the user never saw.
      const longPath = `/${'a'.repeat(4096)}`;
      const held = secureRequest('POST', longPath);
      const [waiting] = await waitForPending();
      expect(waiting.path).toBeUndefined();
      expect((await control('POST', '/approvals', { id: waiting.id, allow: false, remember: false, scope: 'path' })).status).toBe(200);
      expect((await held).status).toMatch(/403/);

      const other = secureRequest('POST', '/a');
      const [second] = await waitForPending();
      expect((await answerPending(second.id, true)).status).toBe(200);
      expect((await other).status).not.toMatch(/403/);
    });

    it('lets a standing approval lift the write it refused once for the turn', async () => {
      const held = secureRequest('POST', '/a');
      const [waiting] = await waitForPending();
      expect((await control('POST', '/approvals', { id: waiting.id, allow: false, remember: false, scope: 'path' })).status).toBe(200);
      expect((await held).status).toMatch(/403/);
      expect((await secureRequest('POST', '/a')).status).toMatch(/403/);

      // The user then approves the same rule: a newer decision, and the way out of the refusal.
      expect((await control('POST', '/writes', { entries: [{ host: 'example.com', path: '/a', methods: ['POST'] }] })).status).toBe(200);
      expect((await secureRequest('POST', '/a')).status).not.toMatch(/403/);
    });

    it('ends a deny once with the turn and leaves a standing answer alone', async () => {
      const held = secureRequest('POST', '/');
      const [waiting] = await waitForPending();
      expect((await control('POST', '/approvals', { id: waiting.id, allow: false })).status).toBe(200);
      expect((await held).status).toMatch(/403/);
      expect((await control('POST', '/turn-end', {})).status).toBe(200);

      // The turn ending says nothing about the user's standing denial.
      expect((await secureRequest('POST', '/')).status).toMatch(/403/);
      expect((await control('GET', '/policy').then((answer) => JSON.parse(answer.body))).denials).toEqual([{ host: 'example.com', methods: ['POST'] }]);
    });

    it('approves only the exact path, query aside, and keeps near-miss paths asking', async () => {
      expect((await control('POST', '/writes', { entries: [{ host: 'example.com', path: '/a', methods: ['POST'] }] })).status).toBe(200);
      expect((await secureRequest('POST', '/a?next=1')).status).not.toMatch(/403/);
      for (const otherPath of ['/b', '/a/../b', '/%61', '/a/']) {
        const held = secureRequest('POST', otherPath);
        const [waiting] = await waitForPending();
        expect(waiting.path).toBe(otherPath);
        expect((await answerPending(waiting.id, true)).status).toBe(200);
        expect((await held).status).not.toMatch(/403/);
      }
      expect((await control('GET', '/policy').then((answer) => JSON.parse(answer.body))).writes).toEqual([{ host: 'example.com', path: '/a', methods: ['POST'] }]);
    });

    it('uses the path answer before the host, and a denial before an approval at the same level', async () => {
      const allowHost = () => control('POST', '/writes', { entries: [{ host: 'example.com', methods: ['POST'] }] });
      expect((await allowHost()).status).toBe(200);
      expect((await control('POST', '/denials', { entries: [{ host: 'example.com', path: '/admin', methods: ['POST'] }] })).status).toBe(200);
      // The host-wide approval survives; the more specific path is refused.
      expect((await secureRequest('POST', '/ordinary')).status).not.toMatch(/403/);
      expect((await secureRequest('POST', '/admin')).status).toMatch(/403/);
      // A path approval beats the host-wide denial, but not a denial for that same path.
      expect((await control('POST', '/denials', { entries: [{ host: 'example.com', methods: ['POST'] }] })).status).toBe(200);
      expect((await control('POST', '/writes', { entries: [{ host: 'example.com', path: '/one', methods: ['POST'] }] })).status).toBe(200);
      expect((await secureRequest('POST', '/one')).status).not.toMatch(/403/);
      expect((await control('POST', '/denials', { entries: [{ host: 'example.com', path: '/one', methods: ['POST'] }] })).status).toBe(200);
      expect((await secureRequest('POST', '/one')).status).toMatch(/403/);
    });

    it('settles only the waiting writes a path approval covers', async () => {
      const first = secureRequest('PUT', '/a');
      const second = secureRequest('PUT', '/b');
      const waits = await waitForPending(2);
      expect((await control('POST', '/writes', { entries: [{ host: 'example.com', path: '/a', methods: ['PUT'] }] })).status).toBe(200);
      expect((await first).status).not.toMatch(/403/);
      expect((await pendingNow()).map((entry) => entry.path)).toEqual(['/b']);
      const [remaining] = await pendingNow();
      expect((await answerPending(remaining.id, false)).status).toBe(200);
      expect((await second).status).toMatch(/403/);
      expect(waits).toHaveLength(2);
    });

    it('remembers an always denial for the path the space chose', async () => {
      const held = secureRequest('DELETE', '/only-this');
      const [waiting] = await waitForPending();
      expect((await control('POST', '/approvals', { id: waiting.id, allow: false, scope: 'path' })).status).toBe(200);
      expect((await held).status).toMatch(/403/);
      expect((await control('GET', '/policy').then((answer) => JSON.parse(answer.body))).denials).toEqual([{ host: 'example.com', path: '/only-this', methods: ['DELETE'] }]);
      expect((await secureRequest('DELETE', '/only-this')).status).toMatch(/403/);
      const other = secureRequest('DELETE', '/elsewhere');
      const [next] = await waitForPending();
      expect((await answerPending(next.id, false)).status).toBe(200);
      expect((await other).status).toMatch(/403/);
    });

    it('refuses a path that is no exact request path, and never reads it as host-wide', async () => {
      const before = (await control('GET', '/policy').then((answer) => JSON.parse(answer.body))).writes;
      for (const bad of ['relative', '/has space', '/query?x=1', '/fragment#x']) {
        expect((await control('POST', '/writes', { entries: [{ host: 'example.com', path: bad, methods: ['POST'] }] })).status).toBe(400);
      }
      expect((await control('GET', '/policy').then((answer) => JSON.parse(answer.body))).writes).toEqual(before);
    });

    it('refuses a denial list that names a method nobody can deny', async () => {
      expect((await control('POST', '/denials', { entries: [{ host: 'example.com', methods: ['CONNECT'] }] })).status).toBe(400);
      expect((await control('POST', '/denials', { entries: [{ host: '10.0.0.1', methods: ['POST'] }] })).status).toBe(400);
    });

    it('releases a waiting write when the dialog approves the method for the destination', async () => {
      const held = secureRequest('POST', '/');
      const [waiting] = await waitForPending();
      expect((await control('POST', '/writes', { entries: [{ host: 'example.com', methods: ['POST'] }] })).status).toBe(200);
      expect((await held).status).not.toMatch(/403/);
      expect(await pendingNow()).toEqual([]);
      expect(waiting.id).toBeGreaterThan(0);
      expect((await control('POST', '/writes', { entries: [] })).status).toBe(200);
    });

    // The corridor's targets here are real names, so the answer comes from out there or not at
    // all; only a 403 would mean the method gate held the request.
    it('sends a GraphQL document that only reads without asking', async () => {
      const at = await journalMark();
      const query = JSON.stringify({ query: 'query Viewer { viewer { login } }' });
      const answer = await secureRequest('POST', '/graphql', { body: query, headers: { 'content-type': 'application/json' } });
      expect(answer.status).not.toMatch(/403/);
      expect(await pendingNow()).toEqual([]);
      expect((await recordsSince(at)).some((record) => record.decision === 'deny:method')).toBe(false);
    });

    it('asks for a GraphQL mutation, and sends it on only after the user allows it', async () => {
      const mutation = JSON.stringify({ query: 'mutation AddStar { addStar(input: {}) { clientMutationId } }' });
      const held = secureRequest('POST', '/graphql', { body: mutation, headers: { 'content-type': 'application/json' } });
      const [waiting] = await waitForPending();
      expect(waiting.method).toBe('POST');
      expect((await answerPending(waiting.id, true)).status).toBe(200);
      expect((await held).status).not.toMatch(/403/);
    });

    it('keeps a denial for the write, and still lets that host\'s GraphQL reads through', async () => {
      const mutation = JSON.stringify({ query: 'mutation { evil }' });
      const held = secureRequest('POST', '/graphql', { body: mutation, headers: { 'content-type': 'application/json' } });
      const [waiting] = await waitForPending();
      expect((await answerPending(waiting.id, false)).status).toBe(200);
      expect((await held).status).toMatch(/403/);

      // The denial stands for the mutation; a query at the same destination is not that write.
      const query = JSON.stringify({ query: 'query { viewer { login } }' });
      const answer = await secureRequest('POST', '/graphql', { body: query, headers: { 'content-type': 'application/json' } });
      expect(answer.status).not.toMatch(/403/);
      expect(await pendingNow()).toEqual([]);
    });

    // The classifier's own cases are beside the GraphQL ones. This is the corridor: an MCP read
    // goes out on the same POST the server would otherwise be asked about. The other half, that a
    // tool call still waits, is measured through the same path in a standalone run and covered by
    // `tools/call` in the classifier tests: a wait here competes with the state the tests above
    // leave, and a test that answers somebody else's wait proves nothing.
    it('sends an MCP server discovery message without asking', async () => {
      const at = await journalMark();
      expect((await control('POST', '/denials', { entries: [] })).status).toBe(200);
      expect((await control('POST', '/turn-end', {})).status).toBe(200);
      const list = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
      const answer = await secureRequest('POST', '/mcp', { host: 'example.org', body: list, headers: { 'content-type': 'application/json' } });
      expect(answer.status).not.toMatch(/403/);
      expect(await pendingNow()).toEqual([]);
      expect((await recordsSince(at)).some((record) => record.decision === 'deny:method')).toBe(false);
    });

    it('asks for a body it cannot read with certainty, and refuses it on a no', async () => {
      const held = secureRequest('POST', '/graphql', { body: '{"extensions":{"persistedQuery":{"version":1}}}', headers: { 'content-type': 'application/json' } });
      const [waiting] = await waitForPending();
      expect((await answerPending(waiting.id, false)).status).toBe(200);
      expect((await held).status).toMatch(/403/);
      expect(await pendingNow()).toEqual([]);
    });

    it('carries the QUERY method, a safe request with a body', async () => {
      const answer = await secureRequest('QUERY', '/search', { body: '{"q":"anything"}', headers: { 'content-type': 'application/json' } });
      expect(answer.status).not.toMatch(/403/);
      expect(await pendingNow()).toEqual([]);
    });

    it('refuses a write nobody answered within the limit, without denying the destination', async () => {
      const at = await journalMark();
      const held = secureRequest('POST', '/');
      await waitForPending();
      // The test child runs with a 1.5 second limit: an answer that never comes is its own refusal.
      expect((await held).status).toMatch(/403/);
      expect((await recordsSince(at)).some((record) => record.decision === 'deny:method' && record.method === 'POST')).toBe(true);
      // A refusal nobody made is not a denial: the destination must still ask.
      expect((await control('GET', '/policy').then((answer) => JSON.parse(answer.body))).denials).toEqual([]);
      const again = secureRequest('POST', '/');
      await waitForPending();
      expect((await again).status).toMatch(/403/);
    });

    it('refuses the waits a newly set denial covers, without asking again', async () => {
      const first = secureRequest('POST', '/');
      await waitForPending();
      expect((await control('POST', '/denials', { entries: [{ host: 'example.com', methods: ['POST'] }] })).status).toBe(200);
      expect((await first).status).toMatch(/403/);
      expect(await pendingNow()).toEqual([]);
    });

    it('refuses a Host that is not the name the tunnel was opened for', async () => {
      const at = await journalMark();
      const answer = await secureRequest('GET', '/', { hostHeader: 'other.example.com' });
      expect(answer.status).toMatch(/403/);
      expect((await recordsSince(at)).some((record) => record.decision === 'deny:host-mismatch')).toBe(true);
    });

    it('refuses a method a user cannot approve', async () => {
      const answer = await control('POST', '/writes', { entries: [{ host: 'example.com', methods: ['CONNECT'] }] });
      expect(answer.status).toBe(400);
      expect(answer.body).toContain('CONNECT');
    });

    it('refuses a write past the number that may wait at once', async () => {
      const held = [];
      for (let index = 0; index < 8; index += 1) held.push(secureRequest('POST', '/'));
      await waitForPending(8);
      // The ninth is refused at once: a space cannot occupy the corridor with waits.
      expect((await secureRequest('POST', '/')).status).toMatch(/403/);
      const pending = await pendingNow();
      expect(pending).toHaveLength(8);
      for (const request of pending) expect((await answerPending(request.id, false)).status).toBe(200);
      expect((await Promise.all(held)).every((answer) => /403/.test(answer.status))).toBe(true);
    });

    it('serves the certificate the space trusts on the window too', async () => {
      const answer = await throughWindow('/ca');
      expect(answer.status).toBe(200);
      expect(answer.body).toContain('BEGIN CERTIFICATE');
    });
  });

  describe('corridor, under abuse', () => {
    it.each([
      'CONNECT HTTP/1.1',
      'CONNECT :443 HTTP/1.1',
      'CONNECT example.com: HTTP/1.1',
      'CONNECT example.com:99999 HTTP/1.1',
      'CONNECT example.com:-1 HTTP/1.1',
      'CONNECT http://example.com/path:443 HTTP/1.1',
      `CONNECT ${'x'.repeat(400)}:443 HTTP/1.1`,
      'CONNECT [::1:443 HTTP/1.1',
      'GARBAGE',
      'CONNECT example.com:443 NOT-HTTP',
    ])('answers %j without ending', async (line) => {
      await connect(line, { wait: 500 });
      expect(child.exitCode).toBe(null);
    });

    it('survives a client that resets in the middle of the handshake', async () => {
      for (let attempt = 0; attempt < 20; attempt += 1) {
        const socket = track(net.connect({ host: '127.0.0.1', port: ports.corridor }));
        socket.on('error', () => {});
        socket.on('connect', () => { socket.write('CONNECT example.com:4'); socket.resetAndDestroy(); });
      }
      await new Promise((resolve) => { setTimeout(resolve, 200); });
      expect(child.exitCode).toBe(null);
    });

    it('survives a huge header block and a slow client', async () => {
      const socket = track(net.connect({ host: '127.0.0.1', port: ports.corridor }));
      socket.on('error', () => {});
      await new Promise((resolve) => { socket.on('connect', resolve); });
      socket.write(`CONNECT ${PUBLIC_ADDRESS}:443 HTTP/1.1\r\n`);
      socket.write(`X-Filler: ${'a'.repeat(200_000)}\r\n\r\n`);
      await new Promise((resolve) => { setTimeout(resolve, 300); });
      socket.destroy();
      expect(child.exitCode).toBe(null);
    });

    // The tunnel cap itself needs 64 tunnels that were allowed, which needs names that resolve
    // to public addresses. The escape suite does that inside a space with a real allowed domain.
    // What is tested here is the cap that holds when nothing is allowed at all: sockets.

    // The cap only bounds what it can see. A refused client used to keep its socket for as long
    // as it liked: the socket allows half-open, the request timeouts stop applying once a CONNECT
    // has been handed over, and no tunnel exists to carry an idle limit. 128 refusals and the
    // corridor answered nothing, with nothing open anywhere.
    it('lets a refused socket go, so refusals cannot fill the connection cap', async () => {
      // One at a time, and each client keeps its socket after reading the refusal. With the
      // socket released at our end, every one of them is answered however long the clients hold
      // on. Without it the cap fills — 128 in the container, 20 here — and everything after that
      // is dropped, the corridor with it. Three times the cap, which is past the cap and past the
      // 16 refused clients the program waits on at once, with room to spare and no more sockets
      // than that needs: this loop was the most expensive thing in the file.
      const attempts = CAPS.corridor * 3;
      const kept = [];
      const outcomes = [];
      for (let attempt = 0; attempt < attempts; attempt += 1) {
        outcomes.push(await new Promise((resolve) => {
          // `allowHalfOpen`, so reading the refusal does not make this client close by itself.
          const socket = track(net.connect({ host: '127.0.0.1', port: ports.corridor, allowHalfOpen: true }));
          kept.push(socket);
          socket.on('error', () => resolve('error'));
          socket.on('connect', () => socket.write('CONNECT 203.0.113.7:443 HTTP/1.1\r\n\r\n'));
          socket.on('data', () => resolve('refused'));
          setTimeout(() => resolve('no answer'), 5_000);
        }));
      }
      expect(outcomes.filter((outcome) => outcome === 'refused')).toHaveLength(attempts);

      // And the corridor is still there, with nothing of its own held open.
      expect((await tunnelTo('blocked.test:443')).status).toMatch(/403/);
      expect(JSON.parse((await control('GET', '/health')).body)).toMatchObject({ ready: true });
      expect(child.exitCode).toBe(null);
      for (const socket of kept) socket.destroy();
    }, 60_000);

    it('keeps the refusal readable for a client that is still writing, and for one reading slowly', async () => {
      // Letting the socket go is what stopped the wedge above, and closing it while the client is
      // still talking costs this: a close with unread bytes in the receive queue is a reset, and a
      // reset throws away what the client has received and not yet read. Measured against a build
      // that closed at once: a client that wrote a megabyte after its CONNECT lost its 403 in
      // three runs out of five. The refusal stood either way; the reason header did not.
      const socket = track(net.connect({ host: '127.0.0.1', port: ports.corridor, allowHalfOpen: true }));
      let text = '';
      socket.on('error', () => {});
      socket.on('data', (chunk) => { text += chunk; });
      await new Promise((resolve) => { socket.on('connect', resolve); });
      socket.write('CONNECT 203.0.113.7:443 HTTP/1.1\r\n\r\n');
      socket.write('x'.repeat(4 * 1024 * 1024));
      const arrived = Date.now();
      while (!text.includes('\r\n\r\n') && Date.now() - arrived < 10_000) {
        await new Promise((resolve) => { setTimeout(resolve, 20); });
      }
      expect(text).toContain('403');
      expect(text).toContain('x-gatekeeper-reason: refused');

      // The discriminating part: the corridor is still holding this socket open, because the
      // client has not finished. A build that closed as soon as it had written the refusal fails
      // here every time, and the megabyte case above only fails on it sometimes.
      await new Promise((resolve) => { setTimeout(resolve, 300); });
      expect(socket.destroyed).toBe(false);

      // And it goes as soon as the client is done with it, which is what keeps refusals off the
      // connection cap. Only the last few refusals are ever waited on; the test above holds 140.
      const closed = new Promise((resolve) => { socket.on('close', resolve); setTimeout(resolve, 5_000); });
      socket.end();
      await closed;
      expect(socket.destroyed).toBe(true);

      // A client that takes its answer a byte at a time still gets all of it.
      const slow = await new Promise((resolve) => {
        const reader = track(net.connect({ host: '127.0.0.1', port: ports.corridor, allowHalfOpen: true }));
        let seen = '';
        reader.on('error', () => resolve(seen));
        reader.on('connect', () => {
          reader.pause();
          reader.write('CONNECT 203.0.113.7:443 HTTP/1.1\r\n\r\n');
          const timer = setInterval(() => {
            const byte = reader.read(1);
            if (byte) seen += byte;
            if (seen.includes('\r\n\r\n')) { clearInterval(timer); resolve(seen); }
          }, 10);
          reader.on('close', () => { clearInterval(timer); resolve(seen); });
        });
        setTimeout(() => resolve(seen), 10_000);
      });
      expect(slow).toContain('403');
      expect(slow).toContain('x-gatekeeper-reason: refused');
      expect(slow.endsWith('\r\n\r\n')).toBe(true);
    }, 30_000);

    // A cap is not exceeded by opening sockets quickly. A connection is dropped when it is
    // *accepted* past the cap, and accepting is the server's turn on the CPU: on a busy machine
    // the kernel's backlog keeps completing handshakes while the process is not scheduled, so
    // every client can be connected with nothing accepted past the cap and nothing to record.
    // Measured with the program stopped while 300 clients connected: 128 connected, no note,
    // ever, and no amount of waiting would have produced one. That is what failed in CI and then
    // on Windows beside the live Docker files, and lowering the cap did not fix it, because the
    // problem was never how many sockets the client opens.
    //
    // So these tests climb to the cap instead of flooding it, and every rung is *proven* accepted
    // before the next one opens: a listener only answers a connection it has accepted. Once the
    // cap is full of proven connections, the next one can only be dropped, whatever else the
    // machine is doing. A second gatekeeper runs with a cap of 2 on every listener, so a whole
    // test costs five sockets instead of forty; the first one keeps a corridor cap above the 16
    // refused clients the program waits on at once, which is what the test above it needs.
    describe('at a cap it cannot exceed', () => {
      let small;
      let smallPorts;

      /** One request, on a connection of its own, closed by its answer. Never keeps a slot. */
      const ask = (port, path) => new Promise((resolve) => {
        const request = track(http.request({ host: '127.0.0.1', port, path, agent: false }, (answer) => {
          let text = '';
          answer.on('data', (chunk) => { text += chunk; });
          answer.on('end', () => resolve({ status: answer.statusCode, body: text }));
        }));
        request.on('error', () => resolve({ status: 0, body: '' }));
        request.end();
      });

      const smallNotes = async (listener) => {
        const body = (await ask(smallPorts.control, '/journal')).body || '{"records":[]}';
        return JSON.parse(body).records.filter((entry) => entry.decision === 'deny:too-many-connections' && entry.listener === listener);
      };

      /**
       * A connection that has been accepted, proven by the listener answering on it, and then
       * kept. What comes back does not matter, only that it came: nothing is answered on a
       * connection that was never accepted.
       */
      const accepted = (port, line) => new Promise((resolve, reject) => {
        // `allowHalfOpen`, or the corridor's rungs do not hold: a refusal ends the gatekeeper's
        // side of the socket, and a client without it ends its own side in answer and the
        // connection is gone. Measured: two refusals left nothing behind and nothing was dropped.
        const socket = track(net.connect({ host: '127.0.0.1', port, allowHalfOpen: true }));
        socket.on('error', reject);
        socket.on('connect', () => socket.write(line));
        socket.on('data', () => resolve(socket));
        setTimeout(() => reject(new Error(`nothing answered on port ${port}`)), 10_000);
      });

      /**
       * A connection the listener drops: closed without a byte on it, because the cap was full of
       * connections this test had already watched being answered. The close is the observable,
       * and the note is written before it, so nothing here waits on a schedule.
       */
      const dropped = (port) => new Promise((resolve, reject) => {
        const socket = track(net.connect({ host: '127.0.0.1', port }));
        let answered = false;
        socket.on('data', () => { answered = true; });
        socket.on('error', () => resolve('closed'));
        socket.on('close', () => resolve(answered ? 'answered' : 'closed'));
        setTimeout(() => reject(new Error(`the listener on port ${port} neither answered nor let go`)), 10_000);
      });

      const settle = () => new Promise((resolve) => { setTimeout(resolve, 200); });

      beforeAll(async () => {
        ({ child: small, ports: smallPorts } = await startGatekeeper(['1500', '2', '2', '2', '300000', '1500']));
        const ready = Date.now();
        while (Date.now() - ready < 20_000) {
          if ((await ask(smallPorts.control, '/health')).status === 200) return;
          await settle();
        }
        throw new Error('the second gatekeeper never became ready');
      }, 30_000);

      afterAll(async () => {
        if (!small) return;
        const ended = new Promise((resolve) => { small.once('exit', resolve); setTimeout(resolve, 5_000); });
        small.kill('SIGKILL');
        await ended;
      });

      it('refuses a connection past the corridor cap, and notes it once', async () => {
        // Two refusals, each proven accepted by its own 403 and each kept: a refused client's
        // socket is held until the client is done with it, so these two fill a cap of 2.
        const held = [await accepted(smallPorts.corridor, 'CONNECT blocked.test:443 HTTP/1.1\r\n\r\n'), await accepted(smallPorts.corridor, 'CONNECT blocked.test:443 HTTP/1.1\r\n\r\n')];
        try {
          // Three more, one at a time, and every one of them is dropped.
          for (let attempt = 0; attempt < 3; attempt += 1) {
            expect(await dropped(smallPorts.corridor), 'a connection past the cap was served').toBe('closed');
          }
          // Recorded, and recorded once for three drops: five hundred notes would erase
          // everything else the space did.
          const notes = await smallNotes('corridor');
          expect(notes).toHaveLength(1);
          expect(notes[0]).toMatchObject({ host: '', port: 0 });
          // The process is alive, and the journal, which lives in its memory, is readable.
          expect(small.exitCode).toBe(null);
        } finally {
          for (const socket of held) socket.destroy();
        }
        // And it serves again once those connections let go.
        await settle();
        expect(await accepted(smallPorts.corridor, 'CONNECT blocked.test:443 HTTP/1.1\r\n\r\n')).toBeTruthy();
      }, 60_000);

      it('refuses a connection past the window cap, and notes it once', async () => {
        const held = [await accepted(smallPorts.window, 'GET /model/nothing/here HTTP/1.1\r\nHost: gatekeeper\r\n\r\n'), await accepted(smallPorts.window, 'GET /model/nothing/here HTTP/1.1\r\nHost: gatekeeper\r\n\r\n')];
        try {
          for (let attempt = 0; attempt < 3; attempt += 1) {
            expect(await dropped(smallPorts.window), 'a connection past the cap was served').toBe('closed');
          }
          expect(await smallNotes('window')).toHaveLength(1);
          // One listener's cap is not another's: the corridor is untouched by a full window.
          const onTheCorridor = await accepted(smallPorts.corridor, 'CONNECT blocked.test:443 HTTP/1.1\r\n\r\n');
          onTheCorridor.destroy();
          expect(small.exitCode).toBe(null);
        } finally {
          for (const socket of held) socket.destroy();
        }
      }, 60_000);

      it('refuses a connection past the control cap, and answers again afterwards', async () => {
        const held = [await accepted(smallPorts.control, 'GET /health HTTP/1.1\r\nHost: gatekeeper\r\n\r\n'), await accepted(smallPorts.control, 'GET /health HTTP/1.1\r\nHost: gatekeeper\r\n\r\n')];
        try {
          for (let attempt = 0; attempt < 3; attempt += 1) {
            expect(await dropped(smallPorts.control), 'a connection past the cap was served').toBe('closed');
          }
          expect(small.exitCode).toBe(null);
        } finally {
          for (const socket of held) socket.destroy();
        }
        // Read after they let go, because reading the journal needs the channel this test fills.
        // The host is the only client of that channel, which is why its cap is the smallest.
        await settle();
        expect((await ask(smallPorts.control, '/health')).status).toBe(200);
        expect(await smallNotes('control')).toHaveLength(1);
      }, 60_000);
    });

    it('is still healthy afterwards', async () => {
      expect((await control('GET', '/health')).status).toBe(200);
      expect(child.exitCode).toBe(null);
    });
  });

  describe('window', () => {
    beforeAll(async () => {
      seen = [];
      expect((await control('POST', '/grants', { id: 'anthropic', upstream: `http://127.0.0.1:${upstreamPort}/v1`, header: 'x-api-key', secret: SECRET })).status).toBe(200);
      expect((await control('POST', '/grants', { id: 'openai', upstream: `http://127.0.0.1:${upstreamPort}/v1`, header: 'authorization', secret: SECRET })).status).toBe(200);
    });

    it('refuses an unknown grant id', async () => {
      const answer = await throughWindow('/model/nothing-here/v1/messages');
      expect(answer.status).toBe(403);
      expect(await decisionFor('unknown-grant')).toMatchObject({ listener: 'window', decision: 'deny:no-grant' });
    });

    it('refuses a path that is not a grant', async () => {
      expect((await throughWindow('/')).status).toBe(403);
      expect((await throughWindow('/model/')).status).toBe(403);
      expect((await throughWindow('/../model/anthropic')).status).toBe(403);
    });

    it('adds the grant\'s own header and takes away what the space sent', async () => {
      const answer = await throughWindow('/model/anthropic/messages?stream=true', {
        authorization: 'Bearer sk-fake-inside',
        'x-api-key': 'sk-fake-inside',
        'x-keep-me': 'yes',
      });

      expect(answer.status).toBe(200);
      const request = seen.at(-1);
      expect(request.url).toBe('/v1/messages?stream=true');
      expect(request.headers['x-api-key']).toBe(SECRET);
      expect(request.headers.authorization).toBeUndefined();
      expect(request.headers['x-keep-me']).toBe('yes');
      // The answer goes back to the space, so it must not carry the key.
      expect(answer.body).not.toContain(SECRET);
    });

    it('adds no header for a grant without a secret, and still takes away what the space sent', async () => {
      expect((await control('POST', '/grants', { id: 'open-registry', upstream: `http://127.0.0.1:${upstreamPort}/npm` })).status).toBe(200);
      const answer = await throughWindow('/model/open-registry/-/package/left-pad', {
        authorization: 'Bearer sk-fake-inside',
        'x-api-key': 'sk-fake-inside',
        'x-keep-me': 'yes',
      });
      expect(answer.status).toBe(200);
      const request = seen.at(-1);
      expect(request.url).toBe('/npm/-/package/left-pad');
      expect(request.headers.authorization).toBeUndefined();
      expect(request.headers['x-api-key']).toBeUndefined();
      expect(request.headers['x-keep-me']).toBe('yes');
      expect(Object.keys(request.headers).some((name) => /key|auth|token/i.test(name))).toBe(false);
    });

    it('sets the grant\'s own headers beside the key, over whatever the space sent under their names, and refuses the names it owns', async () => {
      expect((await control('POST', '/grants', { id: 'lighthouse', upstream: `http://127.0.0.1:${upstreamPort}/v1`, header: 'authorization', secret: SECRET, headers: { 'X-Team': 'platform', 'x-gateway-token': 'gw-secret' } })).status).toBe(200);
      const answer = await throughWindow('/model/lighthouse/chat/completions', { 'x-team': 'space-says-admin', 'x-keep-me': 'yes', authorization: 'Bearer space-window' });
      expect(answer.status).toBe(200);
      const request = seen.at(-1);
      expect(request.headers.authorization).toBe(`Bearer ${SECRET}`);
      expect(request.headers['x-team']).toBe('platform');
      expect(request.headers['x-gateway-token']).toBe('gw-secret');
      expect(request.headers['x-keep-me']).toBe('yes');
      expect(answer.body).not.toContain('gw-secret');
      // A keyless grant may carry headers too; the credential names and the hop-by-hop ones never.
      expect((await control('POST', '/grants', { id: 'open-headers', upstream: `http://127.0.0.1:${upstreamPort}/v1`, headers: { 'x-team': 'platform' } })).status).toBe(200);
      for (const bad of [{ host: 'evil' }, { authorization: 'x' }, { 'content-length': '0' }, { 'bad name!': 'x' }, { 'x-empty': '' }, { 'x-team': 'команда' }, { 'x-team': 'a\r\nx-injected: b' }, 'not-an-object', ['x-team', 'platform']]) {
        expect((await control('POST', '/grants', { id: 'bad', upstream: `http://127.0.0.1:${upstreamPort}/v1`, headers: bad })).status, JSON.stringify(bad)).toBe(400);
      }
      expect((await control('POST', '/grants', { id: 'bad', upstream: `http://127.0.0.1:${upstreamPort}/v1`, header: 'x-api-key', secret: SECRET, headers: { 'x-api-key': 'twice' } })).status).toBe(400);
      expect((await control('POST', '/grants', { id: 'bad', upstream: `http://127.0.0.1:${upstreamPort}/v1`, headers: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`x-h-${i}`, 'v'])) })).status).toBe(400);
      expect((await throughWindow('/model/bad/x')).status).toBe(403);
    });

    it('takes the grant\'s own header name away too, so a placeholder the space sends never reaches the upstream', async () => {
      expect((await control('POST', '/grants', { id: 'google', upstream: `http://127.0.0.1:${upstreamPort}/v1`, header: 'X-Goog-Api-Key', secret: SECRET })).status).toBe(200);
      await throughWindow('/model/google/models', { 'X-Goog-Api-Key': 'space-window' });
      expect(seen.at(-1).headers['x-goog-api-key']).toBe(SECRET);
    });

    it('sends a bearer token for an OpenAI-style grant', async () => {
      await throughWindow('/model/openai/responses');
      expect(seen.at(-1).headers.authorization).toBe(`Bearer ${SECRET}`);
      expect(seen.at(-1).url).toBe('/v1/responses');
    });

    it('keeps no path, no query and no header in its journal', async () => {
      const at = await journalMark();
      await throughWindow('/model/anthropic/messages?key=leak-me', { authorization: 'Bearer sk-fake-inside' });
      const record = await decisionFor('127.0.0.1', at);
      expect(record).toMatchObject({ listener: 'window', host: '127.0.0.1', decision: 'allow' });
      expect(Object.keys(record)).toEqual(['at', 'listener', 'host', 'port', 'method', 'decision']);
      expect(JSON.stringify(record)).not.toMatch(/messages|leak-me|Bearer/);
    });


    it('refuses a path that walks out of the grant, encoded or not', async () => {
      // Same host and same credential, so not an escape; a trap once git and a private registry
      // come through here, where the path is what says which repository or which package. The
      // encoded forms are the point: the rest reaches the upstream verbatim, and a server that
      // decodes before it resolves reads every line below as the same climb. Each one was
      // measured reaching the upstream when this rule only looked for a literal `..`.
      const climbs = [
        '/model/anthropic/../admin',
        '/model/anthropic/%25252e%25252e/admin',
        '/model/anthropic/%2e%2e/admin',
        '/model/anthropic/..%2fadmin',
        '/model/anthropic/.%2e/admin',
        '/model/anthropic/x/..%5cadmin',
        '/model/anthropic/..;/admin',
        '/model/anthropic/%252e%252e/admin',
        '/model/anthropic/v1/../../admin',
        '/model/anthropic/..',
      ];
      for (const path of climbs) {
        const before = seen.length;
        const at = await journalMark();
        const answer = await throughWindow(path);
        expect(answer.status, path).toBe(403);
        // Refused here, not merely answered 403 after the upstream had already served it.
        expect(seen.length, path).toBe(before);
        // And the journal says which refusal this was. Read as `deny:no-grant` it would tell the
        // user the agent guessed at a grant id, which is a different thing to have done.
        expect(await decisionFor('grant-path', at), path).toMatchObject({ listener: 'window', decision: 'deny:path-walks-out' });
      }
      // The space learns nothing from the difference: a real id that climbs and an id that does
      // not exist get the same status and the same body.
      expect((await throughWindow('/model/anthropic/../admin')).body).toBe((await throughWindow('/model/nothing-here/admin')).body);
      // A percent sign is not itself the offence. A scoped npm package is fetched exactly like
      // this, and that window is half the reason the rule exists, so refusing every `%` is out.
      expect((await throughWindow('/model/anthropic/@scope%2fname/-/name-1.0.0.tgz')).status).toBe(200);
      expect(seen.at(-1).url).toBe('/v1/@scope%2fname/-/name-1.0.0.tgz');
      // And the ordinary path still goes through.
      expect((await throughWindow('/model/anthropic/messages')).status).toBe(200);
    });

    it('gives up on an upstream that accepts and never answers', async () => {
      // A deadline of its own: without one, 64 of these hold every slot the window has, in and
      // out, for the life of the space. This gatekeeper was started with a short one so the test
      // can watch it pass; the container command carries 300000.
      // A `net.Server` has no `closeAllConnections`, so its sockets are kept and destroyed by
      // hand; a `close()` that waits for one is a hook that never returns.
      const held = [];
      const silent = net.createServer((socket) => { socket.on('error', () => {}); held.push(socket); });
      await new Promise((resolve) => { silent.listen(0, '127.0.0.1', resolve); });
      const port = silent.address().port;
      try {
        await control('POST', '/grants', { id: 'silent', upstream: `http://127.0.0.1:${port}/v1`, header: 'authorization', secret: SECRET });
        const at = await journalMark();
        const started = Date.now();
        const answer = await throughWindow('/model/silent/messages');
        expect(answer.status).toBe(504);
        // The one clock reading left in this file that means anything: how long the window took,
        // measured entirely inside this process and compared against nothing the program said.
        expect(Date.now() - started).toBeGreaterThan(1_000);
        expect((await decisionFor('127.0.0.1', at)).decision).toBe('failed:timeout');
        // And it is one record, not a timeout followed by the error its own destroy causes.
        const since = await recordsSince(at);
        expect(since.filter((entry) => entry.decision.startsWith('failed:'))).toHaveLength(1);
      } finally {
        for (const socket of held) socket.destroy();
        await new Promise((resolve) => {
          const done = setTimeout(resolve, 2_000);
          silent.close(() => { clearTimeout(done); resolve(); });
        });
      }
    }, 30_000);

    it.each([
      ['its control channel on loopback', () => `http://127.0.0.1:${ports.control}/`],
      ['its corridor on loopback', () => `http://127.0.0.1:${ports.corridor}/`],
      ['its window on loopback', () => `http://127.0.0.1:${ports.window}/`],
      // The listeners bind every interface, so the address the space reaches them on is not
      // loopback. A grant pointing there would feed the window into itself until its sockets ran out.
      ['its window on the address a client reaches it on', () => `http://${ownAddress()}:${ports.window}/`],
      ['its corridor on that same address', () => `http://${ownAddress()}:${ports.corridor}/`],
    ])('refuses to proxy into %s', async (title, upstream) => {
      const id = `loop-${Math.random().toString(36).slice(2, 8)}`;
      expect((await control('POST', '/grants', { id, upstream: upstream(), header: 'authorization', secret: SECRET })).status).toBe(200);
      const at = await journalMark();
      const answer = await throughWindow(`/model/${id}/network`);
      expect(answer.status).toBe(403);
      const host = new URL(upstream()).hostname;
      expect((await decisionFor(host, at)).decision).toBe('deny:own-listener');
    });

    it('answers 502 when the upstream is not there, without the secret in the message', async () => {
      const port = await freePort();
      await control('POST', '/grants', { id: 'gone', upstream: `http://127.0.0.1:${port}/v1`, header: 'authorization', secret: SECRET });
      const answer = await throughWindow('/model/gone/messages');
      expect(answer.status).toBe(502);
      expect(answer.body).not.toContain(SECRET);
    });
  });

  describe('control channel', () => {
    it.each([
      ['a mode that does not exist', '/network', { mode: 'everything', domains: [] }],
      ['a write choice that does not exist', '/network', { mode: 'open', domains: [], writes: 'no' }],
      ['a wildcard on the allowlist', '/network', { mode: 'allowlist', domains: ['*.googleapis.com'] }],
      ['an address on the allowlist', '/network', { mode: 'allowlist', domains: ['10.0.0.1'] }],
      // The list and a target go through the same predicate, so the host cannot put an entry
      // on the list that the corridor would then always refuse as an address.
      ['a numeric last label on the allowlist', '/network', { mode: 'allowlist', domains: ['1.1.1'] }],
      ['a hex last label on the allowlist', '/network', { mode: 'allowlist', domains: ['a.com.0x2'] }],
      ['a single-label name on the allowlist', '/network', { mode: 'allowlist', domains: ['localhost'] }],
      ['a grant with a header and no secret', '/grants', { id: 'x', upstream: 'https://api.example.com', header: 'authorization' }],
      ['a grant with a secret and no header', '/grants', { id: 'x', upstream: 'https://api.example.com', secret: SECRET }],
      ['a grant with an empty secret', '/grants', { id: 'x', upstream: 'https://api.example.com', header: 'authorization', secret: '' }],
      ['a grant with an id that is not one', '/grants', { id: '../../etc', upstream: 'https://api.example.com', header: 'authorization', secret: SECRET }],
      ['a grant with a header name that is not one', '/grants', { id: 'x', upstream: 'https://api.example.com', header: 'a: b', secret: SECRET }],
      ['a grant whose upstream is not a URL', '/grants', { id: 'x', upstream: 'not a url', header: 'authorization', secret: SECRET }],
      ['a grant whose upstream is a file', '/grants', { id: 'x', upstream: 'file:///etc/passwd', header: 'authorization', secret: SECRET }],
    ])('refuses %s', async (title, path, body) => {
      const answer = await control('POST', path, body);
      expect(answer.status).toBe(400);
    });

    it('says what it holds: the mode, the names and the grant ids, and never a secret', async () => {
      expect((await control('POST', '/network', { mode: 'allowlist', domains: ['Example.com.', 'example.org'] })).status).toBe(200);
      const policy = JSON.parse((await control('GET', '/policy')).body);
      expect(policy).toMatchObject({ mode: 'allowlist', domains: ['example.com', 'example.org'] });
      expect(policy.grants).toEqual(expect.arrayContaining(['anthropic', 'openai']));
      expect(JSON.stringify(policy)).not.toContain(SECRET);
    });

    it('answers 404 for anything else and 400 for a body that is not JSON', async () => {
      expect((await control('GET', '/grants')).status).toBe(404);
      expect((await control('POST', '/anything')).status).toBe(404);
      expect((await control('POST', '/network')).status).toBe(400);
      expect((await control('GET', '/health')).status).toBe(200);
    });

    it('records a connection that was allowed and did not happen, apart from a refusal', async () => {
      // 198.51.100.0/24 is documentation space: allowed by every rule here, and nothing answers.
      // The corridor's own connect timeout ends it, so this waits for the record, not the socket.
      await control('POST', '/network', { mode: 'open', domains: [] });
      const at = await journalMark();
      connect('CONNECT one.example.test:443 HTTP/1.1', { keepOpen: true, wait: 500 });
      const decision = await decisionFor('one.example.test', at);
      // It never resolves here, so what is recorded is the refusal that follows the name rules.
      // The failure record is covered where a host does resolve: the escape suite.
      expect(decision.decision).toMatch(/^deny:unresolved:/);
    }, 30_000);

    it('keeps the journal readable however long the space makes its request targets', async () => {
      // A plain proxy request carries its target in the request line, up to the 16 KiB header cap.
      // Without a cut on the host, 201 of these made the journal larger than the host channel
      // reads, and the space could hold it that way: the user's only view of what it tried.
      const longName = `${'a'.repeat(200)}.${'b'.repeat(200)}.${'c'.repeat(200)}.example.com`;
      // Enough of them to fill the ring with the longest host a request can carry, which is the
      // worst case the host channel has to read back. These go through `http.globalAgent`, which
      // keeps connections alive on Node 22, so 520 requests cost a handful of sockets.
      for (let attempt = 0; attempt < 520; attempt += 1) {
        await throughPlainProxy(`http://${longName}/${'p'.repeat(4_000)}`);
      }
      const answer = await control('GET', '/journal');
      expect(answer.status).toBe(200);
      // The host channel refuses a journal over a megabyte, and a full ring must stay under it.
      expect(answer.body.length).toBeLessThan(1024 * 1024);
      const records = JSON.parse(answer.body).records;
      expect(records).toHaveLength(500);
      for (const entry of records) expect(entry.host.length).toBeLessThanOrEqual(256);
      expect(records.at(-1).host.length).toBe(256);
    }, 60_000);

    it('separates one attempt from the next by count, not by any clock', async () => {
      // Every assertion in this file that reads a decision reads it after a mark, and the mark is
      // a count of records for a reason: the stamp on a record is written by the program's clock
      // and the mark would be read from the test's, and on Windows those disagree by about a
      // timer tick. Two attempts against the same host inside one tick are indistinguishable by
      // time and perfectly distinguishable by count. That is what this asserts.
      const host = 'twice.example.test';
      await tunnelTo(`${host}:443`);
      await decisionFor(host);

      const mark = await journalMark();
      await tunnelTo(`${host}:443`);
      await decisionFor(host, mark);

      const since = await recordsSince(mark);
      expect(since).toHaveLength(1);
      expect(since[0].host).toBe(host);
      // And a mark taken after everything sees nothing at all, however fast the machine is.
      expect(await recordsSince(await journalMark())).toHaveLength(0);
    });

    it('keeps the number of journal records bounded and counts what it dropped', async () => {
      const before = await journal();
      // Through the plain-proxy path, which keeps its connections alive: a raw CONNECT needs a
      // socket of its own, and 520 of those is the biggest platform-specific cost in this file
      // on a Windows host, where a closed socket's port waits two minutes to come back.
      for (let attempt = 0; attempt < 520; attempt += 1) {
        expect((await throughPlainProxy(`http://filler-${attempt}.example.test/`)).status, 'the corridor stopped answering during the run').toBe(403);
      }
      // And one raw CONNECT, so the ring holds both shapes of record.
      expect((await tunnelTo('blocked.test:443')).status).toMatch(/403/);
      await decisionFor('blocked.test');
      const after = await journal();
      expect(after.records).toHaveLength(500);
      expect(after.dropped).toBeGreaterThan(before.dropped);
      // Since when it records: its own start, as an instant, so the host can say that nothing older exists.
      expect(after.since).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(after.since).toBe(before.since);
      // The oldest records went, the newest stayed.
      expect(after.records.at(-1).host).toBe('blocked.test');
    }, 60_000);
  });
});

// The rules, called directly. The program is the container's main module and runs its listeners
// only then; a test can require it instead. This is where every range and every target form is
// covered, because the corridor takes names only and an address never reaches the range rules
// through a CONNECT any more.
describe('the rules of the gatekeeper program', () => {
  const rules = createRequire(import.meta.url)(PROGRAM);

  describe('isBlockedAddress', () => {
    it.each([
      ['this network', '0.0.0.0'],
      ['this network, another address', '0.1.2.3'],
      ['a private address', '10.1.2.3'],
      ['carrier-grade NAT', '100.64.0.1'],
      ['the end of carrier-grade NAT', '100.127.255.255'],
      ['loopback', '127.0.0.1'],
      ['another loopback address', '127.1.2.3'],
      ['link-local and cloud metadata', '169.254.169.254'],
      ['the private range around a Docker bridge', '172.17.0.1'],
      ['the start of that range', '172.16.0.0'],
      ['the end of that range', '172.31.255.255'],
      ['IETF protocol assignments', '192.0.0.1'],
      ['a home network', '192.168.1.1'],
      ['benchmarking', '198.18.0.1'],
      ['benchmarking, second half', '198.19.0.1'],
      ['multicast', '224.0.0.1'],
      ['reserved', '240.0.0.1'],
      ['broadcast', '255.255.255.255'],
      ['the unspecified IPv6 address', '::'],
      ['IPv6 loopback', '::1'],
      ['a unique local address', 'fc00::1'],
      ['another unique local address', 'fd12:3456::1'],
      ['IPv6 link-local', 'fe80::1'],
      ['IPv6 link-local with a zone id', 'fe80::1%eth0'],
      ['IPv6 multicast', 'ff02::1'],
      ['an IPv4-mapped private address', '::ffff:10.0.0.1'],
      ['IPv4-mapped loopback', '::ffff:127.0.0.1'],
      ['IPv4-mapped loopback in hex', '::ffff:7f00:1'],
      ['an IPv4-compatible loopback address', '::127.0.0.1'],
      ['NAT64 around loopback', '64:ff9b::7f00:1'],
      ['NAT64 around a private address', '64:ff9b::a00:1'],
      ['6to4 around loopback', '2002:7f00:0001::1'],
      ['6to4 around a private address', '2002:0a00:0001::1'],
      ['something that is not an address', 'not-an-address'],
      ['an empty string', ''],
      ['a name that looks like one', '10.0.0.1.example.com'],
    ])('refuses %s (%s)', (title, address) => {
      expect(rules.isBlockedAddress(address)).toBe(true);
    });

    it.each([
      ['a documentation address', '203.0.113.7'],
      ['another documentation range', '198.51.100.7'],
      ['a public address', '104.18.41.241'],
      ['the first public address after the private range', '172.32.0.1'],
      ['the last public address before it', '172.15.255.255'],
      ['a public address next to carrier-grade NAT', '100.63.255.255'],
      ['a public IPv6 address', '2001:db8::1'],
      ['an IPv4-mapped public address', '::ffff:203.0.113.7'],
      ['6to4 around a public address', '2002:cb00:7107::1'],
    ])('allows %s (%s)', (title, address) => {
      expect(rules.isBlockedAddress(address)).toBe(false);
    });
  });

  describe('refuseTarget', () => {
    const inMode = (mode, domains = []) => { rules.setNetwork({ mode, domains }); };

    it('refuses auth.openai.com in both modes, whatever the list says', () => {
      inMode('open');
      expect(rules.refuseTarget('auth.openai.com', 443)).toBe('deny:always-refused');
      expect(rules.refuseTarget('AUTH.OpenAI.com.', 443)).toBe('deny:always-refused');
      inMode('allowlist', ['auth.openai.com']);
      expect(rules.refuseTarget('auth.openai.com', 443)).toBe('deny:always-refused');
    });

    it.each([
      // Dotted and IPv6 forms.
      '104.18.41.241', '203.0.113.7', '10.0.0.1', '127.0.0.1',
      '::ffff:104.18.41.241', '::ffff:6812:29f1', '2606:4700::6812:29f1', '64:ff9b::6812:29f1', '2002:6812:29f1::1',
      // The spellings `getaddrinfo` takes that four dotted octets do not describe.
      '1746020849', '16843009', '4294967295', '0x01010101', '0xc0a80001', '1.1.257', '1.16843009',
      '0x1.0x1.0x1.0x1', '0177.0.0.1', '0.0x0.0', '192.168.257',
      // Not a name either: no dot, non-ASCII, or a label that is not a label.
      'localhost', 'auth.openai.com\u3002', 'auth.openai\uff0ecom', 'auth\uff61openai.com',
      '.example.com', 'exam ple.com', 'example..com', 'exa_mple.com', '-example.com', '',
    ])('refuses %j in both modes, before the port rule', (address) => {
      for (const port of [443, 80, 8443]) {
        inMode('open');
        expect(rules.refuseTarget(address, port)).toBe('deny:not-a-name');
        inMode('allowlist', ['example.com']);
        expect(rules.refuseTarget(address, port)).toBe('deny:not-a-name');
      }
    });

    it.each([
      'example.com', 'anything.example.org', 'sub.domain.example.co.uk', 'a.io', 'xn--80ak6aa92e.com',
      'registry-1.docker.io', 'api.anthropic.com', '1.1.1.1.example.com', 'v2.example.com', 'EXAMPLE.com.',
    ])('takes %j for an ordinary name', (name) => {
      inMode('open');
      expect(rules.refuseTarget(name, 443)).toBe(null);
    });

    it('allows any name in open mode, on 443 only', () => {
      inMode('open');
      expect(rules.refuseTarget('example.com', 443)).toBe(null);
      expect(rules.refuseTarget('anything.example.org', 443)).toBe(null);
      for (const port of [80, 22, 9418, 8443]) {
        expect(rules.refuseTarget('example.com', port)).toBe('deny:port');
      }
    });

    it('allows a name on the list on 443 only in allowlist mode', () => {
      inMode('allowlist', ['example.com']);
      expect(rules.refuseTarget('example.com', 443)).toBe(null);
      expect(rules.refuseTarget('EXAMPLE.com.', 443)).toBe(null);
      for (const port of [80, 22, 8443]) {
        expect(rules.refuseTarget('example.com', port)).toBe('deny:port');
      }
      for (const name of ['sub.example.com', 'notexample.com', 'example.com.evil.test']) {
        expect(rules.refuseTarget(name, 443)).toBe('deny:not-on-allowlist');
      }
    });
  });

  // The plumbing of an established tunnel, with plain sockets standing in for the two the
  // corridor joins. It is tested apart from the rules because no address this machine has is one
  // the corridor would tunnel to, by design, so a tunnel cannot be established here any other way.
  //
  // The sockets are built the way the program builds them: the space-facing one as an
  // `http.Server` accepts it, half-open allowed, and the one out as `net.connect` makes it, which
  // the program now also asks for half-open.
  describe('guardTunnelIdle', () => {
    it('arms the idle limit on a tunnel and destroys the socket when it passes', () => {
      const { guardTunnelIdle, TUNNEL_IDLE_MS } = createRequire(import.meta.url)(PROGRAM);
      expect(TUNNEL_IDLE_MS).toBe(300_000);
      let armed = null;
      let destroyed = false;
      guardTunnelIdle({ setTimeout: (milliseconds, callback) => { armed = { milliseconds, callback }; }, destroy: () => { destroyed = true; } });
      expect(armed.milliseconds).toBe(300_000);
      armed.callback();
      expect(destroyed).toBe(true);
    });
  });

  describe('chooseAddress', () => {
    const v4 = { address: '203.0.113.7', family: 4 };
    const other4 = { address: '198.51.100.7', family: 4 };
    const v6 = { address: '2001:db8::1', family: 6 };

    it('takes IPv4 whatever order the resolver answered in', () => {
      // The gatekeeper's outer network is made with --ipv6=false, so an IPv6 address there is a
      // connection that cannot happen. A resolver that answers AAAA first would otherwise turn an
      // allowed host into a 502.
      expect(rules.chooseAddress([v4, v6])).toBe(v4);
      expect(rules.chooseAddress([v6, v4])).toBe(v4);
      expect(rules.chooseAddress([v6, v6, v4, other4])).toBe(v4);
    });

    it('keeps the resolver order within a family', () => {
      expect(rules.chooseAddress([v4, other4])).toBe(v4);
      expect(rules.chooseAddress([other4, v4])).toBe(other4);
    });

    it('still attempts an IPv6-only host, so its failure says what happened', () => {
      expect(rules.chooseAddress([v6])).toBe(v6);
    });
  });

  describe('walksOutOfGrant', () => {
    it.each([
      ['a literal climb', '/../admin'],
      ['both dots encoded', '/%2e%2e/admin'],
      ['the separator encoded', '/..%2fadmin'],
      ['one dot encoded', '/.%2e/admin'],
      ['a backslash separator, encoded', '/x/..%5cadmin'],
      ['a path parameter after the dots', '/..;/admin'],
      ['encoded twice', '/%252e%252e/admin'],
      ['encoded four times', '/%25252e%25252e/admin'],
      ['encoded five times', '/%2525252e%2525252e/admin'],
      ['dots and separator both encoded', '/%2e%2e%2fadmin'],
      ['a climb at the very end', '/v1/..'],
      ['a climb before the query', '/v1/..?x=1'],
      ['a percent that is not an escape', '/%zz'],
    ])('refuses %s', (_what, rest) => {
      expect(rules.walksOutOfGrant(rest)).toBe(true);
    });

    it.each([
      ['an ordinary path', '/messages'],
      ['a scoped npm package', '/@scope%2fname/-/name-1.0.0.tgz'],
      ['an encoded space in a query', '/messages?q=hello%20world'],
      ['two dots inside a name', '/a..b/c'],
      ['three dots', '/...'],
      ['a git ref request', '/owner/repo.git/info/refs?service=git-upload-pack'],
      ['nothing at all', ''],
    ])('allows %s', (_what, rest) => {
      expect(rules.walksOutOfGrant(rest)).toBe(false);
    });
  });

  describe('splitTarget', () => {
    it('reads a name, a port and a bracketed IPv6 address', () => {
      expect(rules.splitTarget('example.com:443')).toEqual({ host: 'example.com', port: 443 });
      expect(rules.splitTarget('[2001:db8::1]:8443')).toEqual({ host: '2001:db8::1', port: 8443 });
    });

    it.each(['', 'example.com', 'example.com:', ':443', 'example.com:0', 'example.com:99999', 'example.com:-1', 'a b:443', 'http://example.com/x:443'])(
      'refuses %j',
      (target) => {
        expect(rules.splitTarget(target)).toBe(null);
      },
    );
  });
});

describe('the gatekeeper program and its bind address', () => {
  const folders = [];
  afterAll(() => { for (const folder of folders) fs.rmSync(folder, { recursive: true, force: true }); });

  /** Starts the program with `bind` as its first argument and waits for it to listen or to leave. */
  const startWith = (bind, ports = ['0', '0', '0']) => new Promise((resolve) => {
    const child = spawn(process.execPath, [PROGRAM, bind, ...ports.map(String)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    const finish = (outcome) => { resolve({ ...outcome, output, stop: () => child.kill() }); };
    child.stdout.on('data', (chunk) => { output += chunk; if (output.includes('gatekeeper: corridor')) finish({ exited: null }); });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.on('close', (code) => finish({ exited: code }));
  });

  /** One TCP connect: `connected` or the error code. */
  const tryConnect = (host, port) => new Promise((resolve) => {
    const socket = net.connect({ host, port });
    socket.setTimeout(3000, () => { socket.destroy(); resolve('timeout'); });
    socket.on('connect', () => { socket.destroy(); resolve('connected'); });
    socket.on('error', (error) => resolve(error.code));
  });

  it('listens on the address the file beside it holds, and on nothing else', async () => {
    const other = ownAddress();
    // Without a second address of this machine there is nothing to be refused on.
    expect(other, 'this machine has no address but loopback').not.toBe('127.0.0.1');
    const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'openchamber-gatekeeper-bind-'));
    folders.push(folder);
    const file = path.join(folder, 'bind');
    fs.writeFileSync(file, '127.0.0.1\n');
    // The same race as in `startGatekeeper`: a port can be taken before the program binds it.
    let ports;
    let started;
    for (let attempt = 1; ; attempt += 1) {
      ports = [await freePort(), await freePort(), await freePort()];
      started = await startWith(file, ports);
      if (attempt === 3 || started.exited === null || !started.output.includes('EADDRINUSE')) break;
    }
    try {
      expect(started.exited).toBeNull();
      // Positive control: the address in the file answers on both listeners the space uses.
      expect(await tryConnect('127.0.0.1', ports[0])).toBe('connected');
      expect(await tryConnect('127.0.0.1', ports[1])).toBe('connected');
      // Another address of the same machine does not: the program did not listen everywhere.
      expect(await tryConnect(other, ports[0])).toBe('ECONNREFUSED');
      expect(await tryConnect(other, ports[1])).toBe('ECONNREFUSED');
    } finally {
      started.stop();
    }
  });

  it('reads no bind file when it is required rather than run, whatever the runner\'s arguments are', () => {
    // `node -e` puts its own arguments from argv[1], so the path lands where the program reads its bind argument.
    // A runner whose first argument is a path would otherwise have its file read, and a
    // missing one would end the test process.
    const required = spawnSync(process.execPath, ['-e', `require(${JSON.stringify(PROGRAM)}); console.log('still here')`, 'runner', '/no/such/bind/file'], { encoding: 'utf8' });
    expect(required.status).toBe(0);
    expect(required.stdout).toContain('still here');
  });

  // A gatekeeper made before stage 5b has `0.0.0.0` in its command rather than the file.
  it.each(['0.0.0.0', '::', 'gatekeeper'])('does not start when it is told to listen on %j directly', async (bind) => {
    const started = await startWith(bind);
    expect(started.exited).toBe(2);
    expect(started.output).not.toContain('gatekeeper: corridor');
  });

  it.each([
    ['is missing', null],
    ['is empty', ''],
    ['names every interface', '0.0.0.0'],
    ['names every IPv6 interface', '::'],
    ['is not an address', 'gatekeeper'],
  ])('does not start when the bind file %s', async (title, content) => {
    const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'openchamber-gatekeeper-bind-'));
    folders.push(folder);
    const file = path.join(folder, 'bind');
    if (content !== null) fs.writeFileSync(file, content);
    const started = await startWith(file);
    expect(started.exited).toBe(2);
    expect(started.output).toContain('gatekeeper:');
    expect(started.output).not.toContain('gatekeeper: corridor');
  });
});

describe('the gatekeeper program as a file', () => {
  const source = readFileSync(PROGRAM, 'utf8');

  it('binds the control channel to loopback and never to the space-facing interface', () => {
    expect(source).toContain("const CONTROL_HOST = '127.0.0.1';");
    expect(source).toContain('await listen(control, controlPort, CONTROL_HOST);');
  });

  it('answers a tunnel it cannot carry before it carries anything, and never inside a response', () => {
    // The corridor now terminates the space's TLS, so there is no raw tunnel to write `HTTP/1.1`
    // into: every answer is an HTTP response on the decrypted connection, and only before its
    // headers have gone out. A response that has started is destroyed instead.
    expect(source).toContain('if (!response.headersSent) refuseDecrypted(response, 502, UNREACHABLE');
    expect(source).toContain('else response.destroy();');
  });

  it('lets a 502 leave the same way a 403 does, drained rather than reset', () => {
    // The answer to an allowed host that could not be reached carries the one header that tells
    // the space "allowed, and the connection out failed" apart from "refused", which is the
    // distinction the journal and this reason header exist for. It is a real HTTP answer on the
    // decrypted connection now, so the reset concern belongs to the HTTP server, not to a raw
    // socket write.
    const branch = source.slice(source.indexOf('outgoing.on(\'error\''), source.indexOf('response.on(\'close\''));
    expect(branch).toContain('refuseDecrypted(response, 502, UNREACHABLE');
    expect(branch).toContain('response.destroy()');
  });

  it('connects to the address it checked, and never resolves the name again', () => {
    expect(source).toContain('lookup: fixedLookup(target.address, target.family)');
    expect(source).toContain('servername: target.host');
  });

  it('does not turn a cancelled upload into a blank blocked row', () => {
    // The reset is ordinary traffic; a write already has its `failed:<code>` record, and a second
    // `deny:unreadable-request` with no host would appear in the user's blocked list.
    expect(source).toContain("code !== 'ECONNRESET' && code !== 'EPIPE' && code !== 'ERR_STREAM_PREMATURE_CLOSE'");
  });

  it('arms the tunnel idle limit before it ends TLS, and keeps it on the decrypted server', () => {
    // The place is taken when the 200 goes out, and the TLS handshake can take forever. The timer
    // must be on the socket before the wrap, or sixty-four silent CONNECTs close the corridor.
    expect(source.indexOf('guardTunnelIdle(clientSocket);')).toBeGreaterThan(source.indexOf('200 Connection Established'));
    expect(source.indexOf('guardTunnelIdle(clientSocket);')).toBeLessThan(source.indexOf('new tls.TLSSocket'));
    // The HTTP server resets the socket timeout to its own on every request; without this the
    // limit would cover only the first request of a keep-alive connection.
    expect(source).toContain('decrypted.timeout = TUNNEL_IDLE_MS;');
  });

  it('needs nothing but the standard library', () => {
    const required = [...source.matchAll(/require\('([^']+)'\)/g)].map((match) => match[1]);
    expect(required.every((name) => name.startsWith('node:'))).toBe(true);
  });
});
