// Shared memory with the server inside a space, the local build. Runs only with
// OPENCHAMBER_TEST_DOCKER_PACKED=1, because the published OpenChamber in a registry tools volume
// does not have this store yet. A space made through the journey with a folder source in write
// mode: the server inside lists the seeded entry, counts it in the session index, records an edit
// and a delete as operations, and the host's sync publishes both to the folder.

import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createSpacesHost } from '../host.js';
import { createHostProviders } from '../host-providers.js';
import { runCommand } from '../run-command.js';
import { packLocalTools } from '../tools-pack.js';
import { createPackedToolsSource, readHostToolVersions } from '../tools.js';
import { createLiveDockerPlace } from './docker-live-support.js';

const PACKED_ENABLED = process.env.OPENCHAMBER_TEST_DOCKER_PACKED === '1';
const CREATE_TIMEOUT_MS = 25 * 60_000;
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
const until = async (check, timeoutMs = 10_000) => {
  const deadline = Date.now() + timeoutMs;
  while (!(await check()) && Date.now() < deadline) await sleep(500);
  return check();
};
const write = (root, relative, body) => {
  const file = path.join(root, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
};

describe.skipIf(!PACKED_ENABLED)('shared memory with the server inside a space: docker (live, local build)', () => {
  let place;
  let dispose = async () => {};
  let tarballs;
  let dataDir;
  let project;
  let sourceRoot;
  let host;
  let spaceId;
  let server;
  // Through the host's dispatcher, which logs in to the server inside the way the app does.
  const inside = async (method, requestPath, body = null) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/spaces/${spaceId}${requestPath.replace(/^\/api/, '')}`, {
      method,
      headers: body === null ? {} : { 'content-type': 'application/json' },
      body: body === null ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = { text };
    }
    return { status: response.status, body: parsed };
  };
  const listed = async () => (await host.journey.listSpaces({ access: true })).find((space) => space.id === spaceId);

  beforeAll(async () => {
    tarballs = fs.mkdtempSync(path.join(os.tmpdir(), 'openchamber-environment-packed-'));
    const packed = await packLocalTools({ runCommand, outputDirectory: tarballs });
    ({ place, dispose } = createLiveDockerPlace({ toolsSource: createPackedToolsSource({ ...packed, openCodeVersion: readHostToolVersions().openCodeVersion }) }));
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'openchamber-environment-packed-data-'));
    project = fs.mkdtempSync(path.join(os.tmpdir(), 'openchamber-environment-packed-project-'));
    const git = (...args) => runCommand('git', ['-C', project, ...args]);
    await git('init', '-q', '.');
    fs.writeFileSync(path.join(project, 'README.md'), 'Shared memory live pass.\n');
    await git('add', '.');
    await git('-c', 'user.email=me@example.invalid', '-c', 'user.name=Me', 'commit', '-q', '-m', 'init');
    sourceRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'openchamber-environment-packed-source-')));
    write(sourceRoot, '.openchamber/environment.json', JSON.stringify({ version: 1, configRoot: 'config', memory: { path: 'memory' } }));
    write(sourceRoot, 'config/AGENTS.md', 'Shared.\n');
    for (const id of ['mem_keep', 'mem_edit', 'mem_drop']) {
      write(sourceRoot, `memory/entries/${id}.json`, JSON.stringify({ version: 2, id, title: `Title ${id}`, body: `Body of ${id}.`, type: 'fact', createdAt: 1, updatedAt: 1, revision: 1, operations: [] }));
    }
    host = createSpacesHost({
      dataDir,
      place,
      listProjectDirectories: async () => [project],
      hostEnvironment: { ...process.env },
      hostProviders: createHostProviders({ readStoredKey: async () => null, hostEnvironment: {} }),
      readHostLogin: async () => null,
      logger: { warn: () => {}, info: () => {} },
    });
    const app = express();
    app.use(host.middleware);
    server = await new Promise((resolve) => { const listening = http.createServer(app); listening.listen(0, '127.0.0.1', () => resolve(listening)); });
    const answer = await host.journey.createSpace({ projectDirectory: project, name: 'Shared memory', start: 'clean', network: { mode: 'allowlist', domains: [] }, environment: { kind: 'folder', location: sourceRoot, memory: 'write' } });
    spaceId = answer.id;
    expect(await until(async () => (await listed())?.state === 'running' && (await listed())?.step === null, CREATE_TIMEOUT_MS)).toBe(true);
  }, CREATE_TIMEOUT_MS);

  afterAll(async () => {
    host?.close();
    await new Promise((resolve) => { if (server) { server.closeAllConnections?.(); server.close(() => resolve()); } else resolve(); });
    await dispose();
    for (const folder of [tarballs, dataDir, project, sourceRoot]) if (folder) fs.rmSync(folder, { recursive: true, force: true });
  });

  it('lists the seeded shared entries inside, beside private memory, and counts them in the session index', async () => {
    const shared = await inside('GET', '/api/agent-memory?scope=shared');
    expect(shared.status).toBe(200);
    expect(shared.body.entries.map((entry) => entry.id).sort()).toEqual(['mem_drop', 'mem_edit', 'mem_keep']);
    const all = await inside('GET', '/api/agent-memory/all');
    expect(all.body).toMatchObject({ sharedAvailable: true, sharedFailed: false, sharedStatus: { mode: 'write' } });
    // The host's private memory never travels: the space's own global store is empty.
    expect(all.body.global).toEqual([]);
    const summary = await inside('GET', `/api/session-knowledge/summary?directory=${encodeURIComponent((await listed()).directory)}`);
    expect(summary.body.memory).toMatchObject({ shared: 3 });
  });

  it('records an edit and a delete inside, and a sync publishes both to the folder', async () => {
    expect((await inside('PATCH', '/api/agent-memory/mem_edit?scope=shared', { body: 'Edited inside the space.', revision: 1 })).status).toBe(200);
    expect((await inside('DELETE', '/api/agent-memory/mem_drop?scope=shared&revision=1')).status).toBeLessThan(300);
    // A stale edit is a conflict inside already.
    expect((await inside('PATCH', '/api/agent-memory/mem_edit?scope=shared', { body: 'Stale.', revision: 1 })).status).toBe(409);
    expect(await host.journey.readEnvironmentMemory(spaceId)).toMatchObject({ available: true, pending: 2 });
    expect(await host.journey.syncEnvironmentMemory(spaceId)).toMatchObject({ state: 'synced', published: true, pending: 0 });
    expect(JSON.parse(fs.readFileSync(path.join(sourceRoot, 'memory/entries/mem_edit.json'), 'utf8'))).toMatchObject({ body: 'Edited inside the space.', revision: 2 });
    expect(fs.existsSync(path.join(sourceRoot, 'memory/entries/mem_drop.json'))).toBe(false);
    expect(JSON.parse(fs.readFileSync(path.join(sourceRoot, 'memory/tombstones/mem_drop.json'), 'utf8'))).toMatchObject({ revision: 2 });
    const status = await inside('GET', '/api/agent-memory/all');
    expect(status.body.sharedStatus).toMatchObject({ state: 'synced', pending: 0 });
  }, 120_000);

  it('turns shared memory off without a new container, and off reads as unavailable, not empty', async () => {
    await host.journey.configureEnvironment(spaceId, { memory: 'off' });
    // The space's own memory setting is off, so with shared memory off the whole surface says so,
    // as it does in a space without a source: disabled, never an empty list.
    const all = await inside('GET', '/api/agent-memory/all');
    expect(all).toMatchObject({ status: 404, body: { disabled: true } });
    expect((await inside('GET', '/api/agent-memory?scope=shared')).body).toMatchObject({ disabled: true });
    // Back on, the same container serves it again with what the source holds.
    await host.journey.configureEnvironment(spaceId, { memory: 'read' });
    const again = await inside('GET', '/api/agent-memory?scope=shared');
    expect(again.status).toBe(200);
    expect(again.body.entries.map((entry) => entry.id).sort()).toEqual(['mem_edit', 'mem_keep']);
  });
});
