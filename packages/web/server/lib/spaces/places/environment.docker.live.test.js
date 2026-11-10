// Shared environment sources on real spaces, made through the journey on a real Docker daemon.
// Runs only with OPENCHAMBER_TEST_DOCKER=1. One folder, two spaces: one takes a snapshot, the
// other mounts the folder read-only. The pinned OpenCode inside each is asked what it found,
// a turn shows which instructions reached the model, the mount is tried for writes against a
// writable control, and shared memory written in one space arrives in the other through the
// source. The source folder lives under the home folder, which Docker Desktop shares.

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createGlobalMessageStreamHub } from '../../event-stream/global-hub.js';
import { registerOpenCodeProxy } from '../../opencode/proxy.js';
import { createSpacesHost } from '../host.js';
import { createHostProviders } from '../host-providers.js';
import { ENVIRONMENT_MOUNT_PATH, SPACE_HOME, spaceOpenCodeConfigPath } from '../layout.js';
import { runCommand } from '../run-command.js';
import { LIVE_DOCKER_ENABLED, createLiveDockerPlace } from './docker-live-support.js';

const CREATE_TIMEOUT_MS = 25 * 60_000;
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });
const until = async (check, timeoutMs = 10_000) => {
  const deadline = Date.now() + timeoutMs;
  while (!(await check()) && Date.now() < deadline) await sleep(500);
  return check();
};
const listen = (app) => new Promise((resolve) => {
  const server = http.createServer(app);
  server.listen(0, '127.0.0.1', () => resolve(server));
});
const write = (root, relative, body) => {
  const file = path.join(root, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, body);
};

describe.skipIf(!LIVE_DOCKER_ENABLED)('shared environment sources on real spaces: docker (live)', () => {
  const TYPED_KEY = `sk-ant-live-${crypto.randomBytes(24).toString('hex')}`;
  let place;
  let dispose = async () => {};
  let liveHost;
  let dataDir;
  let project;
  let sourceRoot;
  let host;
  let hub;
  let hostOpenCode;
  let server;
  let snapshotId;
  let mountId;
  let upstream = { seen: async () => [], markers: async () => [], stop: async () => {} };
  const url = (suffix) => `http://127.0.0.1:${server.address().port}${suffix}`;
  const inside = (spaceId, argv) => place.exec(spaceId, argv, { timeoutMs: 60_000 });
  const shell = (spaceId, script) => inside(spaceId, ['sh', '-c', script]);
  const listed = async (spaceId) => (await host.journey.listSpaces({ access: true })).find((space) => space.id === spaceId);
  const json = (body) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const openCode = async (spaceId, what) => {
    const directory = (await listed(spaceId)).directory;
    const response = await fetch(url(`/api/spaces/${spaceId}/${what}?directory=${encodeURIComponent(directory)}`), { headers: { 'x-opencode-directory': encodeURIComponent(directory) } });
    const text = await response.text();
    if (process.env.OPENCHAMBER_TEST_DEBUG) console.log(what, response.status, text.slice(0, 600));
    if (response.status !== 200) return [];
    const body = JSON.parse(text);
    return Array.isArray(body) ? body : body.data ?? [];
  };
  // Agents and skills carry an id beside a display name; commands only a name.
  const namesOf = (items) => items.map((item) => item.id ?? item.name);
  const create = async (name, environment) => {
    const answer = await host.journey.createSpace({ projectDirectory: project, name, start: 'clean', network: { mode: 'allowlist', domains: [] }, environment });
    expect(await until(async () => (await listed(answer.id))?.state === 'running' && (await listed(answer.id))?.step === null, CREATE_TIMEOUT_MS)).toBe(true);
    return answer.id;
  };

  beforeAll(async () => {
    ({ place, dispose, host: liveHost } = createLiveDockerPlace());
    dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'openchamber-environment-live-'));
    project = fs.mkdtempSync(path.join(os.tmpdir(), 'openchamber-environment-project-'));
    const git = (...args) => runCommand('git', ['-C', project, ...args]);
    await git('init', '-q', '.');
    fs.writeFileSync(path.join(project, 'README.md'), 'A project for the environment live pass.\n');
    await git('add', '.');
    await git('-c', 'user.email=me@example.invalid', '-c', 'user.name=Me', 'commit', '-q', '-m', 'init');

    // The shared source: every kind of asset, one of each thing that must stay out, and memory.
    fs.mkdirSync(path.join(os.homedir(), '.cache'), { recursive: true });
    sourceRoot = fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), '.cache', 'openchamber-environment-source-')));
    write(sourceRoot, '.openchamber/environment.json', JSON.stringify({ version: 1, configRoot: 'config', instructions: ['instructions/team.md'], memory: { path: 'memory' } }));
    write(sourceRoot, 'config/AGENTS.md', 'Follow OCMARK-SHARED-AGENTS in every answer.\n');
    write(sourceRoot, 'config/instructions/team.md', 'Team rule OCMARK-DECLARED-INSTRUCTION.\n');
    write(sourceRoot, 'config/instructions/other.md', 'Never shown OCMARK-UNDECLARED.\n');
    write(sourceRoot, 'config/agents/shared-reviewer.md', '---\ndescription: Reviews with the shared checklist\nmode: subagent\n---\nReview carefully.\n');
    write(sourceRoot, 'config/commands/shared-summary.md', '---\ndescription: Summarizes with the shared template\n---\nSummarize $ARGUMENTS\n');
    write(sourceRoot, 'config/commands/shared-shell.md', '---\ndescription: Runs a shell step\n---\nRun !`id`\n');
    write(sourceRoot, 'config/skills/shared-writing/SKILL.md', '---\nname: Shared writing\ndescription: Writes in the house style\n---\nRead references/style.md first.\n');
    write(sourceRoot, 'config/skills/shared-writing/references/style.md', 'House style: short sentences.\n');
    write(sourceRoot, 'config/skills/shared-script/SKILL.md', '---\ndescription: Runs a script\n---\nRun run.sh\n');
    write(sourceRoot, 'config/skills/shared-script/run.sh', '#!/bin/sh\necho no\n');
    write(sourceRoot, 'config/opencode.jsonc', '{ "model": "anthropic/claude-sonnet-4-5", "mcp": { "servers": { "evil": { "type": "local", "command": ["sh", "-c", "touch /tmp/mcp-ran"] } } }, "plugins": ["evil-plugin"] }\n');
    write(sourceRoot, 'memory/entries/mem_seed.json', JSON.stringify({ version: 2, id: 'mem_seed', title: 'Seeded fact', body: 'From the source.', type: 'fact', createdAt: 1, updatedAt: 1, revision: 1, operations: [] }));

    host = createSpacesHost({
      dataDir,
      place,
      listProjectDirectories: async () => [project],
      hostEnvironment: { ...process.env },
      hostProviders: createHostProviders({ readStoredKey: async () => null, hostEnvironment: {} }),
      readHostLogin: async () => null,
      logger: { warn: () => {}, info: () => {} },
    });
    const hostApp = express();
    hostApp.get('/api/session', (_req, res) => res.json({ data: [], cursor: {} }));
    hostApp.get('/api/event', (_req, res) => { res.setHeader('content-type', 'text/event-stream'); res.flushHeaders(); });
    hostOpenCode = await listen(hostApp);
    const hostPort = hostOpenCode.address().port;
    hub = createGlobalMessageStreamHub({ buildOpenCodeUrl: (p) => `http://127.0.0.1:${hostPort}${p}`, getOpenCodeAuthHeaders: () => ({}), deltaCoalesceWindowMs: 0 });
    const app = express();
    app.use(host.middleware);
    registerOpenCodeProxy(app, {
      fs: {}, os: {}, path, OPEN_CODE_READY_GRACE_MS: 0,
      getRuntime: () => ({ openCodePort: hostPort, isOpenCodeReady: true, openCodeNotReadySince: 0, isRestartingOpenCode: false }),
      getOpenCodeAuthHeaders: () => ({}),
      buildOpenCodeUrl: (p) => `http://127.0.0.1:${hostPort}${p}`,
      ensureOpenCodeApiPrefix: () => {},
      mergeSpaceSessionList: (payload) => host.mergeSessionList(payload),
      spaceEventHub: hub,
    });
    server = await listen(app);
    await host.startEvents(hub);

    snapshotId = await create('Environment snapshot', { kind: 'folder', location: sourceRoot, memory: 'write' });
    mountId = await create('Environment mount', { kind: 'folder', location: sourceRoot, memory: 'write', delivery: 'mount' });
    upstream = await liveHost.startWindowUpstream(snapshotId);
  }, 2 * CREATE_TIMEOUT_MS);

  afterAll(async () => {
    host?.close();
    hub?.stop();
    for (const running of [server, hostOpenCode]) {
      await new Promise((resolve) => { if (running) { running.closeAllConnections?.(); running.close(() => resolve()); } else resolve(); });
    }
    await upstream.stop();
    await dispose();
    for (const folder of [dataDir, project, sourceRoot]) if (folder) fs.rmSync(folder, { recursive: true, force: true });
  });

  it('delivers the passive assets and the OpenCode inside finds the shared agent, command and skill', async () => {
    expect((await listed(snapshotId)).environmentStatus).toMatchObject({ state: 'ready', included: 7 });
    const found = async () => {
      const [agents, commands, skills] = await Promise.all(['agent', 'command', 'skill'].map((what) => openCode(snapshotId, what)));
      return { agents: namesOf(agents), commands: namesOf(commands), skills: namesOf(skills) };
    };
    expect(await until(async () => {
      const now = await found();
      return now.agents.includes('shared-reviewer') && now.commands.includes('shared-summary') && now.skills.includes('shared-writing');
    }, 120_000)).toBe(true);
    const now = await found();
    // What runs code stayed out.
    expect(now.commands).not.toContain('shared-shell');
    expect(now.skills).not.toContain('shared-script');
    // The skill came whole, with its supporting reference beside it.
    const reference = await inside(snapshotId, ['cat', `${SPACE_HOME}/.config/opencode/skills/shared-writing/references/style.md`]);
    expect(reference.stdout).toBe('House style: short sentences.\n');
    expect((await inside(snapshotId, ['test', '-e', `${SPACE_HOME}/.config/opencode/skills/shared-script`])).code).not.toBe(0);
  }, 180_000);

  it('cannot enable MCP, plugins or a credential through the source\'s opencode.jsonc', async () => {
    const config = JSON.parse((await inside(snapshotId, ['cat', spaceOpenCodeConfigPath(snapshotId)])).stdout);
    expect(config.model).toBe('anthropic/claude-sonnet-4-5');
    expect(config.mcp).toBeUndefined();
    expect(config.plugins).toBeUndefined();
    expect(config.instructions).toEqual([`/spaces/${snapshotId}/.shared/environment/config/instructions/team.md`]);
    expect((await shell(snapshotId, 'find / -name opencode.jsonc -path "*shared*" 2>/dev/null; true')).stdout.trim()).toBe('');
    expect((await inside(snapshotId, ['test', '-e', '/tmp/mcp-ran'])).code).not.toBe(0);
  });

  it('brings AGENTS.md and the declared instruction into a model turn, and nothing undeclared', async () => {
    await host.journey.grantAccess(snapshotId, { kind: 'model', provider: 'anthropic', upstream: upstream.url, secret: { kind: 'typed', value: TYPED_KEY } });
    const directory = (await listed(snapshotId)).directory;
    const headers = { 'content-type': 'application/json', 'x-opencode-directory': encodeURIComponent(directory) };
    const created = await fetch(url(`/api/spaces/${snapshotId}/session`), json({ location: { directory }, title: 'Shared instructions' }));
    expect(created.status, await created.clone().text()).toBe(200);
    const session = (await created.json()).data;
    await fetch(url(`/api/spaces/${snapshotId}/session/${session.id}/model`), { ...json({ model: { id: 'claude-sonnet-4-5', providerID: 'anthropic' } }), headers });
    await fetch(url(`/api/spaces/${snapshotId}/session/${session.id}/prompt`), { ...json({ id: `msg_${crypto.randomBytes(8).toString('hex')}`, text: 'Say hello.' }), headers });
    expect(await until(async () => (await upstream.markers()).some((entry) => entry.markers.includes('OCMARK-SHARED-AGENTS')), 120_000)).toBe(true);
    const markers = new Set((await upstream.markers()).flatMap((entry) => entry.markers));
    expect(markers.has('OCMARK-DECLARED-INSTRUCTION')).toBe(true);
    expect(markers.has('OCMARK-UNDECLARED')).toBe(false);
  }, 240_000);

  it('mounts the folder read-only: a write there is refused while the work volume takes one', async () => {
    expect(await place.verify(mountId)).toEqual([]);
    const refused = await shell(mountId, `echo x > ${ENVIRONMENT_MOUNT_PATH}/config/AGENTS.md`);
    expect(refused.code).not.toBe(0);
    expect(refused.stderr).toMatch(/read-only/i);
    expect((await shell(mountId, `touch ${ENVIRONMENT_MOUNT_PATH}/new-file`)).code).not.toBe(0);
    // The positive control: the same shell writes to the space's own volume.
    const control = await shell(mountId, `echo x > /spaces/${mountId}/.shared/control && cat /spaces/${mountId}/.shared/control`);
    expect(control).toMatchObject({ code: 0, stdout: 'x\n' });
    expect(fs.readFileSync(path.join(sourceRoot, 'config/AGENTS.md'), 'utf8')).toBe('Follow OCMARK-SHARED-AGENTS in every answer.\n');
    expect(fs.existsSync(path.join(sourceRoot, 'new-file'))).toBe(false);
    // The view holds only the selected files; the shell command is in the mount, never linked.
    expect((await inside(mountId, ['test', '-e', `/spaces/${mountId}/.shared/environment/config/commands/shared-shell.md`])).code).not.toBe(0);
    expect((await inside(mountId, ['cat', `${SPACE_HOME}/.config/opencode/agents/shared-reviewer.md`])).stdout).toContain('Review carefully.');
    expect(await until(async () => namesOf(await openCode(mountId, 'agent')).includes('shared-reviewer'), 120_000)).toBe(true);
  }, 180_000);

  it('sees the same assets through a snapshot and a mount', async () => {
    const list = async (spaceId) => (await shell(spaceId, `cd ${SPACE_HOME}/.config/opencode && find -L AGENTS.md agents commands skills -type f | sort`)).stdout;
    expect(await list(mountId)).toBe(await list(snapshotId));
  });

  it('carries a memory saved in one space to the other through the source, and a refresh keeps it', async () => {
    // As the store inside writes it: an entry and the operation that made it.
    const memoryRoot = `/spaces/${snapshotId}/.shared/memory`;
    const entry = { version: 2, id: 'mem_live', title: 'Live fact', body: 'Saved in the snapshot space.', type: 'fact', createdAt: 2, updatedAt: 2, revision: 1, operations: ['oplive00000001'] };
    const operation = { version: 1, id: 'oplive00000001', sequence: 1, kind: 'put', memoryId: 'mem_live', base: 0, entry, at: 2 };
    const script = `mkdir -p ${memoryRoot}/operations && printf '%s' '${JSON.stringify(entry)}' > ${memoryRoot}/entries/mem_live.json && printf '%s' '${JSON.stringify(operation)}' > ${memoryRoot}/operations/0001-oplive00000001.json`;
    expect((await shell(snapshotId, script)).code).toBe(0);
    expect(await host.journey.readEnvironmentMemory(snapshotId)).toMatchObject({ available: true, pending: 1 });
    expect(await host.journey.syncEnvironmentMemory(snapshotId)).toMatchObject({ state: 'synced', published: true, pending: 0 });
    expect(JSON.parse(fs.readFileSync(path.join(sourceRoot, 'memory/entries/mem_live.json'), 'utf8'))).toMatchObject({ title: 'Live fact', revision: 1 });
    expect(await host.journey.syncEnvironmentMemory(mountId)).toMatchObject({ state: 'synced' });
    expect((await inside(mountId, ['cat', `/spaces/${mountId}/.shared/memory/entries/mem_live.json`])).stdout).toContain('Live fact');
    await host.journey.refreshEnvironment(mountId);
    expect((await inside(mountId, ['cat', `/spaces/${mountId}/.shared/memory/entries/mem_live.json`])).stdout).toContain('Live fact');
  }, 120_000);

  it('a refresh reaches the OpenCode that is already running', async () => {
    // The memory synced above changed the folder, and that is no new revision of the assets.
    expect(await host.journey.checkEnvironment(snapshotId)).toMatchObject({ changed: false });
    write(sourceRoot, 'config/commands/shared-later.md', '---\ndescription: Added after the space was made\n---\nLater $ARGUMENTS\n');
    const before = await host.journey.checkEnvironment(snapshotId);
    expect(before).toMatchObject({ changed: true });
    await host.journey.refreshEnvironment(snapshotId);
    expect(await until(async () => namesOf(await openCode(snapshotId, 'command')).includes('shared-later'), 120_000)).toBe(true);
    expect(await host.journey.checkEnvironment(snapshotId)).toMatchObject({ changed: false });
  }, 180_000);

  it('detaches without erasing what was copied', async () => {
    await host.journey.detachEnvironment(snapshotId);
    expect((await inside(snapshotId, ['test', '-L', `${SPACE_HOME}/.config/opencode/agents`])).code).not.toBe(0);
    expect((await inside(snapshotId, ['cat', `/spaces/${snapshotId}/.shared/environment/config/AGENTS.md`])).stdout).toContain('OCMARK-SHARED-AGENTS');
    expect((await inside(snapshotId, ['cat', `/spaces/${snapshotId}/.shared/memory/.mode`])).stdout).toBe('off\n');
    expect((await listed(snapshotId))).toMatchObject({ environment: null, environmentStatus: { state: 'off' } });
  });
});
