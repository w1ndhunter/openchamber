import { afterEach, describe, expect, test } from 'bun:test';
import fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createAgentMemoryRuntime } from './runtime.js';

const roots = [];
const temporary = async () => {
  const root = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'oc-shared-memory-'));
  roots.push(root);
  return root;
};
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => fsPromises.rm(root, { recursive: true, force: true })));
});

const runtimeAt = (sharedRoot, sharedMode = 'write') => createAgentMemoryRuntime({
  fsPromises,
  path,
  userConfigRoot: path.join(sharedRoot, 'private'),
  projectsDirPath: path.join(sharedRoot, 'projects'),
  sharedRoot,
  sharedMode,
});

describe('shared memory store', () => {
  test('two independent writers keep every entry', async () => {
    const root = await temporary();
    const first = runtimeAt(root);
    const second = runtimeAt(root);
    await Promise.all([
      ...Array.from({ length: 8 }, (_, index) => first.create({ scope: 'shared' }, {
        title: `First ${index}`,
        body: `Body ${index}.`,
      })),
      ...Array.from({ length: 8 }, (_, index) => second.create({ scope: 'shared' }, {
        title: `Second ${index}`,
        body: `Other ${index}.`,
      })),
    ]);
    const stored = await first.read({ scope: 'shared' });
    expect(stored.entries).toHaveLength(16);
    expect(new Set(stored.entries.map((entry) => entry.title)).size).toBe(16);
  });

  test('a stale rewrite is a conflict, not an overwrite', async () => {
    const root = await temporary();
    const first = runtimeAt(root);
    const second = runtimeAt(root);
    const made = await first.create({ scope: 'shared' }, { title: 'Fact', body: 'One.' });
    const afterFirst = await first.update({ scope: 'shared' }, made.entry.id, {
      title: 'Fact',
      body: 'Two.',
      expectedRevision: made.entry.revision,
    });
    expect(afterFirst.entry.revision).toBe(2);
    await expect(second.update({ scope: 'shared' }, made.entry.id, {
      title: 'Fact',
      body: 'Stale.',
      expectedRevision: 1,
    })).rejects.toMatchObject({ code: 'memory_conflict', status: 409 });
    expect((await first.read({ scope: 'shared' })).entries[0].body).toBe('Two.');
  });

  test('deletion leaves a revisioned tombstone and stays deleted', async () => {
    const root = await temporary();
    const first = runtimeAt(root);
    const second = runtimeAt(root);
    const made = await first.create({ scope: 'shared' }, { title: 'Gone', body: 'Body.' });
    await first.remove({ scope: 'shared' }, made.entry.id, made.entry.revision);
    expect((await second.read({ scope: 'shared' })).entries).toEqual([]);
    const tombstones = await fsPromises.readdir(path.join(root, 'tombstones'));
    expect(tombstones).toEqual([`${made.entry.id}.json`]);
    const stored = JSON.parse(await fsPromises.readFile(path.join(root, 'tombstones', tombstones[0]), 'utf8'));
    expect(stored.revision).toBe(2);
  });

  test('every change is recorded once as an operation with the revision it was based on', async () => {
    const root = await temporary();
    const memory = runtimeAt(root);
    const made = await memory.create({ scope: 'shared' }, { title: 'Fact', body: 'One.' });
    await memory.update({ scope: 'shared' }, made.entry.id, { body: 'Two.', expectedRevision: 1 });
    await memory.remove({ scope: 'shared' }, made.entry.id, 2);
    const names = (await fsPromises.readdir(path.join(root, 'operations'))).sort();
    const operations = await Promise.all(names.map(async (name) => JSON.parse(await fsPromises.readFile(path.join(root, 'operations', name), 'utf8'))));
    expect(operations.map(({ kind, base, memoryId }) => ({ kind, base, memoryId }))).toEqual([
      { kind: 'put', base: 0, memoryId: made.entry.id },
      { kind: 'put', base: 1, memoryId: made.entry.id },
      { kind: 'delete', base: 2, memoryId: made.entry.id },
    ]);
    expect(new Set(operations.map((operation) => operation.id)).size).toBe(3);
    expect(await memory.readSharedStatus()).toMatchObject({ mode: 'write', state: 'pending', pending: 3 });
  });

  test('the host\'s mode file wins over the mode the space was made with, and off is unavailable, not empty', async () => {
    const root = await temporary();
    const memory = runtimeAt(root);
    await memory.create({ scope: 'shared' }, { title: 'Fact', body: 'One.' });
    await fsPromises.writeFile(path.join(root, '.mode'), 'read\n');
    await expect(memory.create({ scope: 'shared' }, { title: 'No', body: 'No.' })).rejects.toMatchObject({ status: 403 });
    await fsPromises.writeFile(path.join(root, '.mode'), 'off\n');
    await expect(memory.read({ scope: 'shared' })).rejects.toThrow('detached');
    // Off is no shared memory: other scopes read normally and nothing reports a failure.
    const all = await memory.readAll(null);
    expect(all).toMatchObject({ sharedFailed: false, sharedAvailable: false, shared: [] });
    expect(all.sharedStatus).toMatchObject({ mode: 'off', state: 'off' });
  });

  test('more than 200 shared entries all survive an edit of one, and only a removal deletes', async () => {
    const root = await temporary();
    const memory = runtimeAt(root);
    const made = [];
    for (let index = 0; index < 250; index += 1) made.push(await memory.create({ scope: 'shared' }, { title: `Entry ${index}`, body: `Body ${index}.` }));
    await memory.update({ scope: 'shared' }, made[0].entry.id, { body: 'Changed.', expectedRevision: 1 });
    expect((await memory.read({ scope: 'shared' })).entries).toHaveLength(250);
    expect(await fsPromises.readdir(path.join(root, 'tombstones')).catch(() => [])).toEqual([]);
    await memory.remove({ scope: 'shared' }, made[1].entry.id, 1);
    expect(await fsPromises.readdir(path.join(root, 'tombstones'))).toEqual([`${made[1].entry.id}.json`]);
    expect((await memory.read({ scope: 'shared' })).entries).toHaveLength(249);
  });

  test('a malformed entry makes shared memory unavailable rather than empty', async () => {
    const root = await temporary();
    await fsPromises.mkdir(path.join(root, 'entries'), { recursive: true });
    await fsPromises.writeFile(path.join(root, 'entries', 'bad.json'), '{');
    const all = await runtimeAt(root).readAll(null);
    expect(all.sharedFailed).toBe(true);
  });

  test('read mode refuses mutations but still reads', async () => {
    const root = await temporary();
    const writer = runtimeAt(root);
    const made = await writer.create({ scope: 'shared' }, { title: 'Visible', body: 'Body.' });
    const reader = runtimeAt(root, 'read');
    expect((await reader.read({ scope: 'shared' })).entries[0].id).toBe(made.entry.id);
    await expect(reader.create({ scope: 'shared' }, { title: 'No', body: 'No.' }))
      .rejects.toMatchObject({ status: 403 });
  });
});
