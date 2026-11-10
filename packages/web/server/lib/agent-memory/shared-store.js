/**
 * The shared memory store: one file per entry, tombstones, and an operation log.
 *
 * A shared source is written by more than one OpenChamber process, so the
 * single `memory.json` store beside it cannot be used: two read-modify-write
 * cycles would lose one of the results. Each entry has its own file and a
 * revision, and a directory lock serialises writers across processes.
 *
 * Inside a space every mutation is also recorded as an operation with a
 * stable id and the revision it was based on. The host replays those
 * operations against the authoritative source (`integrateOperations`): an
 * operation already applied there is recognised by its id, so a replay after
 * a crash or restart changes nothing, and an operation based on a revision
 * the source no longer has is a conflict. No timestamp ever decides a winner.
 */

import crypto from 'node:crypto';
import fsPromises from 'node:fs/promises';
import path from 'node:path';

import { isRecord } from '../shared/guards.js';
import { findThreatPattern } from './threat-patterns.js';

const ENTRY_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
const OPERATION_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;
const LOCK_WAIT_MS = 5_000;
const LOCK_STALE_MS = 30_000;
const MEMORY_TYPES = new Set(['fact', 'preference', 'reference']);

export const SHARED_MEMORY_LIMITS = Object.freeze({
  entries: 2_000,
  tombstones: 10_000,
  operations: 500,
  // The operation ids an entry remembers, so a replay of a recent one is recognised.
  remembered: 50,
  title: 60,
  body: 2_000,
});

const SHARED_MEMORY_MODES = Object.freeze(['off', 'read', 'write']);

const sleep = (milliseconds) => new Promise((resolve) => { setTimeout(resolve, milliseconds); });

const requireEntryId = (value) => {
  const id = String(value ?? '');
  if (!ENTRY_PATTERN.test(id)) throw new Error('memoryId contains unsupported characters');
  return id;
};

const naturalNumber = (value, fallback) => (Number.isSafeInteger(value) && value >= 0 ? value : fallback);

const operationsOf = (value) => (Array.isArray(value)
  ? value.map(String).filter((id) => OPERATION_PATTERN.test(id)).slice(-SHARED_MEMORY_LIMITS.remembered)
  : []);

/** An entry as the store and a source hold it, or null for anything that is not one. */
export const normalizeEntry = (value) => {
  if (!isRecord(value)) return null;
  const id = String(value.id ?? '');
  if (!ENTRY_PATTERN.test(id)) return null;
  const title = String(value.title ?? '').trim().slice(0, SHARED_MEMORY_LIMITS.title);
  const body = String(value.body ?? '').trim().slice(0, SHARED_MEMORY_LIMITS.body);
  if (!title || !body) return null;
  const createdAt = naturalNumber(value.createdAt, 0);
  const entry = {
    version: 2,
    id,
    title,
    body,
    type: MEMORY_TYPES.has(value.type) ? value.type : 'fact',
    createdAt,
    updatedAt: naturalNumber(value.updatedAt, createdAt),
    revision: Number.isSafeInteger(value.revision) && value.revision > 0 ? value.revision : 1,
    operations: operationsOf(value.operations),
  };
  if (value.sessionId) entry.sessionId = String(value.sessionId).slice(0, 256);
  return entry;
};

export const normalizeTombstone = (value) => {
  if (!isRecord(value)) return null;
  const id = String(value.id ?? '');
  if (!ENTRY_PATTERN.test(id)) return null;
  return {
    version: 2,
    id,
    deletedAt: naturalNumber(value.deletedAt, 0),
    revision: Number.isSafeInteger(value.revision) && value.revision > 0 ? value.revision : 1,
    operations: operationsOf(value.operations),
  };
};

/** One recorded mutation, or null. `put` with base 0 creates; any other base names the revision it changed. */
export const normalizeOperation = (value) => {
  if (!isRecord(value)) return null;
  const id = String(value.id ?? '');
  if (!OPERATION_PATTERN.test(id)) return null;
  const memoryId = String(value.memoryId ?? '');
  if (!ENTRY_PATTERN.test(memoryId)) return null;
  const base = Number.isSafeInteger(value.base) && value.base >= 0 ? value.base : null;
  if (base === null) return null;
  const sequence = naturalNumber(value.sequence, 0);
  if (value.kind === 'delete') {
    if (base === 0) return null;
    return { version: 1, id, sequence, kind: 'delete', memoryId, base, at: naturalNumber(value.at, 0) };
  }
  if (value.kind !== 'put' || !isRecord(value.entry)) return null;
  const entry = normalizeEntry({ ...value.entry, id: memoryId });
  if (!entry) return null;
  return { version: 1, id, sequence, kind: 'put', memoryId, base, entry, at: naturalNumber(value.at, 0) };
};

const remember = (operations, id) => [...operations.filter((known) => known !== id), id].slice(-SHARED_MEMORY_LIMITS.remembered);

/**
 * Replays operations against a source state. Returns the next state, the ids
 * of operations now reflected in it (applied now or before), and conflicts.
 *
 * - Distinct entry ids merge.
 * - A change based on the revision the source holds is applied as the next one.
 * - A change based on any other revision is a conflict; nothing is overwritten.
 * - A deleted entry stays deleted: a change to it, or a new entry under its id, is a conflict.
 * - An operation whose id the entry or tombstone already remembers is a replay and changes nothing.
 */
export const integrateOperations = (state, operations, { now = Date.now, allowFlagged = false } = {}) => {
  const entries = new Map(state.entries.map((entry) => [entry.id, entry]));
  const tombstones = new Map(state.tombstones.map((entry) => [entry.id, entry]));
  const settled = [];
  // The ids whose files change: a replay touches none.
  const touched = new Set();
  const conflicts = [];
  const ordered = [...operations].sort((left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id));
  for (const operation of ordered) {
    const current = entries.get(operation.memoryId);
    const deleted = tombstones.get(operation.memoryId);
    if (current?.operations.includes(operation.id) || deleted?.operations.includes(operation.id)) {
      settled.push(operation.id);
      continue;
    }
    const conflict = (reason) => conflicts.push({
      operationId: operation.id,
      memoryId: operation.memoryId,
      kind: operation.kind,
      reason,
      base: operation.base,
      sourceRevision: current?.revision ?? deleted?.revision ?? 0,
    });
    if (deleted) {
      if (operation.kind === 'delete') {
        // Deleting what is already deleted is the same outcome; remember the id so a replay stays quiet.
        tombstones.set(deleted.id, { ...deleted, operations: remember(deleted.operations, operation.id) });
        settled.push(operation.id);
        touched.add(operation.memoryId);
      } else {
        conflict('deleted');
      }
      continue;
    }
    if (operation.kind === 'put') {
      // Text that talks to the model would reach every space of the source: it is set aside for a
      // person, never published by a sync. A reviewed import chooses for itself.
      if (!allowFlagged && findThreatPattern(`${operation.entry.title}\n${operation.entry.body}`)) {
        conflict('flagged');
        continue;
      }
      if (operation.base === 0) {
        if (current) {
          conflict('exists');
          continue;
        }
        if (entries.size >= SHARED_MEMORY_LIMITS.entries) {
          conflict('limit');
          continue;
        }
        entries.set(operation.memoryId, { ...operation.entry, revision: 1, operations: [operation.id] });
        settled.push(operation.id);
        touched.add(operation.memoryId);
        continue;
      }
      if (!current || current.revision !== operation.base) {
        conflict(current ? 'stale' : 'missing');
        continue;
      }
      entries.set(operation.memoryId, {
        ...operation.entry,
        createdAt: current.createdAt,
        revision: current.revision + 1,
        operations: remember(current.operations, operation.id),
      });
      settled.push(operation.id);
      touched.add(operation.memoryId);
      continue;
    }
    if (!current || current.revision !== operation.base) {
      conflict(current ? 'stale' : 'missing');
      continue;
    }
    entries.delete(operation.memoryId);
    tombstones.set(operation.memoryId, {
      version: 2,
      id: operation.memoryId,
      deletedAt: operation.at || now(),
      revision: current.revision + 1,
      operations: remember(current.operations, operation.id),
    });
    settled.push(operation.id);
    touched.add(operation.memoryId);
  }
  return {
    entries: [...entries.values()],
    tombstones: [...tombstones.values()].slice(-SHARED_MEMORY_LIMITS.tombstones),
    settled,
    touched: [...touched],
    conflicts,
  };
};

const directories = (root) => ({
  entries: path.join(root, 'entries'),
  tombstones: path.join(root, 'tombstones'),
  operations: path.join(root, 'operations'),
  conflicts: path.join(root, 'conflicts'),
});

/** Reads every `*.json` file in a directory. A missing directory is empty; a malformed file is a failure. */
const readDirectory = async (directory) => {
  let names;
  try {
    names = await fsPromises.readdir(directory);
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  const values = [];
  for (const name of names.sort()) {
    if (!name.endsWith('.json')) continue;
    const text = await fsPromises.readFile(path.join(directory, name), 'utf8');
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error(`Shared memory holds a malformed entry: ${name}`);
    }
    if (!isRecord(value)) {
      throw new Error(`Shared memory holds a malformed entry: ${name}`);
    }
    values.push(value);
  }
  return values;
};

const writeJson = async (file, value) => {
  await fsPromises.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`;
  try {
    await fsPromises.writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    await fsPromises.rename(temporary, file);
  } catch (error) {
    await fsPromises.rm(temporary, { force: true }).catch(() => {});
    throw error;
  }
};

/**
 * A writer lock that works between processes and containers sharing one folder.
 * `mkdir` is atomic on the filesystems the source supports. A lock older than
 * the stale bound is removed: a crashed writer must not stop every later one.
 */
const acquireLock = async (root, now = Date.now) => {
  const lock = path.join(root, '.lock');
  await fsPromises.mkdir(root, { recursive: true, mode: 0o700 });
  const started = now();
  for (;;) {
    try {
      await fsPromises.mkdir(lock);
      return async () => { await fsPromises.rm(lock, { recursive: true, force: true }); };
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      const stats = await fsPromises.stat(lock).catch(() => null);
      if (stats && now() - stats.mtimeMs > LOCK_STALE_MS) {
        await fsPromises.rm(lock, { recursive: true, force: true }).catch(() => {});
        continue;
      }
      if (now() - started >= LOCK_WAIT_MS) throw new Error('Shared memory is busy in another process');
      await sleep(25);
    }
  }
};

const readTextFile = async (file) => {
  try {
    return await fsPromises.readFile(file, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
};

/**
 * Entries and tombstones as a source or a space holds them. `mode` is the mode
 * the space was made with; a `.mode` file the host writes later takes its
 * place, so a mode change or a detach needs no new container. Inside a space
 * the mode only makes the tools cooperate: the agent can write that file, and
 * the host decides on its own record whether anything is published.
 */
export const createSharedMemoryStore = ({ root, mode: initialMode = 'write', recordOperations = false }) => {
  const storeRoot = String(root ?? '').trim();
  if (storeRoot === '') throw new Error('Shared memory needs a folder');
  const location = directories(storeRoot);

  const mode = async () => {
    const text = (await readTextFile(path.join(storeRoot, '.mode')))?.trim();
    if (text !== undefined && SHARED_MEMORY_MODES.includes(text)) return text;
    return SHARED_MEMORY_MODES.includes(initialMode) ? initialMode : 'off';
  };

  const read = async () => {
    const [entries, tombstones] = await Promise.all([
      readDirectory(location.entries),
      readDirectory(location.tombstones),
    ]);
    const normalizedTombstones = tombstones.map(normalizeTombstone).filter(Boolean);
    const deleted = new Set(normalizedTombstones.map((entry) => entry.id));
    return {
      entries: entries.map(normalizeEntry).filter((entry) => entry && !deleted.has(entry.id)),
      tombstones: normalizedTombstones,
    };
  };

  /** The operations recorded here and not yet settled with the source, oldest first. */
  const pendingOperations = async () => (await readDirectory(location.operations))
    .map(normalizeOperation)
    .filter(Boolean)
    .sort((left, right) => left.sequence - right.sequence);

  /** What the host last said about the sync: written by the host, read by the tools. */
  const status = async () => {
    const text = await readTextFile(path.join(storeRoot, '.status.json'));
    if (text === null) return null;
    try {
      const value = JSON.parse(text);
      return isRecord(value) ? value : null;
    } catch {
      return null;
    }
  };

  const record = async (operation) => {
    if (!recordOperations) return;
    const pending = await pendingOperations();
    if (pending.length >= SHARED_MEMORY_LIMITS.operations) {
      throw new Error('Too many shared memory changes wait for a sync; sync the space first');
    }
    const sequence = Math.max(Date.now(), ...pending.map((entry) => entry.sequence + 1));
    const value = { version: 1, sequence, at: Date.now(), ...operation };
    await writeJson(path.join(location.operations, `${String(sequence).padStart(16, '0')}-${operation.id}.json`), value);
  };

  /**
   * Writes the entries whose revision changed, and a tombstone for each id in `removed`. Only an
   * explicit removal deletes: an entry the caller did not pass is left as it is.
   */
  const writeEntries = async (entries, options = {}) => {
    const now = options.now ?? Date.now;
    const deletedAt = options.deletedAt ?? now();
    const removed = new Set((options.removed ?? []).map(requireEntryId));
    const { entries: before } = await read();
    const beforeById = new Map(before.map((entry) => [entry.id, entry]));
    const nextIds = new Set(entries.map((entry) => requireEntryId(entry.id)));
    if (new Set([...beforeById.keys(), ...nextIds].filter((id) => !removed.has(id))).size > SHARED_MEMORY_LIMITS.entries) throw new Error('Shared memory is full');
    for (const raw of entries) {
      const previous = beforeById.get(raw.id);
      const changed = !previous || previous.revision !== raw.revision;
      if (!changed) continue;
      const operationId = crypto.randomUUID().replaceAll('-', '');
      const entry = normalizeEntry({ ...raw, operations: remember(previous?.operations ?? [], operationId) });
      if (!entry) throw new Error('A shared memory entry needs a title and a body');
      await record({ id: operationId, kind: 'put', memoryId: entry.id, base: previous?.revision ?? 0, entry });
      await writeJson(path.join(location.entries, `${entry.id}.json`), entry);
    }
    for (const previous of before) {
      if (!removed.has(previous.id) || nextIds.has(previous.id)) continue;
      const operationId = crypto.randomUUID().replaceAll('-', '');
      await record({ id: operationId, kind: 'delete', memoryId: previous.id, base: previous.revision });
      await fsPromises.rm(path.join(location.entries, `${previous.id}.json`), { force: true });
      await writeJson(path.join(location.tombstones, `${previous.id}.json`), {
        version: 2,
        id: previous.id,
        deletedAt,
        revision: previous.revision + 1,
        operations: remember(previous.operations, operationId),
      });
    }
  };

  const withLock = async (work) => {
    const release = await acquireLock(storeRoot);
    try {
      return await work();
    } finally {
      await release();
    }
  };

  return { root: storeRoot, mode, read, pendingOperations, status, writeEntries, withLock };
};

/**
 * Writes the files of the entries an integration touched, and only those: an entry nobody changed
 * keeps its file byte for byte, so a publish to a repository changes what changed.
 */
export const writeSharedMemoryState = async (root, state) => {
  const location = directories(root);
  await fsPromises.mkdir(location.entries, { recursive: true, mode: 0o700 });
  await fsPromises.mkdir(location.tombstones, { recursive: true, mode: 0o700 });
  const entries = new Map(state.entries.map((entry) => [entry.id, entry]));
  const tombstones = new Map(state.tombstones.map((entry) => [entry.id, entry]));
  for (const id of state.touched) {
    const name = `${requireEntryId(id)}.json`;
    const entry = entries.get(id);
    const tombstone = tombstones.get(id);
    if (entry) await writeJson(path.join(location.entries, name), entry);
    else await fsPromises.rm(path.join(location.entries, name), { force: true });
    if (tombstone) await writeJson(path.join(location.tombstones, name), tombstone);
    else await fsPromises.rm(path.join(location.tombstones, name), { force: true });
  }
};
