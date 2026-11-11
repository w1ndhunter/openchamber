// What the host remembers about a space beside the runtime's labels: the network choice the user
// made, so the host can say it again to a gatekeeper that starts with an empty memory, and where
// the code went in, so the history and the result find the same repository later.
//
// The labels stay the source of truth about which spaces exist: a record without a space is
// forgotten, and a space without a record is listed with nothing known about it. No secret is
// ever in a record; the design keeps secret values out of the host's disk.

import fs from 'node:fs';
import path from 'node:path';

import { z } from 'zod';

import { environmentSourceSchema } from './environment-source.js';
import { requireSpaceId } from './labels.js';
import { MAX_KEPT_OUTPUT_CHARACTERS, MAX_SETUP_COMMAND_LENGTH, MAX_SETUP_COMMANDS } from './space-setup.js';
import { sanitizeSpaceTaskTitle, spaceTaskTitleSchema } from './task-title.js';
import { SpaceError } from './errors.js';

const RECORDS_DIRECTORY = path.join('spaces', 'records');

const NETWORK_MODES = Object.freeze(['allowlist', 'open']);
// The allowlist's own rule for a name: labels of letters, digits and hyphens, with a real last label.
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const MAX_DOMAINS = 200;

/** One name of an allowlist. */
export const domainSchema = z.string().regex(DOMAIN_PATTERN);

// `writes` is what the user chose beside the destinations: `ask` holds every POST, PUT, PATCH and
// DELETE for an approval, `allow` lets them out. A record written before the choice exists keeps
// asking, which is the safer reading of an "open internet" space.
export const networkSchema = z.object({
  mode: z.enum(NETWORK_MODES),
  domains: z.array(domainSchema).max(MAX_DOMAINS).default([]),
  writes: z.enum(['ask', 'allow']).default('ask'),
  // The scope an "always" answer saves: the exact request path, or the whole host. A record from
  // before the choice saves paths from now on; its existing host-wide entries remain unchanged.
  writesScope: z.enum(['path', 'host']).default('path'),
});

const historySchema = z.enum(['pending', 'sent', 'already_complete', 'host_shallow', 'failed']);

// The methods the user approved for a destination. GET, HEAD and OPTIONS need no approval, and
// the rest of the list is closed: a method outside these four cannot be approved.
export const WRITABLE_METHODS = Object.freeze(['DELETE', 'PATCH', 'POST', 'PUT']);
const MAX_WRITE_DESTINATIONS = 200;

export const writePathSchema = z.string().startsWith('/').max(2048).regex(/^[^\u0000-\u0020\u007f?#]*$/);

const writeAccessEntrySchema = z.object({
  host: domainSchema,
  methods: z.array(z.enum(WRITABLE_METHODS)).min(1).max(WRITABLE_METHODS.length),
  // An optional exact request path, without a query or fragment. No path means every path of the
  // host. Never normalized: two different strings are two rules.
  path: z.string().startsWith('/').max(2048).regex(/^[^\u0000-\u0020\u007f?#]*$/).optional(),
}).strict();

export const writeAccessSchema = z.array(writeAccessEntrySchema).max(MAX_WRITE_DESTINATIONS).default([]);

const GRANT_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
/** A provider id as the host's catalog names it, which is also the grant id of a model or login grant. */
export const providerIdSchema = z.string().regex(GRANT_ID_PATTERN);
// zod runs the refinement even when `.url()` failed, so the parse of the URL must not throw here.
const isHttpUrl = (value) => {
  try {
    return /^https?:$/.test(new URL(value).protocol);
  } catch {
    return false;
  }
};
export const upstreamSchema = z.string().url().refine(isHttpUrl, 'http or https');
/** A grant's id and header name, shared with the request that asks for one. */
export const grantIdSchema = z.string().regex(GRANT_ID_PATTERN);
export const grantHeaderSchema = z.string().regex(/^[a-z0-9-]{1,64}$/);
/** Where the host finds a secret again, never the secret: an environment variable of the host's by name, or the user typed it once. */
export const secretSourceSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('env'), name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,255}$/) }).strict(),
  z.object({ kind: z.literal('typed') }).strict(),
]);
/**
 * A grant as the host remembers it. Strict, so a value under any name is refused rather than
 * written: a record holds where a secret comes from and never what it is (decision 5).
 */
export const grantSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('model'),
    id: grantIdSchema,
    provider: z.string().regex(GRANT_ID_PATTERN),
    upstream: upstreamSchema,
    header: grantHeaderSchema,
    source: secretSourceSchema,
  }).strict(),
  z.object({
    kind: z.literal('domain'),
    id: grantIdSchema,
    upstream: upstreamSchema,
  }).strict(),
  // A provider's browser login of the host's, since stage 7: the host reads its own login again
  // at every start, so the record names only the provider and the login method it was made by.
  z.object({
    kind: z.literal('login'),
    id: z.string().regex(GRANT_ID_PATTERN),
    provider: z.string().regex(GRANT_ID_PATTERN),
    method: z.string().regex(/^[a-z0-9-]{1,64}$/),
  }).strict(),
  // A provider the user defined in the host's OpenCode configuration, "custom" in Settings: its
  // address, its key and its models are read from the host again at every start, so the record
  // names only the provider.
  z.object({
    kind: z.literal('custom'),
    id: z.string().regex(GRANT_ID_PATTERN),
    provider: z.string().regex(GRANT_ID_PATTERN),
  }).strict(),
  // An MCP server of a shared environment whose calls go through the window, since 2026-11-11:
  // the id is the server's name in the source, and the upstream is the url the source declared.
  z.object({
    kind: z.literal('mcp'),
    id: grantIdSchema,
    upstream: upstreamSchema,
    header: grantHeaderSchema,
    source: secretSourceSchema,
  }).strict(),
]);
const MAX_GRANTS = 100;

// The setup commands' last run (5d-4): begun, finished, or failed with the end of its output,
// which came from inside the space and is text to show. `space-setup.js` keeps it within these.
// A failed run keeps when it began, so the client can find what the gatekeeper refused meanwhile;
// a record from before that has no `startedAt`.
const setupCountSchema = z.number().int().min(1).max(MAX_SETUP_COMMANDS);
const setupSchema = z.discriminatedUnion('state', [
  z.object({ state: z.literal('running'), total: setupCountSchema, startedAt: z.string() }).strict(),
  z.object({ state: z.literal('done'), total: setupCountSchema, finishedAt: z.string() }).strict(),
  z.object({
    state: z.literal('failed'),
    total: setupCountSchema,
    index: z.number().int().min(0).max(MAX_SETUP_COMMANDS - 1),
    command: z.string().max(MAX_SETUP_COMMAND_LENGTH),
    exitCode: z.number().int().nullable(),
    timedOut: z.boolean(),
    output: z.string().max(MAX_KEPT_OUTPUT_CHARACTERS),
    startedAt: z.string().optional(),
    finishedAt: z.string(),
  }).strict(),
]);

const failureSchema = z.object({
  code: z.string(),
  message: z.string(),
  reason: z.string().nullable().default(null),
  at: z.string(),
}).strict();

const environmentStatusSchema = z.object({
  // `ready` delivered, `blocked` never arrived, `off` detached; the copied files stay in the space either way.
  state: z.enum(['ready', 'blocked', 'off']).default('ready'),
  kind: z.enum(['git', 'folder']),
  location: z.string().min(1),
  ref: z.string().default(''),
  memory: z.enum(['off', 'read', 'write']),
  delivery: z.enum(['snapshot', 'mount']).default('snapshot'),
  revision: z.string().min(1).optional(),
  // A Git source's commit; the revision is the hash of its assets, which a memory commit does not move.
  commit: z.string().nullable().optional(),
  included: z.number().int().min(0),
  omitted: z.array(z.object({ path: z.string(), reason: z.string() })).default([]),
  assets: z.record(z.string(), z.unknown()).optional(),
  instructions: z.array(z.string()).default([]),
  // The preferences and ticked items the configuration beside the project takes, as data.
  config: z.record(z.string(), z.unknown()).default({}),
  appliedAt: z.string(),
  lastFailure: failureSchema.optional(),
  memoryStatus: z.object({
    state: z.enum(['synced', 'pending', 'read_only', 'offline', 'needs_auth', 'conflicted']),
    at: z.string(),
    pending: z.number().int().min(0),
    conflicts: z.number().int().min(0),
    revision: z.string().nullable().default(null),
  }).strict().optional(),
  detachedAt: z.string().optional(),
  mountRemains: z.boolean().optional(),
  // A change made while the space was stopped, applied at its next start; the mode it had before.
  pendingChange: z.object({ memory: z.enum(['off', 'read', 'write']) }).strict().optional(),
}).strict();

const recordSchema = z.object({
  version: z.literal(1),
  /** A shared folder or Git repository of passive OpenCode assets and optional shared memory. */
  environment: environmentSourceSchema.nullable().optional(),
  /** The canonical host folder bound read-only into the container at creation, or null. */
  environmentMount: z.string().min(2).nullable().optional(),
  /** What was last delivered, never a claim that a host source is still at that revision. */
  environmentStatus: environmentStatusSchema.nullable().optional(),
  /** The place the space was made on. A record from before there were two names the local Docker place. */
  placeId: z.string().min(1).default('docker'),
  /** The display name and the creation time, as the labels hold them, for a list while the place cannot be asked. */
  name: z.string().nullable().default(null),
  taskTitle: spaceTaskTitleSchema.nullable().default(null),
  created: z.string().nullable().default(null),
  network: networkSchema,
  /** The host repository the code came from, as the user's project names it. */
  repository: z.string().min(1).nullable().default(null),
  /** The project path inside the space that code in returned. */
  spacePath: z.string().min(1).nullable().default(null),
  /** The commit the snapshot was taken from, which the history is sent behind. */
  base: z.string().regex(/^[0-9a-f]{40}$|^[0-9a-f]{64}$/).nullable().default(null),
  history: historySchema.default('pending'),
  /** The grants the user gave, said again to the gatekeeper after every start. */
  grants: z.array(grantSchema).max(MAX_GRANTS).default([]),
  /** The methods the user approved, per destination, said again after every start. */
  writeAccess: writeAccessSchema,
  /** The methods the user denied there. Refused at once, without a prompt, until the user clears them. */
  deniedWrites: writeAccessSchema,
  /** The setup commands' last run, or null before any. */
  setup: setupSchema.nullable().default(null),
});

/**
 * Per-space records under the host's data directory, one JSON file each, readable by the user only.
 * A record that cannot be read as one is reported as `null` with a warning, never as a fresh one:
 * a bad file must not make the host forget a network choice and leave a space more open than asked.
 */
export function createSpaceRecords({ dataDir, logger = console }) {
  const directory = path.join(dataDir, RECORDS_DIRECTORY);
  const fileOf = (spaceId) => path.join(directory, `${requireSpaceId(spaceId)}.json`);

  /**
   * One grant the host cannot read, from a later version that knows another kind among the
   * reasons, is dropped with a warning and never takes the network, the repository and the
   * history of the record with it: the space then shows that grant as missing, not as unknown.
   */
  const withReadableGrants = (spaceId, raw) => {
    if (!(raw instanceof Object) || !Array.isArray(raw.grants)) return raw;
    const grants = raw.grants.filter((grant) => grantSchema.safeParse(grant).success);
    if (grants.length < raw.grants.length) {
      logger.warn?.(`[spaces] the record of space ${spaceId} holds ${raw.grants.length - grants.length} grant(s) this host cannot read; they are left out`);
    }
    return { ...raw, grants };
  };

  /**
   * A setup the host cannot read, from a later version among the reasons, is forgotten with a
   * warning: it only says how the last run of the setup commands went, and must not make the
   * network and the grants unreadable with it.
   */
  const withReadableSetup = (spaceId, raw) => {
    if (!(raw instanceof Object) || raw.setup === undefined || raw.setup === null) return raw;
    if (setupSchema.safeParse(raw.setup).success) return raw;
    logger.warn?.(`[spaces] the record of space ${spaceId} holds a setup this host cannot read; it is left out`);
    return { ...raw, setup: null };
  };

  /**
   * A write approval or denial the host cannot read, from a later version among the reasons, is
   * forgotten with a warning. Getting one wrong only means the user decides once more; it must
   * not take the network and the grants of the record with it. The same for a `writes` choice this
   * host does not know: the space then asks, which is the safer reading.
   */
  const withReadableWrites = (spaceId, raw) => {
    if (!(raw instanceof Object)) return raw;
    let next = raw;
    for (const field of ['writeAccess', 'deniedWrites']) {
      if (next[field] === undefined || writeAccessSchema.safeParse(next[field]).success) continue;
      logger.warn?.(`[spaces] the record of space ${spaceId} holds ${field} this host cannot read; it is left out`);
      next = { ...next, [field]: [] };
    }
    if (next.network instanceof Object && next.network.writes !== undefined && next.network.writes !== 'ask' && next.network.writes !== 'allow') {
      logger.warn?.(`[spaces] the record of space ${spaceId} holds a network write choice this host cannot read; the space asks`);
      next = { ...next, network: { ...next.network, writes: 'ask' } };
    }
    if (next.network instanceof Object && next.network.writesScope !== undefined && next.network.writesScope !== 'path' && next.network.writesScope !== 'host') {
      logger.warn?.(`[spaces] the record of space ${spaceId} holds a write answer scope this host cannot read; answers save the exact path`);
      next = { ...next, network: { ...next.network, writesScope: 'path' } };
    }
    return next;
  };

  /** An environment this host cannot read is forgotten without losing network, grants or setup. */
  const withReadableEnvironment = (spaceId, raw) => {
    if (!(raw instanceof Object)) return raw;
    let next = raw;
    if (next.environment !== undefined && next.environment !== null && !environmentSourceSchema.safeParse(next.environment).success) {
      logger.warn?.(`[spaces] the record of space ${spaceId} holds an environment source this host cannot read; it is left out`);
      next = { ...next, environment: null };
    }
    if (next.environmentStatus !== undefined && next.environmentStatus !== null && !environmentStatusSchema.safeParse(next.environmentStatus).success) {
      logger.warn?.(`[spaces] the record of space ${spaceId} holds an environment status this host cannot read; it is left out`);
      next = { ...next, environmentStatus: null };
    }
    return next;
  };

  /**
   * A record from before one-answer-per-method may list a method as both approved and denied.
   * The approval won then too, so the shadowed denial is not a rule: leave it out. Other methods
   * for the same destination stay denied. This is a read-time normalization, not a file migration.
   */
  const withOneWriteAnswer = (raw) => {
    if (!(raw instanceof Object) || !Array.isArray(raw.writeAccess) || !Array.isArray(raw.deniedWrites)) return raw;
    if (raw.writeAccess.length === 0 || raw.deniedWrites.length === 0) return raw;
    const approvals = new Map(raw.writeAccess.map((entry) => [`${entry.host}\u0000${entry.path ?? ''}`, new Set(entry.methods)]));
    let changed = false;
    const deniedWrites = [];
    for (const entry of raw.deniedWrites) {
      const approved = approvals.get(`${entry.host}\u0000${entry.path ?? ''}`);
      const methods = approved ? entry.methods.filter((method) => !approved.has(method)) : [...entry.methods];
      if (methods.length !== entry.methods.length) changed = true;
      if (methods.length > 0) deniedWrites.push({ ...entry, methods });
    }
    return changed ? { ...raw, deniedWrites } : raw;
  };

  const read = (spaceId) => {
    const file = fileOf(spaceId);
    let text;
    try {
      text = fs.readFileSync(file, 'utf8');
    } catch (error) {
      if (error?.code === 'ENOENT') return { status: 'missing', record: null };
      logger.warn?.(`[spaces] could not read the record of space ${spaceId}: ${error?.code ?? error?.message ?? error}`);
      return { status: 'unreadable', record: null };
    }
    try {
      const raw = withOneWriteAnswer(withReadableEnvironment(spaceId, withReadableWrites(spaceId, withReadableSetup(spaceId, withReadableGrants(spaceId, JSON.parse(text))))));
      // A display name must not make the network choice or grants unreadable.
      if (raw instanceof Object && raw.taskTitle != null && !spaceTaskTitleSchema.safeParse(raw.taskTitle).success) {
        logger.warn?.(`[spaces] the record of space ${spaceId} holds a task title this host cannot read; it is left out`);
        raw.taskTitle = null;
      }
      const parsed = recordSchema.safeParse(raw);
      if (parsed.success) return { status: 'ok', record: parsed.data };
    } catch {
      // Reported below.
    }
    logger.warn?.(`[spaces] the record of space ${spaceId} is not one this host wrote`);
    return { status: 'unreadable', record: null };
  };

  const write = (spaceId, record) => {
    const checked = recordSchema.parse({ version: 1, ...record });
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const file = fileOf(spaceId);
    // Through a temporary name, so a crash in the middle never leaves half a record.
    const temporary = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(checked, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(temporary, file);
    return checked;
  };

  /** Changes some fields of a record that exists. A record that is missing or unreadable is not written. */
  const update = (spaceId, changes) => {
    const current = read(spaceId);
    if (current.status !== 'ok') return current;
    return { status: 'ok', record: write(spaceId, { ...current.record, ...changes }) };
  };

  const remove = (spaceId) => {
    try {
      fs.rmSync(fileOf(spaceId), { force: true });
    } catch (error) {
      logger.warn?.(`[spaces] could not remove the record of space ${spaceId}: ${error?.code ?? error?.message ?? error}`);
    }
  };

  /** Every record the host holds, `{ id, record }`, by space id; one that cannot be read is left out with its warning. */
  const list = () => {
    let names;
    try {
      names = fs.readdirSync(directory);
    } catch (error) {
      if (error?.code !== 'ENOENT') logger.warn?.(`[spaces] could not list the records: ${error?.code ?? error?.message ?? error}`);
      return [];
    }
    return names
      .filter((name) => /^[0-9a-f]{12}\.json$/.test(name))
      .map((name) => ({ id: name.slice(0, -5), ...read(name.slice(0, -5)) }))
      .filter((entry) => entry.status === 'ok')
      .map(({ id, record }) => ({ id, record }));
  };

  const setTaskTitle = (spaceId, { title: rawTitle, by }) => {
    z.enum(['user', 'agent']).parse(by);
    const current = read(spaceId);
    if (current.status !== 'ok') throw new SpaceError('space_record_unreadable', 'The space record cannot be read.');
    const title = sanitizeSpaceTaskTitle(rawTitle);
    if (by === 'agent' && (!title || current.record.taskTitle?.by === 'user')) {
      return { applied: false, taskTitle: current.record.taskTitle };
    }
    const taskTitle = title ? { title, by } : null;
    if (current.record.taskTitle?.title !== title || current.record.taskTitle?.by !== by) write(spaceId, { ...current.record, taskTitle });
    return { applied: true, taskTitle };
  };

  return { read, write, update, remove, list, setTaskTitle };
}
