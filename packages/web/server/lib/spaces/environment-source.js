/**
 * A shared agent environment source: a Git repository or folder with portable
 * OpenCode assets and an optional shared memory folder.
 *
 * The source is data. Its manifest names paths; it cannot grant network,
 * credentials, execution, a host path or a scope. Standard activation copies
 * only passive assets: AGENTS.md, declared instructions, agents, prompt-only
 * commands, text-only skills with their supporting files, references, and an
 * allowlist of preferences from its `opencode.jsonc`. MCP servers, plugins,
 * commands with shell blocks, skills with scripts, formatters and remote skill
 * catalogs travel only when the user ticked that one item. Nothing of the
 * source ever runs on the host.
 *
 * Memory uses the per-entry shared store, never OpenChamber's single
 * memory.json. The host replays the operations a space recorded against the
 * source and publishes only the declared memory subtree.
 */

import crypto from 'node:crypto';
import fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { parse as parseJsonc } from 'jsonc-parser';
import { z } from 'zod';

import {
  createSharedMemoryStore,
  integrateOperations,
  normalizeEntry,
  normalizeOperation,
  normalizeTombstone,
  SHARED_MEMORY_LIMITS,
  writeSharedMemoryState,
} from '../agent-memory/shared-store.js';
import { findThreatPattern } from '../agent-memory/threat-patterns.js';
import { asNonEmptyString, isRecord } from '../shared/guards.js';
import { SpaceError } from './errors.js';
import { tail } from './exec-http.js';
import { ENVIRONMENT_MOUNT_PATH, IMAGE_NODE, SPACE_HOME, spaceWorkPath } from './layout.js';

// The whole tree, memory included, and the part that travels as assets.
const MAX_FILES = 16_000;
const MAX_BYTES = 48 * 1024 * 1024;
const MAX_ASSET_FILES = 2_000;
const MAX_ASSET_BYTES = 8 * 1024 * 1024;
const MAX_DEPTH = 20;
const COMMAND_SHELL_BLOCK = /!\s*`/;
// Frontmatter keys of an agent file that grant it something.
const AGENT_AUTHORITY = /^["']?(?:permission|permissions|tools)["']?\s*:/m;
const frontmatterOf = (text) => /^---\r?\n([\s\S]*?)\r?\n---/.exec(text)?.[1] ?? '';
const SCRIPT_EXTENSION = /\.(?:sh|bash|zsh|fish|ps1|bat|cmd|js|cjs|mjs|ts|tsx|jsx|py|rb|pl|php|go|rs|java|jar|bin|exe|so|dylib|dll|wasm)$/i;
const SAFE_NAME = /^[A-Za-z0-9._@+-][A-Za-z0-9._ @+-]{0,127}$/;
const ITEM_NAME = /^[A-Za-z0-9._-]{1,128}$/;
// Config text that OpenCode would expand from the environment or a file. A shared source has no
// business naming either: that is how a preference would turn into a credential.
const SUBSTITUTION = /\{(?:env|file):/i;
// The links in OpenCode's global config folder that point into the snapshot.
const LINKED_NAMES = Object.freeze(['AGENTS.md', 'agents', 'commands', 'skills', 'plugins']);
// The preferences a source may set without a tick: none of them reaches a program, a network or a credential.
const PREFERENCE_KEYS = Object.freeze(['model', 'default_agent', 'username', 'snapshots', 'compaction', 'watcher', 'tool_output', 'media']);
const SPACE_CONFIG_HOME = `${SPACE_HOME}/.config/opencode`;

// The source repository is untrusted. No user or system filter configuration may run while its
// tree is checked out; a repository can name any filter that its reader happens to have.
const SOURCE_GIT_ENV = Object.freeze({
  GIT_CONFIG_GLOBAL: os.devNull,
  GIT_CONFIG_SYSTEM: os.devNull,
  GIT_ATTR_NOSYSTEM: '1',
  GIT_TERMINAL_PROMPT: '0',
  // A source URL is data. `ext::` and `fd::` run a command on this host, so only transports a
  // person would recognize as fetching a repository are allowed.
  GIT_ALLOW_PROTOCOL: 'https:http:ssh:git:file',
  GIT_PROTOCOL_FROM_USER: '0',
});

const itemList = z.array(z.string().trim().regex(ITEM_NAME)).max(200).default([]);

/** What the user ticked beyond the standard set, item by item. */
export const environmentOptInsSchema = z.object({
  agents: itemList,
  mcp: itemList,
  plugins: itemList,
  commands: itemList,
  skills: itemList,
  formatter: z.boolean().default(false),
  skillSources: z.array(z.string().trim().url().max(2048)).max(50).default([]),
}).strict();

export const environmentSourceSchema = z.object({
  kind: z.enum(['git', 'folder']),
  location: z.string().trim().min(1).max(4096),
  ref: z.string().trim().max(256).default(''),
  memory: z.enum(['off', 'read', 'write']).default('off'),
  // `mount` is a read-only bind of a folder on the Docker host, for passive assets only.
  delivery: z.enum(['snapshot', 'mount']).default('snapshot'),
  optIns: environmentOptInsSchema.default({}),
}).strict().superRefine((source, context) => {
  if (/[\x00-\x1f\x7f]/.test(source.location) || /[\x00-\x1f\x7f]/.test(source.ref)) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'An environment source cannot hold control characters.' });
    return;
  }
  if (source.kind === 'folder' && !path.isAbsolute(source.location)) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'A folder environment source needs an absolute path.' });
  }
  if (source.kind === 'git' && source.delivery === 'mount') {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'Only a folder can be mounted.' });
  }
  if (source.ref.startsWith('-')) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'A branch or tag cannot start with a dash.' });
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(source.location)) {
    try {
      const url = new URL(source.location);
      if (url.username || url.password) {
        context.addIssue({ code: z.ZodIssueCode.custom, message: 'A repository URL cannot carry a username or password.' });
      }
    } catch {
      context.addIssue({ code: z.ZodIssueCode.custom, message: 'The repository URL is not valid.' });
    }
  }
});

const manifestSchema = z.object({
  version: z.literal(1),
  configRoot: z.string().trim().min(1).max(512).default('config'),
  instructions: z.array(z.string().trim().min(1).max(512)).max(200).default([]),
  memory: z.object({
    path: z.string().trim().min(1).max(512).default('memory'),
    format: z.enum(['openchamber-memory-v1', 'openchamber-memory-v2']).default('openchamber-memory-v2'),
  }).strict().nullable().default(null),
}).strict();

const posix = (value) => String(value).replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/+$/, '');

/** A relative path that cannot leave the source. */
const requireRelativePath = (value, label) => {
  const normalized = posix(value);
  if (normalized === '' || normalized.startsWith('/') || normalized.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    throw new SpaceError('invalid_environment_source', `${label} must be a relative path inside the source.`);
  }
  return normalized;
};

const isInside = (root, relative) => relative === root || relative.startsWith(`${root}/`);

/** The source's declared memory path; asking for memory without one is a refusal, not a default. */
const memoryPathOf = (manifest) => {
  if (!manifest.memory) throw new SpaceError('invalid_environment_source', 'This source asks for shared memory but its manifest names no memory path.');
  return requireRelativePath(manifest.memory.path, 'The memory path');
};

const hashFiles = (files) => {
  const hash = crypto.createHash('sha256');
  for (const file of [...files].sort((left, right) => left.path.localeCompare(right.path))) {
    hash.update(file.path);
    hash.update('\0');
    hash.update(file.data);
    hash.update('\0');
  }
  return hash.digest('hex');
};

/**
 * Reads a folder as a bounded, symlink-free tree. A symlink, device, socket or
 * FIFO is refused: the source may come from a shared repository and must not
 * make the host read somewhere else. Two names that differ only in case are
 * refused as well, because a case-insensitive disk in a space or on another
 * host would keep only one of them.
 */
const readFolder = async ({ root }) => {
  const files = [];
  const seen = new Set();
  let bytes = 0;
  const walk = async (directory, prefix, depth) => {
    if (depth > MAX_DEPTH) throw new SpaceError('environment_source_too_large', `The environment source is deeper than ${MAX_DEPTH} folders.`);
    const entries = await fsPromises.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === '.git' && prefix === '') continue;
      if (!SAFE_NAME.test(entry.name) || entry.name === '.' || entry.name === '..') {
        throw new SpaceError('environment_source_unsafe', `The environment source holds a name this host does not copy: ${JSON.stringify(`${prefix}/${entry.name}`)}`);
      }
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const folded = relative.toLowerCase();
      if (seen.has(folded)) throw new SpaceError('environment_source_unsafe', `The environment source holds two paths that differ only in case: ${relative}`);
      seen.add(folded);
      const absolute = path.join(directory, entry.name);
      const stats = await fsPromises.lstat(absolute);
      if (stats.isSymbolicLink()) throw new SpaceError('environment_source_unsafe', `The environment source contains a symbolic link: ${relative}`);
      if (stats.isDirectory()) {
        await walk(absolute, relative, depth + 1);
      } else if (stats.isFile()) {
        bytes += stats.size;
        if (files.length >= MAX_FILES) throw new SpaceError('environment_source_too_large', `The environment source has more than ${MAX_FILES} files.`);
        if (bytes > MAX_BYTES) throw new SpaceError('environment_source_too_large', `The environment source is larger than ${MAX_BYTES} bytes.`);
        files.push({ path: relative, data: await fsPromises.readFile(absolute), mode: stats.mode & 0o777 });
      } else {
        throw new SpaceError('environment_source_unsafe', `The environment source contains a special file: ${relative}`);
      }
    }
  };
  await walk(root, '', 0);
  return files;
};

/** Why a git call failed, in the words of the status: the network, a login, or the source itself. */
const classifyGitFailure = (stderr) => {
  const text = String(stderr ?? '');
  if (/authentication|permission denied|could not read (?:username|password)|terminal prompts disabled|\b40[13]\b|access denied|publickey/i.test(text)) return 'needs_auth';
  if (/could not resolve|unable to access|connection (?:refused|timed out|reset)|network is unreachable|operation timed out|no route to host/i.test(text)) return 'offline';
  return 'unavailable';
};

const gitFailure = (code, what, result) => {
  const reason = classifyGitFailure(result.stderr);
  return new SpaceError(code, `${what}: ${tail(result.stderr) || `exit code ${result.code}`}`, { reason });
};

/**
 * The user's own credential helpers, passed on explicitly. The rest of their git config stays out,
 * because a filter or hook it names would run on the source's checkout; a credential helper is
 * theirs and runs for any fetch they make. Credentials never leave the host.
 */
// How a user reaches their repositories: credential helpers, proxies, certificates, an SSH command
// and URL rewrites. Read from their system and global config, in git's own order, so an empty
// helper that resets the list keeps doing so. Nothing here reads the source's own config.
const TRANSPORT_KEYS = '^(credential\\..*helper|credential\\.usehttppath|http\\..*proxy|https?\\.proxy|http\\..*sslcainfo|http\\..*sslcapath|http\\.sslbackend|core\\.sshcommand|url\\..*\\.(insteadof|pushinsteadof))$';

const credentialArgs = async (g, directory) => {
  // `directory` is our temporary folder, not a repository, so only system and global config answer.
  const result = await g.run(directory, ['config', '--null', '--get-regexp', TRANSPORT_KEYS], { timeoutMs: 10_000 });
  if (result.code !== 0) return [];
  return result.stdout.split('\0').filter(Boolean).flatMap((pair) => {
    const split = pair.indexOf('\n');
    const key = split === -1 ? pair : pair.slice(0, split);
    const value = split === -1 ? '' : pair.slice(split + 1);
    return ['-c', `${key}=${value}`];
  });
};

const cloneRoot = async ({ g, directory, source, credentials }) => {
  const options = [...credentials, 'clone', '--depth', '1', '--no-tags', '--single-branch', '--no-recurse-submodules'];
  if (source.ref !== '') options.push('--branch', source.ref);
  options.push('--', source.location, path.join(directory, 'source'));
  const result = await g.run(directory, options, { timeoutMs: 5 * 60_000, maxOutputBytes: 8 * 1024 * 1024, env: SOURCE_GIT_ENV });
  if (result.code !== 0) throw gitFailure('environment_source_unavailable', 'Could not read the environment repository', result);
};

const readManifest = (files) => {
  const file = files.find((candidate) => candidate.path === '.openchamber/environment.json');
  if (!file) return manifestSchema.parse({ version: 1 });
  let raw;
  try {
    raw = JSON.parse(file.data.toString('utf8'));
  } catch {
    throw new SpaceError('invalid_environment_source', 'The environment manifest is not valid JSON.');
  }
  const parsed = manifestSchema.safeParse(raw);
  if (!parsed.success) throw new SpaceError('invalid_environment_source', 'The environment manifest is not a version this OpenChamber knows, or it names something a manifest cannot.');
  const manifest = parsed.data;
  const configRoot = requireRelativePath(manifest.configRoot, 'The config root');
  if (isInside('.openchamber', configRoot)) throw new SpaceError('invalid_environment_source', 'The config root cannot be inside .openchamber.');
  if (manifest.memory) {
    const memoryPath = requireRelativePath(manifest.memory.path, 'The memory path');
    // Shared memory is written back to the source. A path that overlaps the assets would let a
    // hostile manifest turn a memory publish into a rewrite of the instructions beside it.
    if (isInside(configRoot, memoryPath) || isInside(memoryPath, configRoot) || isInside('.openchamber', memoryPath)) {
      throw new SpaceError('invalid_environment_source', 'The shared memory path must stay apart from the config root and .openchamber.');
    }
  }
  return manifest;
};

const parseJsonFile = (file, label) => {
  try {
    return JSON.parse(file.data.toString('utf8'));
  } catch {
    throw new SpaceError('invalid_environment_source', `${label} is not valid JSON: ${file.path}`);
  }
};

/**
 * The memory a source holds. Version 2 is one file per entry and tombstone. A
 * version 1 file, a single `memory.json`, is offered for a reviewed one-time
 * import and never written; it is not shared memory until the user imports it.
 */
const readMemory = (files, manifest) => {
  if (!manifest.memory) return { format: 'none', entries: [], tombstones: [], legacy: [] };
  const root = memoryPathOf(manifest);
  const entries = [];
  const tombstones = [];
  for (const file of files) {
    if (!file.path.endsWith('.json')) continue;
    if (file.path.startsWith(`${root}/entries/`)) {
      const entry = normalizeEntry(parseJsonFile(file, 'A shared memory entry'));
      if (entry) entries.push(entry);
    } else if (file.path.startsWith(`${root}/tombstones/`)) {
      const tombstone = normalizeTombstone(parseJsonFile(file, 'A shared memory tombstone'));
      if (tombstone) tombstones.push(tombstone);
    }
  }
  const legacyFile = files.find((candidate) => candidate.path === `${root}/memory.json`);
  const hasV2 = entries.length > 0 || tombstones.length > 0 || files.some((file) => file.path.startsWith(`${root}/entries/`) || file.path.startsWith(`${root}/tombstones/`));
  const legacyRaw = legacyFile ? parseJsonFile(legacyFile, 'The version 1 memory file') : null;
  const legacy = Array.isArray(legacyRaw?.entries)
    ? legacyRaw.entries.map(normalizeEntry).filter(Boolean).slice(0, SHARED_MEMORY_LIMITS.entries)
    : [];
  const deleted = new Set(tombstones.map((entry) => entry.id));
  return {
    format: hasV2 || !legacyFile ? 'v2' : 'v1',
    entries: entries.filter((entry) => !deleted.has(entry.id)).slice(0, SHARED_MEMORY_LIMITS.entries),
    tombstones,
    legacy,
  };
};

const skillRootOf = (relative) => {
  const parts = relative.split('/');
  if (parts[0] !== 'skills' || parts.length < 2) return null;
  return parts.length === 2 ? relative : `skills/${parts[1]}`;
};

const skillIdOf = (root) => root.slice('skills/'.length).replace(/\.md$/, '');

const isPassiveFile = (file) => !SCRIPT_EXTENSION.test(file.path) && (file.mode & 0o111) === 0;

const containsSubstitution = (value) => JSON.stringify(value ?? null).match(SUBSTITUTION) !== null;

/** The source's `opencode.jsonc`, parsed without comments, or null for none. */
const readSourceConfig = (files, configRoot, omitted) => {
  const file = files.find((candidate) => candidate.path === `${configRoot}/opencode.jsonc`)
    ?? files.find((candidate) => candidate.path === `${configRoot}/opencode.json`);
  if (!file) return null;
  const errors = [];
  const value = parseJsonc(file.data.toString('utf8'), errors, { allowTrailingComma: true });
  if (errors.length > 0 || !isRecord(value)) {
    omitted.push({ path: file.path.slice(configRoot.length + 1), reason: 'config_unreadable' });
    return null;
  }
  return value;
};

/** An MCP entry with nothing that could carry a credential: headers, environment and OAuth stay behind. */
// Zod drops every key it does not name, which is the point: what is not listed here stays behind.
const mcpCommon = { enabled: z.boolean().optional(), timeout: z.number().int().positive().optional() };
const mcpServerSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('local'), command: z.array(z.string()).min(1), ...mcpCommon }),
  z.object({ type: z.literal('remote'), url: z.string().regex(/^https?:\/\//i), ...mcpCommon }),
]);

const sanitizeMcpServer = (value) => {
  const parsed = mcpServerSchema.safeParse(value);
  if (!parsed.success || containsSubstitution(parsed.data)) return null;
  return parsed.data;
};

/**
 * Which files standard activation may use, what was left out and why, and the
 * items a user could tick. Nothing here is decided by the source: an item it
 * names is an offer, and only the user's tick in `optIns` takes it.
 */
const selectAssets = (files, manifest, optIns) => {
  const configRoot = requireRelativePath(manifest.configRoot, 'The config root');
  const prefix = `${configRoot}/`;
  const omitted = [];
  const chosen = new Map();
  const offers = { agents: [], mcp: [], plugins: [], commands: [], skills: [], formatter: false, skillSources: [] };
  const assets = { agents: [], commands: [], skills: [], instructions: [], references: 0, plugins: [], mcp: [], agentsFile: false, preferences: [] };
  const choose = (file) => chosen.set(file.path, file);
  const skillRoots = new Set();
  const pluginRoots = new Set();
  for (const file of files) {
    if (!file.path.startsWith(prefix)) continue;
    const relative = file.path.slice(prefix.length);
    const parts = relative.split('/');
    const [top] = parts;
    if (relative === 'AGENTS.md') {
      choose(file);
      assets.agentsFile = true;
    } else if (top === 'instructions' || top === 'references') {
      if (isPassiveFile(file)) {
        choose(file);
        if (top === 'references') assets.references += 1;
      } else {
        omitted.push({ path: relative, reason: 'executable_file' });
      }
    } else if (top === 'agents') {
      if (parts.length === 2 && relative.endsWith('.md')) {
        const name = parts[1].replace(/\.md$/, '');
        // An agent that sets its own permissions or tools would replace the space's permission
        // default for whoever picks it: an offer, not a passive file.
        if (AGENT_AUTHORITY.test(frontmatterOf(file.data.toString('utf8')))) {
          offers.agents.push(name);
          if (!optIns.agents.includes(name)) {
            omitted.push({ path: relative, reason: 'agent_permissions' });
            continue;
          }
        }
        choose(file);
        assets.agents.push(name);
      }
    } else if (top === 'commands') {
      if (parts.length !== 2 || !relative.endsWith('.md')) continue;
      const name = parts[1].replace(/\.md$/, '');
      if (COMMAND_SHELL_BLOCK.test(file.data.toString('utf8'))) {
        offers.commands.push(name);
        if (!optIns.commands.includes(name)) {
          omitted.push({ path: relative, reason: 'shell_block' });
          continue;
        }
      }
      choose(file);
      assets.commands.push(name);
    } else if (top === 'skills') {
      const root = skillRootOf(relative);
      if (root) skillRoots.add(root);
    } else if (top === 'plugins' && parts.length >= 2) {
      pluginRoots.add(parts[1]);
    }
  }
  // A skill is whole: its references and templates stay together, or the whole skill stays out.
  for (const root of skillRoots) {
    const id = skillIdOf(root);
    const full = `${prefix}${root}`;
    const members = files.filter((file) => file.path === full || file.path.startsWith(`${full}/`));
    if (!root.endsWith('.md') && !members.some((file) => file.path === `${full}/SKILL.md`)) continue;
    if (!members.every(isPassiveFile)) {
      offers.skills.push(id);
      if (!optIns.skills.includes(id)) {
        omitted.push({ path: root, reason: 'script_skill' });
        continue;
      }
    }
    members.forEach(choose);
    assets.skills.push(id);
  }
  // A plugin runs inside the space when OpenCode starts; it travels only when ticked.
  for (const root of pluginRoots) {
    const name = root.replace(/\.[^.]+$/, '');
    if (!ITEM_NAME.test(name)) continue;
    offers.plugins.push(name);
    if (!optIns.plugins.includes(name)) {
      omitted.push({ path: `plugins/${root}`, reason: 'plugin' });
      continue;
    }
    const full = `${prefix}plugins/${root}`;
    files.filter((file) => file.path === full || file.path.startsWith(`${full}/`)).forEach(choose);
    assets.plugins.push(name);
  }

  const chosenFiles = [...chosen.values()];
  if (chosenFiles.length > MAX_ASSET_FILES || chosenFiles.reduce((sum, file) => sum + file.data.length, 0) > MAX_ASSET_BYTES) {
    throw new SpaceError('environment_source_too_large', `The selected assets are more than ${MAX_ASSET_FILES} files or ${MAX_ASSET_BYTES} bytes.`);
  }
  const pathOf = (file) => file.path.slice(prefix.length);
  // Only the instructions the manifest declares become instructions; the folder alone is a set of files.
  const instructions = [];
  for (const entry of manifest.instructions) {
    const declared = requireRelativePath(entry, 'A declared instruction');
    const matches = chosenFiles.filter((file) => (pathOf(file) === declared || pathOf(file).startsWith(`${declared}/`)) && file.path.endsWith('.md'));
    if (matches.length === 0) omitted.push({ path: declared, reason: 'instruction_missing' });
    for (const file of matches) if (!instructions.includes(pathOf(file))) instructions.push(pathOf(file));
  }
  assets.instructions = instructions;

  // The source's own config: preferences on the allowlist, ticked items, and nothing else.
  const config = {};
  const sourceConfig = readSourceConfig(files, configRoot, omitted);
  if (sourceConfig) {
    for (const [key, value] of Object.entries(sourceConfig)) {
      if (key === '$schema') continue;
      if (PREFERENCE_KEYS.includes(key)) {
        if (containsSubstitution(value)) {
          omitted.push({ path: `opencode.jsonc#${key}`, reason: 'credential_reference' });
        } else {
          config[key] = value;
          assets.preferences.push(key);
        }
        continue;
      }
      if (key === 'mcp' && isRecord(value?.servers)) {
        for (const [name, server] of Object.entries(value.servers)) {
          if (!ITEM_NAME.test(name)) continue;
          offers.mcp.push(name);
          if (!optIns.mcp.includes(name)) {
            omitted.push({ path: `opencode.jsonc#mcp.${name}`, reason: 'mcp' });
            continue;
          }
          const sanitized = sanitizeMcpServer(server);
          if (!sanitized) {
            omitted.push({ path: `opencode.jsonc#mcp.${name}`, reason: 'credential_reference' });
            continue;
          }
          config.mcp ??= { servers: {} };
          config.mcp.servers[name] = sanitized;
          assets.mcp.push(name);
        }
        continue;
      }
      if (key === 'formatter') {
        offers.formatter = true;
        if (!optIns.formatter) omitted.push({ path: 'opencode.jsonc#formatter', reason: 'formatter' });
        else if (containsSubstitution(value)) omitted.push({ path: 'opencode.jsonc#formatter', reason: 'credential_reference' });
        else config.formatter = value;
        continue;
      }
      if (key === 'skills' && Array.isArray(value)) {
        for (const entry of value) {
          if (!z.string().url().regex(/^https:\/\//i).safeParse(entry).success) {
            omitted.push({ path: 'opencode.jsonc#skills', reason: 'skill_path' });
            continue;
          }
          offers.skillSources.push(entry);
          if (optIns.skillSources.includes(entry)) {
            config.skills ??= [];
            config.skills.push(entry);
          } else {
            omitted.push({ path: `opencode.jsonc#skills:${entry}`, reason: 'remote_catalog' });
          }
        }
        continue;
      }
      omitted.push({ path: `opencode.jsonc#${key}`, reason: 'config_not_inherited' });
    }
  }
  // A tick for an item the source does not offer is a refusal: the user ticked something that is not there.
  for (const kind of ['agents', 'mcp', 'plugins', 'commands', 'skills', 'skillSources']) {
    const missing = optIns[kind].filter((name) => !offers[kind].includes(name));
    if (missing.length > 0) throw new SpaceError('invalid_environment_source', `The source does not offer ${kind} ${missing.join(', ')}.`);
  }
  return { configRoot, files: chosenFiles, instructions, config, omitted, offers, assets };
};

const sourceKey = (source) => `${source.kind}\0${source.location}\0${source.ref}`;

/**
 * Work on one source, one at a time per source on this host: two spaces that
 * sync to the same repository integrate one after the other, never in parallel.
 */
export const createSourceQueue = () => {
  const tails = new Map();
  return (source, work) => {
    const key = sourceKey(source);
    const previous = tails.get(key) ?? Promise.resolve();
    const run = previous.catch(() => {}).then(work);
    const settled = run.catch(() => {});
    tails.set(key, settled);
    void settled.then(() => { if (tails.get(key) === settled) tails.delete(key); });
    return run;
  };
};

/** The plan for one source: what would travel, and its stable revision. */
export const inspectEnvironmentSource = async ({ source, withHostGit }) => {
  const parsed = environmentSourceSchema.parse(source);
  const readAt = async (root) => {
    const files = await readFolder({ root });
    const manifest = readManifest(files);
    // The revision of the assets: a memory sync writes to the source and must not read as a new revision.
    const memoryPath = manifest.memory ? requireRelativePath(manifest.memory.path, 'The memory path') : null;
    return {
      manifest,
      contentRevision: hashFiles(memoryPath === null ? files : files.filter((file) => !isInside(memoryPath, file.path))),
      memory: readMemory(files, manifest),
      assets: selectAssets(files, manifest, parsed.optIns),
    };
  };
  if (parsed.kind === 'folder') {
    let root;
    try {
      root = await fsPromises.realpath(parsed.location);
      const stats = await fsPromises.stat(root);
      if (!stats.isDirectory()) throw new Error('not a directory');
    } catch {
      throw new SpaceError('environment_source_unavailable', `${parsed.location} is not a folder this host can read.`, { reason: 'needs_setup' });
    }
    const plan = await readAt(root);
    return { ...plan, revision: plan.contentRevision, location: root };
  }
  if (!withHostGit) throw new SpaceError('environment_source_unavailable', 'Git is not available for the environment source.', { reason: 'needs_setup' });
  return withHostGit('environment_source_unavailable', async (g, directory) => {
    const credentials = await credentialArgs(g, directory);
    await cloneRoot({ g, directory, source: parsed, credentials });
    const root = path.join(directory, 'source');
    const commit = (await g.output(root, ['rev-parse', 'HEAD'], { env: SOURCE_GIT_ENV })).trim();
    const plan = await readAt(root);
    return { ...plan, revision: plan.contentRevision, commit, location: parsed.location };
  });
};

/** What the dialog shows before a space is made: identity, assets, offers and memory, no file contents. */
export const describePlan = (plan) => ({
  location: plan.location,
  revision: plan.revision,
  commit: plan.commit ?? null,
  assets: plan.assets.assets,
  offers: plan.assets.offers,
  omitted: plan.assets.omitted,
  memory: {
    declared: plan.manifest.memory !== null,
    format: plan.memory.format,
    entries: plan.memory.entries.length,
    legacy: plan.memory.legacy.length,
    flagged: plan.memory.entries.filter((entry) => findThreatPattern(`${entry.title}\n${entry.body}`)).length,
  },
});

const environmentPaths = (spaceId) => ({
  environmentRoot: `${spaceWorkPath(spaceId)}/.shared/environment`,
  memoryRoot: `${spaceWorkPath(spaceId)}/.shared/memory`,
  configHome: SPACE_CONFIG_HOME,
});


// Writes the next snapshot beside the current one and swaps them, so a failure before the swap
// leaves the previous revision in place. Links in OpenCode's global folder point into it; a file or
// folder the space made there itself is left alone and reported.
const APPLY_PROGRAM = `
const fs = require('node:fs'), path = require('node:path');
const [base, configHome, memoryRoot] = process.argv.slice(1);
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', () => {
  const p = JSON.parse(input);
  const next = base + '.next', previous = base + '.previous';
  fs.rmSync(next, { recursive: true, force: true });
  fs.mkdirSync(next, { recursive: true, mode: 0o755 });
  for (const f of p.files) {
    const file = path.join(next, f.path);
    if (!file.startsWith(next + '/')) throw new Error('path outside the snapshot');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, Buffer.from(f.data, 'base64'), { mode: (f.mode & 0o755) | 0o400 });
  }
  for (const v of p.view) {
    const file = path.join(next, v.path);
    if (!file.startsWith(next + '/') || !v.target.startsWith(p.mountRoot + '/')) throw new Error('path outside the view');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.symlinkSync(v.target, file);
  }
  fs.rmSync(previous, { recursive: true, force: true });
  if (fs.existsSync(base)) fs.renameSync(base, previous);
  try { fs.renameSync(next, base); } catch (error) { if (fs.existsSync(previous)) fs.renameSync(previous, base); throw error; }
  fs.rmSync(previous, { recursive: true, force: true });
  fs.mkdirSync(configHome, { recursive: true });
  const kept = [];
  for (const name of p.names) {
    const link = path.join(configHome, name);
    let stats = null;
    try { stats = fs.lstatSync(link); } catch {}
    if (stats && stats.isSymbolicLink() && fs.readlinkSync(link).startsWith(base + '/')) fs.unlinkSync(link);
    else if (stats) { kept.push(name); continue; }
    const target = path.join(base, p.configRoot, name);
    if (p.links.includes(name) && fs.existsSync(target)) fs.symlinkSync(target, link);
  }
  if (p.memory) {
    fs.mkdirSync(path.join(memoryRoot, 'entries'), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(memoryRoot, 'tombstones'), { recursive: true, mode: 0o700 });
    if (p.memory.seed) {
      for (const dir of ['entries', 'tombstones']) for (const name of fs.readdirSync(path.join(memoryRoot, dir))) fs.rmSync(path.join(memoryRoot, dir, name), { force: true });
      for (const e of p.memory.state.entries) fs.writeFileSync(path.join(memoryRoot, 'entries', e.id + '.json'), JSON.stringify(e, null, 2) + '\\n', { mode: 0o600 });
      for (const e of p.memory.state.tombstones) fs.writeFileSync(path.join(memoryRoot, 'tombstones', e.id + '.json'), JSON.stringify(e, null, 2) + '\\n', { mode: 0o600 });
      fs.writeFileSync(path.join(memoryRoot, '.status.json'), JSON.stringify(p.memory.status) + '\\n', { mode: 0o600 });
    }
    fs.writeFileSync(path.join(memoryRoot, '.mode'), p.memory.mode + '\\n', { mode: 0o600 });
  }
  process.stdout.write(JSON.stringify({ kept }));
});
`;

// Unlinks what points into the snapshot and turns shared memory off. The copied files stay: a
// detach never erases data the space already has.
const DETACH_PROGRAM = `
const fs = require('node:fs'), path = require('node:path');
const [base, configHome, memoryRoot] = process.argv.slice(1);
for (const name of ${JSON.stringify(LINKED_NAMES)}) {
  const link = path.join(configHome, name);
  try { if (fs.lstatSync(link).isSymbolicLink() && fs.readlinkSync(link).startsWith(base + '/')) fs.unlinkSync(link); } catch {}
}
if (fs.existsSync(memoryRoot)) fs.writeFileSync(path.join(memoryRoot, '.mode'), 'off\\n', { mode: 0o600 });
`;

const READ_MEMORY_PROGRAM = `
const fs = require('node:fs'), path = require('node:path');
const root = process.argv[1];
const read = (dir) => { try { return fs.readdirSync(dir).filter((n) => n.endsWith('.json')).sort().map((n) => { try { return JSON.parse(fs.readFileSync(path.join(dir, n), 'utf8')); } catch { return null; } }); } catch (e) { if (e.code === 'ENOENT') return []; throw e; } };
const status = (() => { try { return JSON.parse(fs.readFileSync(path.join(root, '.status.json'), 'utf8')); } catch { return null; } })();
process.stdout.write(JSON.stringify({ entries: read(path.join(root, 'entries')), tombstones: read(path.join(root, 'tombstones')), operations: read(path.join(root, 'operations')), conflicts: read(path.join(root, 'conflicts')).length, status }));
`;

// Takes the store's own lock, writes the state the source now has, drops the operations that are in
// it, keeps conflicted ones aside, and replays on top any operation that arrived during the sync.
const WRITE_MEMORY_PROGRAM = `
const fs = require('node:fs'), path = require('node:path');
const root = process.argv[1];
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', async () => {
  const p = JSON.parse(input);
  const lock = path.join(root, '.lock');
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  const started = Date.now();
  for (;;) {
    try { fs.mkdirSync(lock); break; } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const stats = (() => { try { return fs.statSync(lock); } catch { return null; } })();
      if (stats && Date.now() - stats.mtimeMs > 30000) { fs.rmSync(lock, { recursive: true, force: true }); continue; }
      if (Date.now() - started > 10000) throw new Error('Shared memory is busy inside the space');
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
  }
  try {
    const dirs = { entries: path.join(root, 'entries'), tombstones: path.join(root, 'tombstones'), operations: path.join(root, 'operations'), conflicts: path.join(root, 'conflicts') };
    for (const dir of Object.values(dirs)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const write = (file, value) => { const temporary = file + '.' + process.pid + '.tmp'; fs.writeFileSync(temporary, JSON.stringify(value, null, 2) + '\\n', { mode: 0o600 }); fs.renameSync(temporary, file); };
    if (p.state) {
      for (const dir of [dirs.entries, dirs.tombstones]) for (const name of fs.readdirSync(dir)) fs.rmSync(path.join(dir, name), { force: true });
      for (const e of p.state.entries) write(path.join(dirs.entries, e.id + '.json'), e);
      for (const e of p.state.tombstones) write(path.join(dirs.tombstones, e.id + '.json'), e);
    }
    const settled = new Set(p.settled), conflicted = new Map(p.conflicts.map((c) => [c.operationId, c]));
    for (const name of fs.readdirSync(dirs.operations).sort()) {
      const file = path.join(dirs.operations, name);
      let op = null;
      try { op = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { fs.rmSync(file, { force: true }); continue; }
      if (settled.has(op.id)) { fs.rmSync(file, { force: true }); continue; }
      if (conflicted.has(op.id)) { write(path.join(dirs.conflicts, op.id + '.json'), { ...op, conflict: conflicted.get(op.id) }); fs.rmSync(file, { force: true }); continue; }
      if (!p.state || !op || typeof op.memoryId !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(op.memoryId)) continue;
      const entryFile = path.join(dirs.entries, op.memoryId + '.json');
      const current = (() => { try { return JSON.parse(fs.readFileSync(entryFile, 'utf8')); } catch { return null; } })();
      const revision = current ? current.revision : 0;
      if (revision !== op.base) continue;
      if (op.kind === 'put' && op.entry) write(entryFile, { ...op.entry, id: op.memoryId, revision: op.base + 1 });
      if (op.kind === 'delete' && current) { fs.rmSync(entryFile, { force: true }); write(path.join(dirs.tombstones, op.memoryId + '.json'), { version: 2, id: op.memoryId, deletedAt: op.at || Date.now(), revision: op.base + 1, operations: [op.id] }); }
    }
    write(path.join(root, '.status.json'), p.status);
    if (p.mode) fs.writeFileSync(path.join(root, '.mode'), p.mode + '\\n', { mode: 0o600 });
  } finally {
    fs.rmSync(lock, { recursive: true, force: true });
  }
});
`;

const execOrFail = async (exec, spaceId, argv, options, code, what) => {
  const result = await exec(spaceId, argv, options);
  if (result.code !== 0) throw new SpaceError(code, `${what}: ${tail(result.stderr) || `exit code ${result.code}`}`);
  return result;
};

/**
 * Materialises the approved tree. The first application seeds shared memory
 * from the source; a later asset refresh leaves the space's memory alone. For
 * a mounted folder nothing is copied: the snapshot is a view of links into the
 * read-only mount, one per selected file, so an unselected file in the folder
 * is never part of OpenCode's discovery.
 */
export const applyEnvironmentSource = async ({ spaceId, source, plan, exec, seedMemory, now = () => new Date() }) => {
  if (source.memory !== 'off' && !plan.manifest.memory) {
    throw new SpaceError('invalid_environment_source', 'This source asks for shared memory but its manifest names no memory path.');
  }
  if (source.memory !== 'off' && plan.memory.format === 'v1' && source.memory === 'write') {
    // A version 1 file is imported once, reviewed, before anything writes to it.
    throw new SpaceError('environment_memory_needs_import', 'This source holds version 1 memory. Import it first; until then it can be attached read-only or not at all.');
  }
  const paths = environmentPaths(spaceId);
  const { configRoot } = plan.assets;
  const mounted = source.delivery === 'mount';
  const payload = {
    files: mounted ? [] : plan.assets.files.map((file) => ({ path: file.path, data: file.data.toString('base64'), mode: file.mode })),
    view: mounted ? plan.assets.files.map((file) => ({ path: file.path, target: `${ENVIRONMENT_MOUNT_PATH}/${file.path}` })) : [],
    mountRoot: ENVIRONMENT_MOUNT_PATH,
    configRoot,
    names: LINKED_NAMES,
    links: LINKED_NAMES.filter((name) => plan.assets.files.some((file) => isInside(`${configRoot}/${name}`, file.path))),
    memory: source.memory === 'off' && !seedMemory ? { mode: 'off', seed: false } : {
      mode: source.memory,
      seed: seedMemory,
      state: { entries: plan.memory.entries, tombstones: plan.memory.tombstones },
      status: { state: source.memory === 'read' ? 'read_only' : 'synced', at: now().toISOString(), revision: plan.revision, conflicts: [] },
    },
  };
  const result = await execOrFail(exec, spaceId, [IMAGE_NODE, '-e', APPLY_PROGRAM, paths.environmentRoot, paths.configHome, paths.memoryRoot], {
    stdin: JSON.stringify(payload),
    timeoutMs: 120_000,
    maxOutputBytes: 1024 * 1024,
  }, 'space_setup_failed', 'Could not apply the environment source');
  let kept = [];
  try {
    kept = JSON.parse(result.stdout).kept ?? [];
  } catch {
    kept = [];
  }
  const omitted = [...plan.assets.omitted, ...kept.filter((name) => asNonEmptyString(name) !== null).map((name) => ({ path: name, reason: 'space_file_kept' }))];
  return {
    kind: source.kind,
    location: plan.location,
    ref: source.ref,
    memory: source.memory,
    delivery: source.delivery,
    revision: plan.revision,
    commit: plan.commit ?? null,
    included: plan.assets.files.length,
    omitted,
    assets: plan.assets.assets,
    instructions: plan.assets.instructions.map((relative) => `${paths.environmentRoot}/${configRoot}/${relative}`),
    config: plan.assets.config,
    appliedAt: now().toISOString(),
  };
};

export const detachEnvironmentSource = async ({ spaceId, exec }) => {
  const paths = environmentPaths(spaceId);
  await execOrFail(exec, spaceId, [IMAGE_NODE, '-e', DETACH_PROGRAM, paths.environmentRoot, paths.configHome, paths.memoryRoot], { timeoutMs: 60_000 }, 'space_setup_failed', 'Could not detach the environment source');
};

const readSpaceMemory = async ({ spaceId, exec }) => {
  const output = await execOrFail(exec, spaceId, [IMAGE_NODE, '-e', READ_MEMORY_PROGRAM, environmentPaths(spaceId).memoryRoot], {
    timeoutMs: 60_000,
    maxOutputBytes: 16 * 1024 * 1024,
  }, 'environment_memory_unavailable', 'Could not read shared memory from the space');
  let parsed;
  try {
    parsed = JSON.parse(output.stdout);
  } catch {
    throw new SpaceError('environment_memory_unavailable', 'Shared memory inside the space answered in an unknown shape.');
  }
  const list = (value, limit) => (Array.isArray(value) ? value.slice(0, limit) : []);
  return {
    entries: list(parsed?.entries, SHARED_MEMORY_LIMITS.entries).map(normalizeEntry).filter(Boolean),
    tombstones: list(parsed?.tombstones, SHARED_MEMORY_LIMITS.tombstones).map(normalizeTombstone).filter(Boolean),
    // What the agent wrote is data: an operation that is not one, or names a field the contract does not have, is dropped.
    operations: list(parsed?.operations, SHARED_MEMORY_LIMITS.operations).map(normalizeOperation).filter(Boolean),
    conflicts: Number.isSafeInteger(parsed?.conflicts) && parsed.conflicts >= 0 ? parsed.conflicts : 0,
    reported: isRecord(parsed?.status) ? parsed.status : null,
  };
};

/**
 * What waits in a space's shared memory now: the pending operations and the conflicts kept aside.
 * Read from the space, so a deletion can warn about changes the source does not have yet. The
 * state the space reports is shown as the space's, and only a name the host knows passes.
 */
export const readSpaceMemoryStatus = async ({ spaceId, exec }) => {
  const space = await readSpaceMemory({ spaceId, exec });
  const reported = ['synced', 'read_only', 'offline', 'needs_auth', 'conflicted'].includes(space.reported?.state) ? space.reported.state : null;
  // The conflicts of the latest sync: `conflicts/` keeps every set-aside change for a person to
  // read, and a later sync that went through is no longer in conflict.
  const conflicts = Array.isArray(space.reported?.conflicts) ? space.reported.conflicts.length : 0;
  let state = reported ?? 'pending';
  if (conflicts > 0) state = 'conflicted';
  else if (space.operations.length > 0 && reported !== 'offline' && reported !== 'needs_auth') state = 'pending';
  return {
    state,
    pending: space.operations.length,
    conflicts,
    setAside: space.conflicts,
    entries: space.entries.length,
    at: asNonEmptyString(space.reported?.at),
  };
};

const writeSpaceMemory = ({ spaceId, exec, payload }) => execOrFail(exec, spaceId, [IMAGE_NODE, '-e', WRITE_MEMORY_PROGRAM, environmentPaths(spaceId).memoryRoot], {
  stdin: JSON.stringify(payload),
  timeoutMs: 60_000,
  maxOutputBytes: 1024 * 1024,
}, 'environment_memory_unavailable', 'Could not write shared memory into the space');

const statePaths = (memoryPath) => [`${memoryPath}/entries`, `${memoryPath}/tombstones`];

/** The folder adapter: the source's own store lock, then a revision-checked replay. */
const integrateFolder = async ({ source, operations, now, allowLegacy = false }) => {
  let root;
  try {
    root = await fsPromises.realpath(source.location);
  } catch {
    throw new SpaceError('environment_source_unavailable', `${source.location} is not a folder this host can read.`, { reason: 'offline' });
  }
  const manifest = readManifest(await readFolder({ root }));
  const memoryRoot = path.join(root, memoryPathOf(manifest));
  const store = createSharedMemoryStore({ root: memoryRoot });
  return store.withLock(async () => {
    const files = await readFolder({ root });
    const current = readMemory(files, readManifest(files));
    if (current.format === 'v1' && operations.length > 0 && !allowLegacy) throw new SpaceError('environment_memory_needs_import', 'This source holds version 1 memory. Import it first.');
    const result = integrateOperations(current, operations, { now, allowFlagged: allowLegacy });
    const changed = result.touched.length > 0;
    if (changed) await writeSharedMemoryState(memoryRoot, result);
    return { ...result, revision: hashFiles(await readFolder({ root })), published: changed };
  });
};

/**
 * The Git adapter: clone the fixed branch, replay, write only the memory
 * subtree, commit with a fixed identity and no hooks, and push that branch
 * without force. A push that lost a race is integrated again from a new clone;
 * no remote, ref, path or commit comes from the space.
 */
const integrateGit = async ({ source, operations, withHostGit, snapshotIdentity, now, allowLegacy = false }) => {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const outcome = await withHostGit('environment_memory_unavailable', async (g, directory) => {
      const credentials = await credentialArgs(g, directory);
      await cloneRoot({ g, directory, source, credentials });
      const root = path.join(directory, 'source');
      const files = await readFolder({ root });
      const manifest = readManifest(files);
      const memoryPath = memoryPathOf(manifest);
      const current = readMemory(files, manifest);
      if (current.format === 'v1' && operations.length > 0 && !allowLegacy) throw new SpaceError('environment_memory_needs_import', 'This source holds version 1 memory. Import it first.');
      const result = integrateOperations(current, operations, { now, allowFlagged: allowLegacy });
      const head = (await g.output(root, ['rev-parse', 'HEAD'], { env: SOURCE_GIT_ENV })).trim();
      if (result.touched.length === 0) return { ...result, revision: head, published: false };
      const branch = await g.run(root, ['symbolic-ref', '--quiet', '--short', 'HEAD'], { env: SOURCE_GIT_ENV });
      if (branch.code !== 0) throw new SpaceError('environment_memory_read_only', 'A tag or a commit can be read, but shared memory can only be written to a branch.');
      await writeSharedMemoryState(path.join(root, memoryPath), result);
      await g.output(root, ['add', '--all', '--', ...statePaths(memoryPath)], { env: SOURCE_GIT_ENV });
      const staged = (await g.output(root, ['diff', '--cached', '--name-only', '-z'], { env: SOURCE_GIT_ENV })).split('\0').filter(Boolean);
      // The commit holds memory files and nothing else, whatever the write above did.
      if (staged.some((file) => !statePaths(memoryPath).some((allowed) => file.startsWith(`${allowed}/`)))) {
        throw new SpaceError('environment_memory_unavailable', 'A shared memory publish would have changed files outside the memory folder; nothing was published.');
      }
      if (staged.length === 0) return { ...result, revision: head, published: false };
      const commit = await g.run(root, ['commit', '--no-verify', '--no-gpg-sign', '-m', 'Update shared agent memory'], {
        env: { ...SOURCE_GIT_ENV, ...snapshotIdentity },
        timeoutMs: 120_000,
      });
      if (commit.code !== 0) throw new SpaceError('environment_memory_unavailable', `Could not commit shared memory: ${tail(commit.stderr) || `exit code ${commit.code}`}`);
      const target = `refs/heads/${branch.stdout.trim()}`;
      const push = await g.run(root, [...credentials, 'push', '--porcelain', '--no-verify', 'origin', `HEAD:${target}`], { timeoutMs: 5 * 60_000, env: SOURCE_GIT_ENV });
      if (push.code !== 0) {
        const text = `${push.stderr}\n${push.stdout}`;
        if (/rejected|non-fast-forward|fetch first|stale info/i.test(text)) return { retry: true };
        throw gitFailure('environment_memory_unavailable', 'Shared memory was not published', push);
      }
      return { ...result, revision: (await g.output(root, ['rev-parse', 'HEAD'], { env: SOURCE_GIT_ENV })).trim(), published: true };
    });
    if (!outcome.retry) return outcome;
  }
  throw new SpaceError('environment_memory_unavailable', 'The source kept changing while shared memory was published; try again.', { reason: 'pending' });
};

const integrate = (options) => (options.source.kind === 'folder' ? integrateFolder(options) : integrateGit(options));

/**
 * One sync of a space's shared memory with its source. In write mode the
 * operations the space recorded are replayed against the source; in read mode
 * nothing is published. Either way the space then holds the source's state,
 * with any change still pending replayed on top. Assets are never touched.
 *
 * A source that cannot be reached is reported as offline with the pending
 * count, never as an empty success.
 */
export const syncEnvironmentMemory = async ({ spaceId, source, exec, withHostGit, queue, snapshotIdentity = {}, now = () => new Date() }) => {
  if (source.memory === 'off') throw new SpaceError('environment_memory_off', 'This space has no shared memory.');
  const space = await readSpaceMemory({ spaceId, exec });
  // The host's record decides the mode, not the space: a `.mode` file it rewrote changes nothing here.
  const operations = source.memory === 'write' ? space.operations : [];
  let result;
  try {
    result = await queue(source, () => integrate({ source, operations, withHostGit, snapshotIdentity, now: () => now().getTime() }));
  } catch (error) {
    const reason = error?.details?.reason;
    if (error instanceof SpaceError && (reason === 'offline' || reason === 'needs_auth' || reason === 'unavailable' || reason === 'pending')) {
      const status = { state: reason === 'needs_auth' ? 'needs_auth' : 'offline', at: now().toISOString(), message: error.message, conflicts: [] };
      await writeSpaceMemory({ spaceId, exec, payload: { state: null, settled: [], conflicts: [], status } }).catch(() => {});
      return { ...status, pending: space.operations.length, published: false };
    }
    throw error;
  }
  const state = result.conflicts.length > 0 ? 'conflicted' : source.memory === 'read' ? 'read_only' : 'synced';
  const status = { state, at: now().toISOString(), revision: result.revision, conflicts: result.conflicts };
  await writeSpaceMemory({
    spaceId,
    exec,
    payload: {
      state: { entries: result.entries, tombstones: result.tombstones },
      settled: result.settled,
      conflicts: result.conflicts,
      status,
      mode: source.memory,
    },
  });
  return {
    ...status,
    pending: source.memory === 'write' ? 0 : space.operations.length,
    published: result.published,
    settled: result.settled.length,
  };
};

const importOperationId = (entry) => `import${crypto.createHash('sha256').update(entry.id).digest('hex').slice(0, 24)}`;

/**
 * The reviewed one-time import of a version 1 `memory.json`. Without `confirm`
 * it answers what would be imported, with the entries the threat scan flags;
 * with it, those entries become version 2 files beside it. The operation ids
 * come from the entry ids, so running the import twice imports once.
 */
export const importLegacyMemory = async ({ source, inspect, withHostGit, queue, snapshotIdentity = {}, confirm, memoryIds = null, now = () => new Date() }) => {
  const plan = await inspect(source);
  if (!plan.manifest.memory) throw new SpaceError('invalid_environment_source', 'This source names no memory path.');
  const candidates = plan.memory.legacy.map((entry) => ({ ...entry, flagged: findThreatPattern(`${entry.title}\n${entry.body}`) !== null }));
  if (!confirm) return { entries: candidates.map(({ id, title, body, type, flagged }) => ({ id, title, body, type, flagged })), imported: 0 };
  const chosen = candidates.filter((entry) => (memoryIds === null ? !entry.flagged : memoryIds.includes(entry.id)));
  const operations = chosen.map((entry, index) => normalizeOperation({
    version: 1,
    id: importOperationId(entry),
    sequence: index,
    kind: 'put',
    memoryId: entry.id,
    base: 0,
    entry,
    at: now().getTime(),
  })).filter(Boolean);
  // The import writes the first version 2 files, so the version 1 guard of a normal sync does not apply.
  const result = await queue(source, () => integrate({
    source: { ...source, memory: 'write' },
    operations,
    withHostGit,
    snapshotIdentity,
    now: () => now().getTime(),
    allowLegacy: true,
  }));
  return { imported: result.settled.length, conflicts: result.conflicts, revision: result.revision };
};
