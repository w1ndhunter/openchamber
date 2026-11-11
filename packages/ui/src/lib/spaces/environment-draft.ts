// The environment source a new space is being made with, as the dialog holds it, and the request
// the host takes from it.

import type { SpaceEnvironmentOptIns, SpaceEnvironmentSourceRequest } from '@/lib/spaces/spaces-api';

/** A key for one MCP server of the source, as the dialog holds it until the space is made. */
export type McpKeyDraft = {
  header: string;
  source: 'typed' | 'env';
  value: string;
  envName: string;
};

export type EnvironmentDraft = {
  kind: 'none' | 'folder' | 'git';
  location: string;
  ref: string;
  memory: 'off' | 'read' | 'write';
  delivery: 'snapshot' | 'mount';
  optIns: SpaceEnvironmentOptIns;
  /** By server name. A server without one goes out without a key. */
  mcpKeys: Record<string, McpKeyDraft>;
  /** What the host said the source offers, so a key knows the url it is for. */
  mcpServers: { name: string; type: 'local' | 'remote'; url?: string }[];
};

export const noOptIns = (): SpaceEnvironmentOptIns => ({ agents: [], mcp: [], plugins: [], commands: [], skills: [], formatter: false, skillSources: [] });

export const emptyMcpKey = (): McpKeyDraft => ({ header: 'authorization', source: 'env', value: '', envName: '' });

/** A header name as the host takes it: lower case, letters, digits and dashes. */
export const headerFieldOf = (typed: string) => typed.toLowerCase().replace(/[^a-z0-9-]/g, '');

/** A host variable name as the host takes it: letters, digits and underscores, not starting with a digit. */
export const variableFieldOf = (typed: string) => typed.replace(/[^A-Za-z0-9_]/g, '').replace(/^\d+/, '');

/** Whether a server's name can name a grant at all; a longer or odder one goes out without a key. */
export const canKeyServer = (name: string) => /^[A-Za-z0-9._-]{1,64}$/.test(name);

export const emptyEnvironmentDraft = (): EnvironmentDraft => ({ kind: 'none', location: '', ref: '', memory: 'off', delivery: 'snapshot', optIns: noOptIns(), mcpKeys: {}, mcpServers: [] });

/** The request the host takes, or null for none. A mount is a folder's only. */
export const environmentRequestOf = (draft: EnvironmentDraft): SpaceEnvironmentSourceRequest | null => (draft.kind === 'none' ? null : {
  kind: draft.kind,
  location: draft.location.trim(),
  ref: draft.kind === 'git' ? draft.ref.trim() : '',
  memory: draft.memory,
  delivery: draft.kind === 'folder' ? draft.delivery : 'snapshot',
  optIns: draft.optIns,
});

export const isEnvironmentDraftComplete = (draft: EnvironmentDraft) => draft.kind === 'none' || draft.location.trim() !== '';
