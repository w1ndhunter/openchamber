// How a space's environment source reads on screen: one state the user can act on, from the
// record the host keeps. The host decides; this only names what it decided.

import type { SpaceEnvironmentSource, SpaceEnvironmentStatus, SpaceLiveMemory } from '@/lib/spaces/spaces-api';

export type SpaceEnvironmentState =
  | 'ready'
  | 'needs_setup'
  | 'needs_auth'
  | 'pending'
  | 'offline'
  | 'conflicted'
  | 'blocked'
  | 'off'
  | 'applies_on_restart';

const fromReason = (reason: string | null | undefined, code: string): SpaceEnvironmentState => {
  if (reason === 'needs_auth') return 'needs_auth';
  if (reason === 'offline') return 'offline';
  if (reason === 'needs_setup' || code === 'environment_memory_needs_import' || code === 'environment_source_unavailable') return 'needs_setup';
  return 'blocked';
};

/**
 * The one state of a source. A delivery that failed outranks memory; memory that cannot reach its
 * source or holds a conflict outranks "ready"; a detached mount stays until the space is made again.
 * `live` is the space's memory read now, when the dialog asked for it.
 */
export const environmentStateOf = (
  source: SpaceEnvironmentSource | null | undefined,
  status: SpaceEnvironmentStatus | null | undefined,
  live: SpaceLiveMemory | null = null,
): SpaceEnvironmentState | null => {
  if (!source) return status?.state === 'off' ? 'off' : null;
  if (!status) return 'pending';
  if (status.pendingChange) return 'applies_on_restart';
  if (status.state === 'blocked') return fromReason(status.lastFailure?.reason, status.lastFailure?.code ?? '');
  if (source.memory !== 'off') {
    const memory = live?.available ? live : null;
    const conflicts = memory?.conflicts ?? status.memoryStatus?.conflicts ?? 0;
    if (conflicts > 0) return 'conflicted';
    const reported = status.memoryStatus?.state;
    if (reported === 'offline') return 'offline';
    if (reported === 'needs_auth') return 'needs_auth';
    if ((memory?.pending ?? 0) > 0) return 'pending';
  }
  return 'ready';
};

/** The tone of each state, as the status badge shows it. */
export const environmentStateTone = (state: SpaceEnvironmentState): 'success' | 'warning' | 'error' | 'muted' => {
  switch (state) {
    case 'ready':
      return 'success';
    case 'pending':
    case 'needs_setup':
    case 'needs_auth':
    case 'offline':
    case 'applies_on_restart':
      return 'warning';
    case 'conflicted':
    case 'blocked':
      return 'error';
    case 'off':
      return 'muted';
  }
};

/**
 * The shared memory changes a removal or detach would leave behind: a count, or null when the
 * space's memory could not be read, which is never taken for zero.
 */
export const unsyncedMemoryOf = (live: SpaceLiveMemory | null): number | null => {
  if (live === null) return null;
  return live.available ? live.pending + live.conflicts : 0;
};
