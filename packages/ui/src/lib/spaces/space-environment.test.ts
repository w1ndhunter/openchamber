import { describe, expect, test } from 'bun:test';

import { environmentStateOf, unsyncedMemoryOf } from './space-environment';
import type { SpaceEnvironmentSource, SpaceEnvironmentStatus } from './spaces-api';

const source = (memory: 'off' | 'read' | 'write' = 'write'): SpaceEnvironmentSource => ({
  kind: 'folder',
  location: '/shared',
  ref: '',
  memory,
  delivery: 'snapshot',
  optIns: { agents: [], mcp: [], plugins: [], commands: [], skills: [], formatter: false, skillSources: [] },
});
const status = (change: Partial<SpaceEnvironmentStatus> = {}): SpaceEnvironmentStatus => ({
  state: 'ready',
  kind: 'folder',
  location: '/shared',
  ref: '',
  memory: 'write',
  delivery: 'snapshot',
  revision: 'abc',
  included: 3,
  omitted: [],
  instructions: [],
  mcpServers: [],
  appliedAt: '2026-11-06T00:00:00.000Z',
  ...change,
});
const failure = (code: string, reason: string | null) => ({ code, message: 'x', reason, at: '2026-11-06T00:00:00.000Z' });

describe('the state of an environment source', () => {
  test('names no state for a space without a source', () => {
    expect(environmentStateOf(null, null)).toBeNull();
  });

  test('ready, and pending until the host has applied it', () => {
    expect(environmentStateOf(source(), status())).toBe('ready');
    expect(environmentStateOf(source(), null)).toBe('pending');
  });

  test('a delivery that failed says what the user can do', () => {
    expect(environmentStateOf(source(), status({ state: 'blocked', lastFailure: failure('environment_source_unavailable', 'needs_auth') }))).toBe('needs_auth');
    expect(environmentStateOf(source(), status({ state: 'blocked', lastFailure: failure('environment_source_unavailable', 'offline') }))).toBe('offline');
    expect(environmentStateOf(source(), status({ state: 'blocked', lastFailure: failure('environment_memory_needs_import', null) }))).toBe('needs_setup');
    expect(environmentStateOf(source(), status({ state: 'blocked', lastFailure: failure('environment_source_unsafe', null) }))).toBe('blocked');
  });

  test('memory that waits, cannot reach its source or conflicts is never shown as ready', () => {
    const live = { available: true as const, state: 'pending', pending: 2, conflicts: 0, entries: 4, at: null };
    expect(environmentStateOf(source(), status(), live)).toBe('pending');
    expect(environmentStateOf(source(), status({ memoryStatus: { state: 'offline', at: 'x', pending: 2, conflicts: 0, revision: null } }), live)).toBe('offline');
    expect(environmentStateOf(source(), status({ memoryStatus: { state: 'conflicted', at: 'x', pending: 0, conflicts: 1, revision: null } }))).toBe('conflicted');
    // Memory off: nothing of memory decides.
    expect(environmentStateOf(source('off'), status({ memoryStatus: { state: 'offline', at: 'x', pending: 0, conflicts: 0, revision: null } }))).toBe('ready');
  });

  test('a detach is off, and a change made while stopped applies on restart', () => {
    expect(environmentStateOf(null, status({ state: 'off' }))).toBe('off');
    expect(environmentStateOf(null, status({ state: 'off', mountRemains: true }))).toBe('off');
    expect(environmentStateOf(source(), status({ pendingChange: { memory: 'off' } }))).toBe('applies_on_restart');
  });

  test('counts what a removal would lose', () => {
    expect(unsyncedMemoryOf({ available: true, state: 'pending', pending: 2, conflicts: 1, entries: 4, at: null })).toBe(3);
    expect(unsyncedMemoryOf({ available: false, reason: 'stopped' })).toBe(0);
    // Unread is unknown, not nothing.
    expect(unsyncedMemoryOf(null)).toBeNull();
  });
});
