import { describe, expect, test } from 'bun:test';

import { approvalsOfDirectory, approvalExpired, useSpaceApprovalsStore } from './space-approvals';
import type { SpaceApprovalRequest } from '@/sync/event-pipeline';

const request = (spaceId: string, requestId: number, expiresAt = '2026-11-06T10:00:00.000Z'): SpaceApprovalRequest => ({
  spaceId,
  requestId,
  host: 'api.github.com',
  port: 443,
  method: 'POST',
  expiresAt,
});

describe('the writes waiting for the user', () => {
  test('keeps one prompt per wait, and settles only the one that was answered', () => {
    const store = useSpaceApprovalsStore.getState();
    store.note(request('aaaaaaaaaaaa', 1));
    store.note(request('aaaaaaaaaaaa', 1));
    store.note(request('bbbbbbbbbbbb', 1));
    expect(useSpaceApprovalsStore.getState().requests).toHaveLength(2);

    useSpaceApprovalsStore.getState().settle('aaaaaaaaaaaa', 1);
    expect(useSpaceApprovalsStore.getState().requests).toEqual([request('bbbbbbbbbbbb', 1)]);

    useSpaceApprovalsStore.getState().forgetSpace('bbbbbbbbbbbb');
    expect(useSpaceApprovalsStore.getState().requests).toEqual([]);
  });

  test('shows a chat only the waits of its own space, and a chat outside every space none', () => {
    const mine = request('aaaaaaaaaaaa', 1);
    const other = request('bbbbbbbbbbbb', 1);
    expect(approvalsOfDirectory([mine, other], '/spaces/aaaaaaaaaaaa/project')).toEqual([mine]);
    expect(approvalsOfDirectory([mine, other], '/home/me/app')).toEqual([]);
    expect(approvalsOfDirectory([mine, other], null)).toEqual([]);
  });

  test('carries the URL the space wrote into the wait', () => {
    const store = useSpaceApprovalsStore.getState();
    store.note({ ...request('aaaaaaaaaaaa', 2), url: 'https://api.github.com/repos?x=1' });
    expect(useSpaceApprovalsStore.getState().requests[0]?.url).toBe('https://api.github.com/repos?x=1');
    useSpaceApprovalsStore.getState().resetForRuntimeSwitch();
  });

  test('closes a prompt whose held time passed, and keeps one that has not', () => {
    const now = Date.parse('2026-11-06T09:59:00.000Z');
    expect(approvalExpired(request('aaaaaaaaaaaa', 1, '2026-11-06T10:00:00.000Z'), now)).toBe(false);
    expect(approvalExpired(request('aaaaaaaaaaaa', 1, '2026-11-06T10:00:00.000Z'), Date.parse('2026-11-06T10:00:00.500Z'))).toBe(true);
    // A time the host did not write is not a reason to close a prompt the user may still answer.
    expect(approvalExpired(request('aaaaaaaaaaaa', 1, 'soon'), now)).toBe(false);
  });

  test('lets the same id from a restarted gatekeeper replace the wait it held before', () => {
    const store = useSpaceApprovalsStore.getState();
    const before = { ...request('aaaaaaaaaaaa', 1), host: 'api.github.com' };
    const after = { ...request('aaaaaaaaaaaa', 1), host: 'registry.npmjs.org', url: 'https://registry.npmjs.org/pkg' };
    store.note(before);
    store.note(after);
    // A gatekeeper that restarted begins its ids at one, so the id alone is not the wait.
    expect(useSpaceApprovalsStore.getState().requests).toEqual([after]);
    useSpaceApprovalsStore.getState().resetForRuntimeSwitch();
  });

  test('settles every wait a standing answer covers, and only those', () => {
    const store = useSpaceApprovalsStore.getState();
    const covered = [request('aaaaaaaaaaaa', 1), request('aaaaaaaaaaaa', 2)];
    const otherMethod = { ...request('aaaaaaaaaaaa', 3), method: 'PUT' };
    const otherHost = { ...request('aaaaaaaaaaaa', 4), host: 'registry.npmjs.org' };
    const otherSpace = request('bbbbbbbbbbbb', 5);
    for (const wait of [...covered, otherMethod, otherHost, otherSpace]) store.note(wait);
    useSpaceApprovalsStore.getState().settleCovered('aaaaaaaaaaaa', 'api.github.com', 'POST');
    expect(useSpaceApprovalsStore.getState().requests).toEqual([otherMethod, otherHost, otherSpace]);
    // The same method and host on another path is another answer.
    const otherPath = { ...request('aaaaaaaaaaaa', 6), path: '/b' };
    store.note({ ...request('aaaaaaaaaaaa', 7), path: '/a' });
    store.note(otherPath);
    useSpaceApprovalsStore.getState().settleCovered('aaaaaaaaaaaa', 'api.github.com', 'POST', '/a');
    expect(useSpaceApprovalsStore.getState().requests).toEqual([otherMethod, otherHost, otherSpace, otherPath]);
    useSpaceApprovalsStore.getState().resetForRuntimeSwitch();
  });

  test('drops only the waits whose held time passed, wherever they are', () => {
    const store = useSpaceApprovalsStore.getState();
    store.note(request('aaaaaaaaaaaa', 1, '2026-11-06T10:00:00.000Z'));
    store.note(request('bbbbbbbbbbbb', 2, '2026-11-06T10:05:00.000Z'));
    store.pruneExpired(Date.parse('2026-11-06T10:01:00.000Z'));
    expect(useSpaceApprovalsStore.getState().requests).toEqual([request('bbbbbbbbbbbb', 2, '2026-11-06T10:05:00.000Z')]);
    useSpaceApprovalsStore.getState().resetForRuntimeSwitch();
  });
});
