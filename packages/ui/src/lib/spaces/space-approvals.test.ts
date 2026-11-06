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
});
