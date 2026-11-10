/** The host side of a space's shared environment source. */

import os from 'node:os';

import { createTransferSession, SNAPSHOT_IDENTITY } from './code-transfer.js';
import { SpaceError } from './errors.js';
import {
  applyEnvironmentSource,
  createSourceQueue,
  describePlan,
  detachEnvironmentSource,
  importLegacyMemory,
  inspectEnvironmentSource,
  readSpaceMemoryStatus,
  syncEnvironmentMemory,
} from './environment-source.js';

export const createEnvironmentService = ({ git, exec, temporaryDirectory = os.tmpdir(), removeDirectory, now = () => new Date() }) => {
  const transfer = createTransferSession({ git, temporaryDirectory, removeDirectory, name: 'environment source' });
  // One queue per host for every source: memory publishes to one repository never interleave.
  const queue = createSourceQueue();
  const inspect = (source) => inspectEnvironmentSource({ source, withHostGit: transfer.withHostGit });
  return {
    inspect,
    /** What the dialog shows: the plan without file contents. */
    check: async (source) => describePlan(await inspect(source)),
    /**
     * Inspects again and applies. An inspection or write that fails leaves the snapshot the space
     * has in place: the next snapshot is swapped in only once it is complete.
     */
    apply: async (spaceId, source, { seedMemory = true, mountedAt = null } = {}) => {
      const plan = await inspect(source);
      // The container binds the folder its path named at creation; a path that now resolves elsewhere
      // would have the view checked against one folder and read from another.
      if (source.delivery === 'mount' && mountedAt !== null && plan.location !== mountedAt) {
        throw new SpaceError('environment_mount_unavailable', `${source.location} now resolves to another folder than the one mounted into this space. Make the space again to mount it.`);
      }
      return applyEnvironmentSource({ spaceId, source, plan, exec, seedMemory, now });
    },
    detach: (spaceId) => detachEnvironmentSource({ spaceId, exec }),
    memoryStatus: (spaceId) => readSpaceMemoryStatus({ spaceId, exec }),
    syncMemory: (spaceId, source) => syncEnvironmentMemory({
      spaceId,
      source,
      exec,
      withHostGit: transfer.withHostGit,
      queue,
      snapshotIdentity: SNAPSHOT_IDENTITY,
      now,
    }),
    importMemory: (source, { confirm = false, memoryIds = null } = {}) => importLegacyMemory({
      source,
      inspect,
      withHostGit: transfer.withHostGit,
      queue,
      snapshotIdentity: SNAPSHOT_IDENTITY,
      confirm,
      memoryIds,
      now,
    }),
  };
};
