# Agent memory

## Ownership

This module owns the agent memory store (`runtime.js`), the `openchamber_memory`
tool's actions (`actions.js`), the panel's routes (`routes.js`), which store a
folder belongs to (`project-resolution.js`), and dreaming (`dreaming.js`), the
pass that tidies the store on its own. What a session is told about memory is
`../session-knowledge`; the panel is `packages/ui/src/components/session/project-context`.

It also owns the shared domain (`shared-store.js`): memory a space reads and
writes through an environment source its user attached. What that source is and
how its operations reach it is `../spaces`, not this module.

What the agent chooses to remember, in three domains:

| Domain | Store | Boundary |
|---|---|---|
| global | `<OPENCHAMBER_DATA_DIR>/memory.json` | one user, every project |
| project | `<OPENCHAMBER_DATA_DIR>/projects/<project-id>/memory.json` | one project, every worktree |
| shared | the folder named by `OPENCHAMBER_SPACE_SHARED_MEMORY_DIR` | only a space whose environment source declares it |

The panel, tool, HTTP routes and session index read the same runtime. No domain is
derived from a model-supplied path or project id.

## Invariants

- A store that cannot be read is a failure, never an empty store (`read`).
- Every write to a scope, a dreaming record and an undo included, runs under
  that scope's lock, so an undo never interleaves with a pass being recorded.
- A dreaming pass never creates entries and never asks: it rewrites by
  `memoryId` and deletes.
- Undo takes back only what the last pass changed: an entry it deleted comes
  back, an entry it rewrote gets its old text unless it changed since. Entries
  created, edited or deleted after the pass stay as they are. A write made while
  the pass ran cannot be told from the pass's own and is undone with it.
- A pass's session carries `metadata.hidden: true` and is deleted when the pass
  ends, so no client or server-side consumer ever sees it.
- A missing store is authoritative empty; a malformed store is a failure, never
  an empty store. A failed domain does not hide a healthy one.
- `global` and `project` keep the version-1 single-document format and its
  process-local writer lock.
- Shared memory is one file per entry plus a tombstone file per deletion. A
  directory lock serialises writers across processes and containers.
- Inside a space every shared change is also recorded as an operation with a
  stable id and the revision it was based on (`operations/`). The host replays
  them against the source (`integrateOperations`); a replay of an id the entry
  remembers changes nothing, so a sync after a crash is idempotent. Conflicted
  operations are kept in `conflicts/`.
- The shared mode is `off`, `read` or `write`: the container's variable,
  overridden by a `.mode` file the host writes. `off` reads as unavailable, never
  as empty. `memory.list` carries `sharedSync`: the mode, the state (`synced`,
  `pending`, `read_only`, `offline`, `needs_auth`, `conflicted`, `off`) and the
  counts, so an agent never takes a local change for a shared one.
- Every shared entry has a stable id and a revision. An update or delete names
  the revision it read; a stale revision is `memory_conflict`, not last-writer
  wins. Wall-clock timestamps order display only.
- Titles, bodies, types, capacities and threat scans apply in every domain.
  Automatic session context carries titles only, never bodies.
- `scope: shared` exists only while the space carries a shared store.
  `scope: both` keeps its pre-shared meaning: private global and project only.
  An omitted list/read scope searches every available domain.
- Read-only shared memory can be read but not mutated. The check is in the
  store boundary, not only in UI visibility.
- Host global and project memory is never imported or mounted into a space by
  this module. A shared domain is a separate source the user attached.

## Dreaming

The server looks a few minutes after it starts and every hour after, so a
desktop app opened and closed through the day still dreams. A scope is due a day
after its last pass, once it holds ten or more entries created or changed since
then, or its titles no longer fit the index sessions get (`measureMemoryIndex`
in `../session-knowledge/runtime.js`). A pass waits while any session runs.
One pass covers one project, the one dreamed longest ago first, and the global
store too when that is due; the global store alone runs in the active project.

The pass is a session in the project's folder, with the model from
`agentMemoryDreamingModel` (else the session defaults), `metadata.hidden: true`
and `metadata.openchamber.kind = 'memory-dream'`, by which a leftover is found. Its permission ruleset denies everything, then allows
reading (not `.env` files), `git log`/`git show`, skills, the model and Code Mode:
session rules are read after the agent's, so no `ask` in the project's config
can wait for a person who is not there. It gets every entry with its id, the
index budget and the rules, and acts through the memory tool. The runtime polls
`/api/session/active` rather than OpenCode's wait route, which outlives Bun's
five-minute fetch timeout while a slow model thinks; every request has its own
timeout, and the pass as a whole 30 minutes. A turn that ended on a provider
error (the newest idle record failed) is a failed pass, never "nothing to tidy".

When it ends, the runtime diffs the store against the snapshot it took and
records the pass in `memory-dream.json` beside the scope's `memory.json`: the
record, `lastRunAt`, and, when anything changed, the snapshot and the id and
`updatedAt` of every entry the pass left, which is how undo tells the pass's
writes from later ones. Then it deletes the session and announces the change to
open panels. The agent's last line, `DREAM {"project": P, "global": G}`, splits
each scope's deleted count into merged and removed. A failed pass is tried again
after six hours.

### Why topical merges wait for an overflow

Every pass merges entries that say the same thing. Entries that only share a
topic are merged into one only while the index leaves titles out: a merged
entry's title names a topic, and a session picks what to read by its title, so
merging fitting entries trades specific titles for nothing.

### Why a hidden session and not a model call

The pass has to check entries against the code and the agent docs, which takes
the agent's own tools. A tool-less call would see only the entries and could
not tell a recipe the skills already hold from one they lack.

### Why hidden by a metadata flag, filtered on the server

`metadata.hidden: true` is a plain flag any session can carry, a plugin's too.
Most events carry only a session id, so a client could not filter them by
metadata; the server learns the hidden ids instead
(`../opencode/hidden-sessions.js`): from a record's metadata in `session.created`
and `session.updated`, from every session list the proxy serves, and from the
list it reads when it connects to OpenCode. It drops their events in the hub
(`../event-stream/global-hub.js`) and the directory bridge, and leaves them out of
the proxy's `/api/session` and `/api/session/active` and the control tool's
`session.list`. The sidebar, In work, notifications, Jev hints and extension
events all read through those, so no consumer needs a check of its own. A
learned id stays for the life of the process, so the events trailing a deleted
session stay hidden too. A session left by a server that stopped mid-pass is
deleted on the first look that reaches OpenCode, dreaming on or off.

### Why undo keeps later writes

A pass is recorded when it ends, and the agent or the user may save or correct
entries before anyone looks at the panel. Restoring the snapshot alone would
undo that work too.

### Why shared entries are files rather than a second memory.json

A source can be written by several OpenChamber installations and spaces.
Whole-file read-modify-write with process-local locks loses updates. Per-entry
files let unrelated ids merge, and revisions plus tombstones give conflict and
deletion semantics without trusting clocks or a single JSON rewrite.

### Why the shared lock is a directory

The same folder may be seen by independent server processes and containers.
`mkdir` is an atomic claim on the supported filesystems, and a stale lock is
removed by age. A process-local promise lock remains correct for the private
single-file stores.

### Why updates require a revision

An agent may hold a title and body from an earlier turn while a teammate changed
the entry. Accepting the write without the revision would silently erase one
side. A conflict tells the agent to read again; the UI route answers 409.
