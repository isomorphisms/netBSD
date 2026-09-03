# Single-principal compatibility mode

## Phase 1 contract

`SINGLE_PRINCIPAL` is an experimental compile-time mode that collapses the traditional process-user axis to one principal while retaining NetBSD ABI and on-disk ownership fields.

The compatibility encoding of the sole principal is UID 0, GID 0. This is not the final conceptual design and is not a claim that `uid_t`, `gid_t`, `struct stat` ownership fields, filesystem ownership fields, UID accounting, or compatibility syscall numbers have been removed.

Two facts must be read together:

1. There is no distinction between process users in this mode.
2. Until authority is redesigned separately, every process has much of the host authority traditionally associated with UID 0.

This mode does **not** provide privilege separation between services. A daemon that asks to become a nonzero service UID/GID must receive `EOPNOTSUPP`; the kernel must not falsely report that privilege dropping succeeded.

## Process identity

When `SINGLE_PRINCIPAL` is enabled:

- `getuid()`, `geteuid()`, `getgid()`, and `getegid()` return 0.
- `getgroups()` reports zero supplementary groups.
- Process credentials exposed through the normal process credential path remain canonically 0:0 with no supplementary groups.
- `fork` preserves that sole identity.
- `exec` preserves that sole identity; set-user-ID and set-group-ID file bits never install a file owner/group as a process credential.
- `issetugid()` remains false because there is no identity transition.
- `setuid`, `setgid`, `setresuid`, and `setresgid` requests containing only 0 or the interface's unchanged sentinel succeed as no-ops.
- Any request to install a nonzero UID or GID fails with `EOPNOTSUPP`.
- Empty `setgroups` succeeds as a no-op; nonempty `setgroups` fails with `EOPNOTSUPP`.

## Filesystem identity and permissions

For the initial executable target, FFS is the supported root filesystem.

- New filesystem objects receive compatibility ownership 0:0.
- Existing nonzero `st_uid`/`st_gid` values may remain visible as inert legacy metadata. Phase 1 does not rewrite FFS disk formats.
- `chown` to 0:0 or unchanged values may succeed. A request containing a nonzero UID or GID fails with `EOPNOTSUPP`.
- Ordinary non-ACL access checks always select the owner permission class. Stored file UID/GID values do not select a different process identity.
- Owner read/write/execute bits are the single live mode-bit class. Group and other bits remain ABI-compatible legacy fields but do not denote other process identities.
- `0400` permits reading and denies writing; `0200` permits writing and denies reading; `0000` denies both; execution requires the owner execute bit.
- Vnode administration (`VADMIN`) is available to the sole principal for ordinary metadata management, subject to independent restrictions.
- UID-zero superuser fallback must not rescue a failed vnode mode check.

The following remain independent restrictions and are not removed by this experiment: read-only mounts, immutable and append-only flags, securelevel, VM protection, address-space separation, and other non-identity policy checks.

## Security-model seam

The stock `secmodel_overlay` is useful scaffolding because it stops the normal suser/securelevel listeners and replays selected listeners through internal scopes. It intentionally has no suser vnode fallback, so UID 0 does not rescue a failed vnode mode check.

It is not sufficient unchanged for this experiment: it also omits `secmodel_securelevel_vnode_cb`, which means the securelevel veto on vnode system-flag writes would be lost. `SINGLE_PRINCIPAL` therefore uses an explicit single-principal security model derived from the overlay structure: retain suser behavior for non-vnode authority, retain securelevel vetoes including its vnode callback, and omit only the suser vnode permission override.

Normal GENERIC semantics must remain unchanged.

## Initial executable scope

Acceptance target:

- NetBSD/amd64 under QEMU;
- FFS root filesystem;
- boot to a single-user shell.

The `SINGLEPRINCIPAL` amd64 configuration may disable identity-dependent facilities that are not modeled coherently in phase 1. Initial planned exclusions are UFS ACL processing, quotas, NFS server identity mapping, and SysV IPC ownership. Every actual exclusion is recorded in `AUDIT.md` and `receipts.tsv`.

Full multiuser startup is not an initial acceptance requirement. Existing daemons may fail when they request nonzero service identities; that failure is preferable to deceptively acknowledging an identity change that did not occur.

## Explicit non-goals / phase 2

Phase 1 does not delete:

- `uid_t` or `gid_t`;
- UID/GID fields in `struct stat` or filesystem metadata;
- syscall numbers or ABI layout;
- per-UID process/LWP accounting keyed to compatibility ID 0;
- all compatibility layers, sockets carrying credentials, NFS mapping, procfs ownership reporting, or every filesystem-specific ownership implementation.

Actual removal of identity fields and accounting is phase 2 and should start only if build, boot, and behavioral evidence from this compatibility spike is credible.
