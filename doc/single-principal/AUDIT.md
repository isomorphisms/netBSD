# Single-principal phase-1 audit

This audit is for the amd64 `SINGLEPRINCIPAL` spike only.  It classifies UID/GID dependencies rather than treating a smaller grep result as semantic removal.  Phase 1 keeps the ABI and FFS disk format intact.

## Security-model seam inspected first

The initial inspection covered:

- `sys/secmodel/overlay/secmodel_overlay.c`
- `sys/secmodel/overlay/files.overlay`
- `sys/secmodel/suser/secmodel_suser.c`
- `sys/secmodel/bsd44/secmodel_bsd44.c`
- `sys/secmodel/bsd44/files.bsd44`
- `sys/secmodel/files.secmodel`
- `sys/conf/std`

The stock overlay is useful but not sufficient.  It removes the suser vnode listener, which is desirable here because UID 0 must not rescue a failed mode check, but it also fails to replay the securelevel vnode listener.  The explicit `secmodel_singleprincipal` retains securelevel's vnode veto and omits only the suser vnode grant.

`SINGLEPRINCIPAL` also removes GENERIC's `INSECURE` option so securelevel remains an independent restriction in the executable experiment.

## Changed in this spike

### Kauth credential storage and process mutation

- `sys/kern/kern_prot.c`: shared `do_setresuid` / `do_setresgid` reject explicit nonzero identities with `EOPNOTSUPP`; 0/unchanged requests are no-ops.  `getgroups` reports zero; empty `setgroups` succeeds and nonempty `setgroups` fails; `issetugid` is false.
- `sys/kern/kern_auth.c`: `kauth_cred_setgroups` rejects nonempty supplementary groups when `SINGLE_PRINCIPAL` is compiled, closing an internal/public mutation seam as well as the syscall path.
- `sys/kern/kern_proc.c`: publication of a process credential is a central invariant point.  Unexpected internally constructed noncanonical process credentials are detected, logged, and normalized to 0:0 with no supplementary groups rather than being allowed into `p_cred`.
- `sys/kern/kern_exec.c`: `credexec` refuses a pre-existing noncanonical process credential, never installs set-ID file ownership, clears `PK_SUGID`, and leaves the sole identity unchanged.
- Fork already holds/inherits the parent's process credential; with canonical parent credentials it preserves the sole identity without a separate fork UID patch.

The raw `kauth_cred_t` representation and low-level setters still contain UID/GID fields.  Kernel code can still construct a foreign credential for non-process uses.  That is residue, not a claim that credentials have been structurally deleted.

### Vnode ownership and mode checks

- `sys/miscfs/genfs/genfs_vnops.c`: normal non-ACL `genfs_can_access` coerces stored owner/group to the calling compatibility credential before class selection.  This always selects owner mode bits and, through the existing owner path, grants `VADMIN` without granting read/write/execute that the owner bits deny.
- The same file neutralizes ownership distinctions in generic chmod/chflags/chtimes/sticky checks and rejects a foreign chown at the generic authorization seam.
- `sys/ufs/ufs/ufs_vnops.c`: FFS/UFS chown rejects an explicitly requested nonzero UID/GID before applying it.
- `sys/ufs/ffs/ffs_vfsops.c`: new FFS objects are initialized with compatibility ownership 0:0 rather than inheriting a legacy nonzero directory group.
- `secmodel_singleprincipal`: a failed vnode DAC result is not rescued by suser's UID-zero vnode callback; securelevel's vnode callback remains active.

Read-only mounts, immutable/append-only flags and filesystem-level checks execute before or independently of the mode-bit result and are intentionally not bypassed.

### Set-ID execution and directory inheritance

Set-user-ID and set-group-ID executable bits remain representable on disk but `credexec` does not install their owner/group into a process credential and does not mark the process as having undergone an identity transition.  FFS new-object ownership is forced to 0:0, so setgid-directory group inheritance cannot create a nonzero process or new-file group in the supported FFS target.  The legacy mode bits remain present.

### Sticky directories

`genfs_can_sticky` is evaluated as though both directory and target ownership belong to the sole principal.  Sticky remains a directory policy bit, but it no longer selects between process identities.

## Semantically neutralized but still present

### Process visibility, signals, ptrace and ktrace

The normal process authorization machinery is retained.  UID comparisons used for `KAUTH_PROCESS_CANSEE` collapse because every process credential is 0.  The single-principal model also retains suser process authority, so actions traditionally granted to UID 0 remain broadly available to the sole principal.  PID, parent/child, session, kernel-address exposure, VM/address-space and other non-UID constraints remain where their call sites impose them.

This is **not** process/service privilege separation.  Signals, ptrace, ktrace and related process-control authority need a separate phase-2 authority model if isolation between services is desired.

### Resource limits

Per-process rlimits remain.  UID-based exemptions/accounting around resource limits still exist and now key to compatibility ID 0 for normal processes.  Removing or redefining those exceptions is a phase-2 authority/accounting task.

### Temporary filesystems

`tmpfs_access` calls `genfs_can_access`, so ordinary tmpfs mode checks inherit the owner-class behavior and still enforce read-only mounts and immutable flags.  tmpfs retains its own stored `tn_uid`/`tn_gid`, creation and setattr machinery; phase 1 does not claim tmpfs as an audited on-disk/ownership target.  FFS is the executable acceptance filesystem.

### Device nodes

Device nodes on the FFS acceptance root use the same FFS/genfs pathname permission checks before device-specific authorization.  Device-scope kauth policy remains suser/securelevel based under the new model.  This branch does not redesign device authority and does not claim that all device drivers have identity-free policy.

## Retained ABI or disk-format residue

The following deliberately remain:

- `uid_t` and `gid_t` typedefs and syscall arguments;
- UID/GID fields in `struct ucred` / `kauth_cred_t`;
- real/effective/saved UID and GID slots;
- supplementary-group array storage, although process credentials expose zero entries in this mode;
- syscall numbers and compatibility entry points;
- `struct stat` / `vattr` ownership fields;
- FFS inode UID/GID fields and existing nonzero on-disk values;
- stat/getattr reporting of existing legacy ownership metadata;
- login/session strings such as `s_login`, which are labels rather than authorization identities;
- protocol structures that carry numeric credentials;
- kernel module APIs that allocate, clone, inspect or construct credentials.

Existing nonzero FFS `st_uid` / `st_gid` values are intentionally visible as inert legacy metadata.  New FFS objects are 0:0.

## Disabled in `SINGLEPRINCIPAL`

The experimental amd64 configuration disables only identity-dependent facilities not given coherent phase-1 semantics:

- `UFS_ACL` — UID/group ACL interpretation is not active.
- `QUOTA` and `QUOTA2` — per-user/per-group quota ownership is not modeled.
- `NFSSERVER` — server-side remote credential mapping is not modeled.
- `SYSVMSG`, `SYSVSEM`, `SYSVSHM` — SysV IPC ownership is not modeled.

`MEMORY_DISK_DYNAMIC` is disabled only as established amd64 INSTALL-kernel boot plumbing for the embedded FFS acceptance root.  GENERIC hardware and networking support are otherwise inherited.

## Phase-2 blockers / retained semantic UID machinery

### Per-UID process/LWP and resource accounting

`sys/kern/kern_uidinfo.c` and `sys/sys/uidinfo.h` remain.  `uid_init()` creates a UID hash, ensures UID 0 exists, and `chgproccnt`, `chglwpcnt`, semaphore counts and socket-buffer accounting continue to index `struct uidinfo` by numeric UID.  For normal single-principal processes these counters collapse onto compatibility ID 0; the data model is not removed.

### POSIX IPC ownership

POSIX semaphore/message-queue and related resource accounting remains enabled.  Fresh kernel objects created from process credentials normally see compatibility ID 0, but their UID/GID fields and authorization logic have not been structurally removed or comprehensively redefined.  This is a phase-2 blocker, not part of the FFS acceptance claim.

### Sockets carrying credentials

Socket credential structures and ancillary-data interfaces continue to carry numeric UID/GID/group information.  Process-originated credentials should encode the compatibility identity, but the ABI and internal representation remain.  Socket-buffer resource accounting also remains keyed through `uidinfo`.

### NFS credential mapping

The NFS server is disabled.  NFS client/RPC AUTH_SYS credential encoding remains in the tree and still has numeric UID/GID semantics; process requests in this mode originate from 0:0, but the protocol machinery is not removed.  Supporting NFS as a truly identity-free filesystem/protocol is phase 2 or later.

### procfs and process sysctls

Procfs/process-export structures and `KERN_PROC_UID/RUID/GID/RGID` selectors remain ABI-visible.  They observe the compatibility process credentials rather than disappearing.  This is retained compatibility surface.

### Filesystems outside the FFS target

Filesystems that call ordinary `genfs_can_access` receive the owner-class mode behavior, but not every filesystem has been validated for creation ownership, chown/setattr, ACLs, network credential mapping, or filesystem-specific access routines.  Unsupported filesystems/configurations therefore remain explicit SKIP territory in phase 1.

### Compatibility syscall layers

The native setuid/setgid/seteuid/setegid/setreuid/setregid/setresuid/setresgid paths in `kern_prot.c` converge on the shared `do_setresuid` / `do_setresgid` helpers and therefore receive the phase-1 rejection rule.  Compatibility structures and old stat/credential ABIs remain.  A complete deletion phase must audit every compat translation before removing fields or syscall numbers.

### Kernel modules constructing credentials

`kauth_cred_alloc`, clone/copy operations and low-level setters remain usable for kernel-internal objects.  The process-publication seam prevents such a credential from remaining noncanonical as a process identity, but foreign non-process credentials can still exist.  Removing that representational possibility is phase 2.

## Unrelated uses of “user”

`maxusers`, `USERCONF`, `USER_LDT`, comments describing users/userland, usernames in documentation, and similarly named interfaces are not evidence of a process-user security axis by themselves.  `maxusers` remains unchanged; it sizes/tunes kernel resources and is not a credential-removal mechanism.

## Grep inventory

The executable acceptance run records exact commands, exit status and counts for the following inventory.  The counts are evidence of remaining surface area, not proof of semantic removal:

```sh
git grep -n -E '\b(uid_t|gid_t)\b' -- sys
git grep -n -E 'kauth_cred_(get|set|clone|copy|alloc|dup)' -- sys
git grep -n -E '\b(uid_init|uid_find|chgproccnt|chglwpcnt|chgsemcnt|chgsbsize)\b' -- sys
git grep -n -E '(va_uid|va_gid|st_uid|st_gid|i_uid|i_gid|tn_uid|tn_gid)' -- sys
git grep -n -E '(KAUTH_PROCESS_|ptrace|ktrace)' -- sys
git grep -n -E '(SCM_CREDS|sockcred|unpcbid|cr_uid|cr_gid)' -- sys
git grep -n -E '(AUTH_SYS|authunix|NFS.*cred|nfs.*cred)' -- sys
```

Exact counts are copied into the final receipt commit after the acceptance run; changing these counts is not itself a completion criterion.
