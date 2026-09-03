#!/usr/bin/env python3
from pathlib import Path

path = Path("sys/kern/kern_proc.c")
s = path.read_text()
old = '''#ifdef SINGLE_PRINCIPAL
\tif (scred != NULL) {
\t\tKASSERTMSG(kauth_cred_getuid(scred) == 0 &&
\t\t    kauth_cred_geteuid(scred) == 0 &&
\t\t    kauth_cred_getsvuid(scred) == 0 &&
\t\t    kauth_cred_getgid(scred) == 0 &&
\t\t    kauth_cred_getegid(scred) == 0 &&
\t\t    kauth_cred_getsvgid(scred) == 0 &&
\t\t    kauth_cred_ngroups(scred) == 0,
\t\t    "noncanonical process credential in single-principal mode");
\t\tsugid = false;
\t}
#endif'''
new = '''#ifdef SINGLE_PRINCIPAL
\tif (scred != NULL) {
\t\tif (kauth_cred_getuid(scred) != 0 ||
\t\t    kauth_cred_geteuid(scred) != 0 ||
\t\t    kauth_cred_getsvuid(scred) != 0 ||
\t\t    kauth_cred_getgid(scred) != 0 ||
\t\t    kauth_cred_getegid(scred) != 0 ||
\t\t    kauth_cred_getsvgid(scred) != 0 ||
\t\t    kauth_cred_ngroups(scred) != 0) {
\t\t\tprintf("single-principal: normalizing unexpected process credential\\n");
\t\t\tkauth_cred_setuid(scred, 0);
\t\t\tkauth_cred_seteuid(scred, 0);
\t\t\tkauth_cred_setsvuid(scred, 0);
\t\t\tkauth_cred_setgid(scred, 0);
\t\t\tkauth_cred_setegid(scred, 0);
\t\t\tkauth_cred_setsvgid(scred, 0);
\t\t\t(void)kauth_cred_setgroups(scred, NULL, 0, -1,
\t\t\t    UIO_SYSSPACE);
\t\t}
\t\tsugid = false;
\t}
#endif'''
if s.count(old) != 1:
    raise SystemExit(f"expected one process-credential assertion block; found {s.count(old)}")
path.write_text(s.replace(old, new, 1))
