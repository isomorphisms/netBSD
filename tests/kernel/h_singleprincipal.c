/* $NetBSD$ */
/*
 * Direct executable contract probe for SINGLE_PRINCIPAL.
 *
 * This is intentionally usable without ATF so it can run from the minimal
 * FFS root used by the QEMU acceptance receipt.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

static void
result(const char *name, bool ok, const char *detail)
{
	printf("%s\t%s\t%s\n", ok ? "PASS" : "FAIL", name, detail);
	if (!ok)
		failures++;
}

static bool
singleprincipal_enabled(void)
{
	int enabled = 0;
	size_t len = sizeof(enabled);

	if (sysctlbyname("security.models.singleprincipal.enabled", &enabled,
	    &len, NULL, 0) == -1)
		return false;
	return len == sizeof(enabled) && enabled == 1;
}

static bool
ids_are_zero(void)
{
	return getuid() == 0 && geteuid() == 0 &&
	    getgid() == 0 && getegid() == 0;
}

static bool
no_supplementary_groups(void)
{
	return getgroups(0, NULL) == 0;
}

static bool
fails_eopnotsupp(int rv)
{
	return rv == -1 && errno == EOPNOTSUPP;
}

static bool
copy_file(const char *src, const char *dst)
{
	char buf[32768];
	ssize_t nr;
	int in, out;

	in = open(src, O_RDONLY);
	if (in == -1)
		return false;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0700);
	if (out == -1) {
		close(in);
		return false;
	}
	while ((nr = read(in, buf, sizeof(buf))) > 0) {
		ssize_t off = 0;
		while (off < nr) {
			ssize_t nw = write(out, buf + off, (size_t)(nr - off));
			if (nw <= 0) {
				close(in);
				close(out);
				return false;
			}
			off += nw;
		}
	}
	if (nr < 0) {
		close(in);
		close(out);
		return false;
	}
	if (close(in) == -1 || close(out) == -1)
		return false;
	return true;
}

static int
child_identity(const char *kind)
{
	bool ok;

	ok = singleprincipal_enabled();
	result("running_mode_detection", ok, ok ? "enabled=1" : "wrong kernel");
	ok = ids_are_zero();
	result(kind, ok, ok ? "uid/euid/gid/egid=0" : "nonzero identity");
	ok = no_supplementary_groups();
	result("child_groups", ok, ok ? "supplementary groups=0" :
	    "supplementary groups nonempty");
	ok = issetugid() == 0;
	result("issetugid", ok, ok ? "false" : "true");
	return failures == 0 ? 0 : 1;
}

static bool
wait_success(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) != pid)
		return false;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void
test_identity_changes(void)
{
	gid_t group = 0;
	bool ok;

	errno = 0;
	ok = setuid(0) == 0;
	result("setuid_zero", ok, ok ? "no-op succeeded" : strerror(errno));

	errno = 0;
	ok = setgid(0) == 0;
	result("setgid_zero", ok, ok ? "no-op succeeded" : strerror(errno));

	errno = 0;
	ok = setresuid((uid_t)-1, (uid_t)-1, (uid_t)-1) == 0;
	result("setresuid_unchanged", ok, ok ? "no-op succeeded" :
	    strerror(errno));

	errno = 0;
	ok = setresgid((gid_t)-1, (gid_t)-1, (gid_t)-1) == 0;
	result("setresgid_unchanged", ok, ok ? "no-op succeeded" :
	    strerror(errno));

	errno = 0;
	ok = setgroups(0, NULL) == 0;
	result("setgroups_empty", ok, ok ? "no-op succeeded" : strerror(errno));

	errno = 0;
	ok = fails_eopnotsupp(setuid(1));
	result("setuid_nonzero", ok, ok ? "EOPNOTSUPP" : strerror(errno));

	errno = 0;
	ok = fails_eopnotsupp(setgid(1));
	result("setgid_nonzero", ok, ok ? "EOPNOTSUPP" : strerror(errno));

	errno = 0;
	ok = fails_eopnotsupp(setresuid((uid_t)-1, 1, (uid_t)-1));
	result("setresuid_nonzero", ok, ok ? "EOPNOTSUPP" : strerror(errno));

	errno = 0;
	ok = fails_eopnotsupp(setresgid((gid_t)-1, 1, (gid_t)-1));
	result("setresgid_nonzero", ok, ok ? "EOPNOTSUPP" : strerror(errno));

	errno = 0;
	ok = fails_eopnotsupp(setgroups(1, &group));
	result("setgroups_nonempty", ok, ok ? "EOPNOTSUPP" : strerror(errno));

	ok = ids_are_zero() && no_supplementary_groups();
	result("identity_still_canonical", ok,
	    ok ? "all process IDs=0; supplementary groups=0" :
	    "identity changed after rejected request");
}

static void
test_fork_and_exec(const char *self)
{
	pid_t pid;
	bool ok;
	char path[MAXPATHLEN];

	pid = fork();
	if (pid == 0)
		_exit(ids_are_zero() && no_supplementary_groups() ? 0 : 1);
	ok = pid > 0 && wait_success(pid);
	result("fork_identity", ok, ok ? "child remained 0:0" :
	    "fork child identity failure");

	(void)snprintf(path, sizeof(path), "/tmp/sp-exec-%ld", (long)getpid());
	unlink(path);
	ok = copy_file(self, path);
	result("exec_fixture_copy", ok, ok ? path : strerror(errno));
	if (!ok)
		return;

	ok = chmod(path, 0000) == 0;
	if (ok) {
		pid = fork();
		if (pid == 0) {
			execl(path, path, "--exec-child", (char *)NULL);
			_exit(errno == EACCES ? 0 : 2);
		}
		ok = pid > 0 && wait_success(pid);
	}
	result("owner_execute_required", ok,
	    ok ? "0000 exec denied" : "0000 exec was not denied");

	ok = chmod(path, 0100) == 0;
	if (ok) {
		pid = fork();
		if (pid == 0) {
			execl(path, path, "--exec-child", (char *)NULL);
			_exit(127);
		}
		ok = pid > 0 && wait_success(pid);
	}
	result("owner_execute_allows_exec", ok,
	    ok ? "0100 exec succeeded with canonical identity" :
	    "0100 exec failed");
	unlink(path);
}

static void
test_setid_exec(const char *fixture)
{
	struct stat st;
	pid_t pid;
	bool ok;

	ok = stat(fixture, &st) == 0;
	result("setid_fixture_present", ok, ok ? "fixture found" : strerror(errno));
	if (!ok)
		return;
	ok = (st.st_mode & (S_ISUID | S_ISGID)) == (S_ISUID | S_ISGID) &&
	    (st.st_uid != 0 || st.st_gid != 0);
	result("setid_fixture_legacy_owner", ok,
	    ok ? "set-ID bits and nonzero legacy owner present" :
	    "fixture lacks set-ID/nonzero legacy ownership");
	if (!ok)
		return;

	pid = fork();
	if (pid == 0) {
		execl(fixture, fixture, "--setid-child", (char *)NULL);
		_exit(127);
	}
	ok = pid > 0 && wait_success(pid);
	result("setid_exec_identity", ok,
	    ok ? "set-ID exec stayed 0:0 and issetugid=false" :
	    "set-ID exec changed identity or issetugid");
}

static bool
open_succeeds(const char *path, int flags)
{
	int fd = open(path, flags);
	if (fd == -1)
		return false;
	close(fd);
	return true;
}

static void
test_file_modes(void)
{
	char path[MAXPATHLEN];
	struct stat st;
	int fd;
	bool ok;

	(void)snprintf(path, sizeof(path), "/tmp/sp-mode-%ld", (long)getpid());
	unlink(path);
	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
	ok = fd != -1;
	if (fd != -1)
		close(fd);
	result("create_file", ok, ok ? "created" : strerror(errno));
	if (!ok)
		return;

	ok = stat(path, &st) == 0 && st.st_uid == 0 && st.st_gid == 0;
	result("new_file_owner", ok, ok ? "st_uid=0 st_gid=0" :
	    "new file is not compatibility owner 0:0");

	errno = 0;
	ok = chown(path, 0, 0) == 0 && chown(path, (uid_t)-1, (gid_t)-1) == 0;
	result("chown_zero_or_unchanged", ok, ok ? "succeeded" : strerror(errno));

	errno = 0;
	ok = fails_eopnotsupp(chown(path, 1, (gid_t)-1));
	result("chown_nonzero_uid", ok, ok ? "EOPNOTSUPP" : strerror(errno));

	errno = 0;
	ok = fails_eopnotsupp(chown(path, (uid_t)-1, 1));
	result("chown_nonzero_gid", ok, ok ? "EOPNOTSUPP" : strerror(errno));

	ok = chmod(path, 0400) == 0 && open_succeeds(path, O_RDONLY) &&
	    !open_succeeds(path, O_WRONLY);
	result("mode_0400", ok, ok ? "read allowed; write denied" :
	    "owner read/write contract failed");

	ok = chmod(path, 0200) == 0 && open_succeeds(path, O_WRONLY) &&
	    !open_succeeds(path, O_RDONLY);
	result("mode_0200", ok, ok ? "write allowed; read denied" :
	    "owner read/write contract failed");

	ok = chmod(path, 0000) == 0 && !open_succeeds(path, O_RDONLY) &&
	    !open_succeeds(path, O_WRONLY);
	result("mode_0000", ok, ok ? "read and write denied" :
	    "failed VFS mode check was rescued");

	ok = chmod(path, 0600) == 0 && chflags(path, UF_IMMUTABLE) == 0;
	if (ok) {
		errno = 0;
		ok = !open_succeeds(path, O_WRONLY);
	}
	result("immutable_restriction", ok, ok ? "write denied despite 0200-class authority" :
	    "UF_IMMUTABLE did not prevent write");
	(void)chflags(path, 0);
	(void)unlink(path);
}

static int
generic_smoke(void)
{
	gid_t group = 1;
	bool ok;

	ok = !singleprincipal_enabled();
	result("generic_mode_detection", ok,
	    ok ? "single-principal sysctl absent/off" : "single-principal enabled");
	if (!ok)
		return 1;

	ok = getuid() == 0 && geteuid() == 0;
	result("generic_start_root", ok, ok ? "uid/euid=0" : "not root");

	errno = 0;
	ok = setgroups(1, &group) == 0;
	result("generic_setgroups_nonempty", ok,
	    ok ? "ordinary group transition succeeded" : strerror(errno));

	errno = 0;
	ok = setgid(1) == 0;
	result("generic_setgid_nonzero", ok,
	    ok ? "ordinary GID transition succeeded" : strerror(errno));

	errno = 0;
	ok = setuid(1) == 0;
	result("generic_setuid_nonzero", ok,
	    ok ? "ordinary UID transition succeeded" : strerror(errno));

	ok = getuid() == 1 && geteuid() == 1 && getgid() == 1 && getegid() == 1;
	result("generic_nonzero_identity", ok,
	    ok ? "ordinary user model retained" : "nonzero identity not installed");
	return failures == 0 ? 0 : 1;
}

int
main(int argc, char **argv)
{
	const char *fixture = "/singleprincipal-setid";
	bool ok;

	if (argc > 1 && strcmp(argv[1], "--exec-child") == 0)
		return child_identity("exec_identity");
	if (argc > 1 && strcmp(argv[1], "--setid-child") == 0)
		return child_identity("setid_child_identity");
	if (argc > 1 && strcmp(argv[1], "--generic-smoke") == 0)
		return generic_smoke();
	if (argc > 1)
		fixture = argv[1];

	ok = singleprincipal_enabled();
	result("running_mode_detection", ok, ok ? "enabled=1" : "wrong kernel");
	if (!ok)
		return 2;

	ok = ids_are_zero();
	result("credential_getters", ok, ok ? "uid/euid/gid/egid=0" :
	    "nonzero process identity");
	ok = no_supplementary_groups();
	result("getgroups", ok, ok ? "supplementary groups=0" :
	    "supplementary groups nonempty");

	test_identity_changes();
	test_fork_and_exec(argv[0]);
	test_setid_exec(fixture);
	test_file_modes();

	printf("SUMMARY\t%s\tfailures=%d\n", failures == 0 ? "PASS" : "FAIL",
	    failures);
	return failures == 0 ? 0 : 1;
}
