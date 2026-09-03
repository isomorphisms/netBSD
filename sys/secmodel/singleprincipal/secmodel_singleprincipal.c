/* $NetBSD$ */
/*-
 * Experimental single-principal compatibility security model.
 *
 * This is deliberately derived from secmodel_overlay's composition pattern:
 * suser answers non-vnode authority questions, securelevel retains its vetoes,
 * and vnode requests do not receive suser's UID-zero permission override.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kauth.h>
#include <sys/module.h>
#include <sys/sysctl.h>

#include <secmodel/secmodel.h>
#include <secmodel/suser/suser.h>
#include <secmodel/securelevel/securelevel.h>

#define SECMODEL_SINGLEPRINCIPAL_NAME \
    "Single-principal compatibility model"
#define SECMODEL_SINGLEPRINCIPAL_ID \
    "org.netbsd.secmodel.singleprincipal"

#define SP_ISCOPE_GENERIC "org.netbsd.kauth.singleprincipal.generic"
#define SP_ISCOPE_SYSTEM  "org.netbsd.kauth.singleprincipal.system"
#define SP_ISCOPE_PROCESS "org.netbsd.kauth.singleprincipal.process"
#define SP_ISCOPE_NETWORK "org.netbsd.kauth.singleprincipal.network"
#define SP_ISCOPE_MACHDEP "org.netbsd.kauth.singleprincipal.machdep"
#define SP_ISCOPE_DEVICE  "org.netbsd.kauth.singleprincipal.device"

MODULE(MODULE_CLASS_SECMODEL, secmodel_singleprincipal,
    "suser,securelevel,extensions");

static kauth_scope_t sp_iscope_generic;
static kauth_scope_t sp_iscope_system;
static kauth_scope_t sp_iscope_process;
static kauth_scope_t sp_iscope_network;
static kauth_scope_t sp_iscope_machdep;
static kauth_scope_t sp_iscope_device;

static kauth_listener_t l_generic, l_system, l_process, l_network, l_machdep;
static kauth_listener_t l_device, l_vnode;
static secmodel_t singleprincipal_sm;
static int singleprincipal_enabled = 1;

static int secmodel_singleprincipal_generic_cb(kauth_cred_t, kauth_action_t,
    void *, void *, void *, void *, void *);
static int secmodel_singleprincipal_system_cb(kauth_cred_t, kauth_action_t,
    void *, void *, void *, void *, void *);
static int secmodel_singleprincipal_process_cb(kauth_cred_t, kauth_action_t,
    void *, void *, void *, void *, void *);
static int secmodel_singleprincipal_network_cb(kauth_cred_t, kauth_action_t,
    void *, void *, void *, void *, void *);
static int secmodel_singleprincipal_machdep_cb(kauth_cred_t, kauth_action_t,
    void *, void *, void *, void *, void *);
static int secmodel_singleprincipal_device_cb(kauth_cred_t, kauth_action_t,
    void *, void *, void *, void *, void *);
static int secmodel_singleprincipal_vnode_cb(kauth_cred_t, kauth_action_t,
    void *, void *, void *, void *, void *);

static void
secmodel_singleprincipal_init(void)
{
	sp_iscope_generic = kauth_register_scope(SP_ISCOPE_GENERIC, NULL, NULL);
	sp_iscope_system = kauth_register_scope(SP_ISCOPE_SYSTEM, NULL, NULL);
	sp_iscope_process = kauth_register_scope(SP_ISCOPE_PROCESS, NULL, NULL);
	sp_iscope_network = kauth_register_scope(SP_ISCOPE_NETWORK, NULL, NULL);
	sp_iscope_machdep = kauth_register_scope(SP_ISCOPE_MACHDEP, NULL, NULL);
	sp_iscope_device = kauth_register_scope(SP_ISCOPE_DEVICE, NULL, NULL);

	kauth_listen_scope(SP_ISCOPE_GENERIC, secmodel_suser_generic_cb, NULL);

	kauth_listen_scope(SP_ISCOPE_SYSTEM, secmodel_suser_system_cb, NULL);
	kauth_listen_scope(SP_ISCOPE_SYSTEM, secmodel_securelevel_system_cb,
	    NULL);

	kauth_listen_scope(SP_ISCOPE_PROCESS, secmodel_suser_process_cb, NULL);
	kauth_listen_scope(SP_ISCOPE_PROCESS, secmodel_securelevel_process_cb,
	    NULL);

	kauth_listen_scope(SP_ISCOPE_NETWORK, secmodel_suser_network_cb, NULL);
	kauth_listen_scope(SP_ISCOPE_NETWORK, secmodel_securelevel_network_cb,
	    NULL);

	kauth_listen_scope(SP_ISCOPE_MACHDEP, secmodel_suser_machdep_cb, NULL);
	kauth_listen_scope(SP_ISCOPE_MACHDEP, secmodel_securelevel_machdep_cb,
	    NULL);

	kauth_listen_scope(SP_ISCOPE_DEVICE, secmodel_suser_device_cb, NULL);
	kauth_listen_scope(SP_ISCOPE_DEVICE, secmodel_securelevel_device_cb,
	    NULL);
}

SYSCTL_SETUP(sysctl_security_singleprincipal_setup,
    "single-principal security model sysctls")
{
	const struct sysctlnode *rnode;

	sysctl_createv(clog, 0, NULL, &rnode,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "models", NULL,
	    NULL, 0, NULL, 0,
	    CTL_SECURITY, CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, &rnode,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_NODE, "singleprincipal",
	    SYSCTL_DESCR("Single-principal compatibility mode"),
	    NULL, 0, NULL, 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_STRING, "name", NULL,
	    NULL, 0, __UNCONST(SECMODEL_SINGLEPRINCIPAL_NAME), 0,
	    CTL_CREATE, CTL_EOL);

	sysctl_createv(clog, 0, &rnode, NULL,
	    CTLFLAG_PERMANENT,
	    CTLTYPE_INT, "enabled",
	    SYSCTL_DESCR("1 when single-principal compatibility mode is active"),
	    NULL, 0, &singleprincipal_enabled, 0,
	    CTL_CREATE, CTL_EOL);
}

static void
secmodel_singleprincipal_start(void)
{
	l_generic = kauth_listen_scope(KAUTH_SCOPE_GENERIC,
	    secmodel_singleprincipal_generic_cb, NULL);
	l_system = kauth_listen_scope(KAUTH_SCOPE_SYSTEM,
	    secmodel_singleprincipal_system_cb, NULL);
	l_process = kauth_listen_scope(KAUTH_SCOPE_PROCESS,
	    secmodel_singleprincipal_process_cb, NULL);
	l_network = kauth_listen_scope(KAUTH_SCOPE_NETWORK,
	    secmodel_singleprincipal_network_cb, NULL);
	l_machdep = kauth_listen_scope(KAUTH_SCOPE_MACHDEP,
	    secmodel_singleprincipal_machdep_cb, NULL);
	l_device = kauth_listen_scope(KAUTH_SCOPE_DEVICE,
	    secmodel_singleprincipal_device_cb, NULL);
	l_vnode = kauth_listen_scope(KAUTH_SCOPE_VNODE,
	    secmodel_singleprincipal_vnode_cb, NULL);
}

static void
secmodel_singleprincipal_stop(void)
{
	kauth_unlisten_scope(l_generic);
	kauth_unlisten_scope(l_system);
	kauth_unlisten_scope(l_process);
	kauth_unlisten_scope(l_network);
	kauth_unlisten_scope(l_machdep);
	kauth_unlisten_scope(l_device);
	kauth_unlisten_scope(l_vnode);
}

static int
secmodel_singleprincipal_modcmd(modcmd_t cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MODULE_CMD_INIT:
		error = secmodel_register(&singleprincipal_sm,
		    SECMODEL_SINGLEPRINCIPAL_ID,
		    SECMODEL_SINGLEPRINCIPAL_NAME, NULL, NULL, NULL);
		if (error != 0)
			return error;

		secmodel_singleprincipal_init();
		secmodel_suser_stop();
		secmodel_securelevel_stop();
		secmodel_singleprincipal_start();
		printf("single-principal compatibility mode enabled\n");
		break;

	case MODULE_CMD_FINI:
		secmodel_singleprincipal_stop();
		error = secmodel_deregister(singleprincipal_sm);
		break;

	case MODULE_CMD_AUTOUNLOAD:
		error = EPERM;
		break;

	default:
		error = ENOTTY;
		break;
	}

	return error;
}

#define SP_FORWARD_CB(name, scope) \
static int \
name(kauth_cred_t cred, kauth_action_t action, void *cookie, void *arg0, \
    void *arg1, void *arg2, void *arg3) \
{ \
	return kauth_authorize_action(scope, cred, action, \
	    arg0, arg1, arg2, arg3); \
}

SP_FORWARD_CB(secmodel_singleprincipal_generic_cb, sp_iscope_generic)
SP_FORWARD_CB(secmodel_singleprincipal_system_cb, sp_iscope_system)
SP_FORWARD_CB(secmodel_singleprincipal_process_cb, sp_iscope_process)
SP_FORWARD_CB(secmodel_singleprincipal_network_cb, sp_iscope_network)
SP_FORWARD_CB(secmodel_singleprincipal_machdep_cb, sp_iscope_machdep)
SP_FORWARD_CB(secmodel_singleprincipal_device_cb, sp_iscope_device)

/*
 * Deliberately no suser vnode listener here.  A failed DAC/mode check stays
 * failed.  Securelevel's vnode listener is retained so its system-flag veto
 * remains active.
 */
static int
secmodel_singleprincipal_vnode_cb(kauth_cred_t cred, kauth_action_t action,
    void *cookie, void *arg0, void *arg1, void *arg2, void *arg3)
{
	return secmodel_securelevel_vnode_cb(cred, action, NULL,
	    arg0, arg1, arg2, arg3);
}
