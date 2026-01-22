# KernelSU Kernel Source Analysis Report

## Executive Summary

This report provides a deep technical analysis of KernelSU's kernel-level implementation, focusing on hook architecture, path handling, stat interception, and mount management. The analysis is intended to inform NoMount VFS adaptation.

---

## 1. Hook Architecture

### 1.1 All Hooks Registered by KernelSU

KernelSU uses **syscall tracepoints** as its primary hooking mechanism, NOT VFS-level hooks.

| Hook Function | Syscall | File | Purpose |
|---------------|---------|------|---------|
| `ksu_handle_stat` | `__NR_newfstatat` | `sucompat.c` | Redirect `/system/bin/su` stat to `/system/bin/sh` |
| `ksu_handle_faccessat` | `__NR_faccessat` | `sucompat.c` | Redirect `/system/bin/su` access check to `/system/bin/sh` |
| `ksu_handle_execve_sucompat` | `__NR_execve` | `sucompat.c` | Redirect `/system/bin/su` execution to `ksud` |
| `ksu_handle_setresuid` | `__NR_setresuid` | `setuid_hook.c` | Trigger umount and install KSU fd for allowed UIDs |
| `ksu_handle_init_mark_tracker` | `__NR_execve` (init only) | `syscall_hook_manager.c` | Track init's children for process marking |

### 1.2 How Hooks Are Registered

```c
// From syscall_hook_manager.c - using tracepoints, NOT kprobes for syscalls
ret = register_trace_sys_enter(ksu_sys_enter_handler, NULL);
```

The hook dispatcher (`ksu_sys_enter_handler`) is triggered on syscall entry:

```c
static void ksu_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
    if (unlikely(check_syscall_fastpath(id))) {
        if (ksu_su_compat_enabled) {
            if (id == __NR_newfstatat) {
                int *dfd = (int *)&PT_REGS_PARM1(regs);
                const char __user **filename_user =
                    (const char __user **)&PT_REGS_PARM2(regs);
                int *flags = (int *)&PT_REGS_SYSCALL_PARM4(regs);
                ksu_handle_stat(dfd, filename_user, flags);
                return;
            }
            // ... other syscalls
        }
    }
}
```

### 1.3 Hook Execution Order

**CRITICAL FINDING**: KSU hooks run at syscall entry via tracepoints, BEFORE the syscall reaches VFS.

Execution flow:
```
App calls stat("/system/bin/su")
    |
    v
sys_enter tracepoint fires
    |
    v
ksu_sys_enter_handler() called
    |
    v
ksu_handle_stat() modifies filename pointer
    |
    v
Kernel VFS receives modified path "/system/bin/sh"
    |
    v
VFS stat() executes on /system/bin/sh
```

---

## 2. Stat Hook Deep Dive

### 2.1 Complete Code Analysis

```c
// From kernel/sucompat.c - COMPLETE IMPLEMENTATION
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
    const char su[] = SU_PATH;  // "/system/bin/su"

    // Only process if UID is in allow list
    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        return 0;
    }

    if (unlikely(!filename_user)) {
        return 0;
    }

    // Read path from userspace (max 16 bytes = sizeof("/system/bin/su") + 1)
    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    // If path is exactly "/system/bin/su", redirect to /system/bin/sh
    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        pr_info("newfstatat su->sh!\n");
        *filename_user = sh_user_path();  // Returns pointer to "/system/bin/sh" on user stack
    }

    return 0;
}
```

### 2.2 What the Stat Hook Does

1. **Checks permission**: Only processes requests from UIDs in the KSU allow list
2. **Reads filename**: Copies up to 16 bytes from userspace
3. **Path comparison**: Compares against `/system/bin/su` (exact match only)
4. **Path replacement**: If matched, replaces the userspace filename pointer with a new string

### 2.3 What the Stat Hook Does NOT Do

- Does NOT intercept ALL stat calls - only for allowed UIDs
- Does NOT modify any other paths besides `/system/bin/su`
- Does NOT interact with overlayfs AT ALL
- Does NOT look at device/inode numbers
- Does NOT modify stat results - only modifies the input path BEFORE VFS

### 2.4 The v3.0.0 "Remove unreachable vfs_statx handling" Commit

**Commit**: `5007bea7`
**Date**: November 25, 2025
**Author**: Wang Han

**What was removed**:
```c
// REMOVED CODE - was unreachable
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0) && 0  // Note: && 0 made it dead code
    // it becomes a `struct filename *` after 5.18
    const char sh[] = SH_PATH;
    struct filename *filename = *((struct filename **)filename_user);
    if (IS_ERR(filename)) {
        return 0;
    }
    if (likely(memcmp(filename->name, su, sizeof(su))))
        return 0;
    pr_info("vfs_statx su->sh!\n");
    memcpy((void *)filename->name, sh, sizeof(sh));
#else
    // ... current implementation using strncpy_from_user_nofault
#endif
```

**Why it was unreachable**: The `&& 0` made this code ALWAYS compile out. It was dead code left over from an earlier attempt to handle kernel 5.18+ where `vfs_statx` uses `struct filename *` instead of raw userspace string. But since KSU now uses syscall tracepoints (which intercept BEFORE the kernel converts to `struct filename`), this path is never needed.

---

## 3. Path Resolution Flow

### 3.1 Step-by-Step Path Handling

When an app calls `stat("/system/etc/audio_effects.conf")`:

1. **Syscall entry**: `sys_newfstatat(AT_FDCWD, "/system/etc/audio_effects.conf", ...)`
2. **KSU tracepoint fires**: `ksu_sys_enter_handler()`
3. **Path check**: `ksu_handle_stat()` reads first 16 bytes
4. **Comparison fails**: Path != "/system/bin/su", so NO MODIFICATION
5. **VFS proceeds normally**: Kernel handles the syscall as usual
6. **Overlayfs resolves**: If `/system` has an overlay, overlayfs resolves the path

### 3.2 KSU Does NOT Modify Arbitrary Paths

**CRITICAL**: KSU's stat hook ONLY modifies paths that exactly match `/system/bin/su`.

For NoMount, this means:
- KSU won't interfere with your stat interception
- KSU won't modify paths like `/system/etc/audio_effects.conf`
- Your hooks can run either before or after KSU's hooks without conflict

### 3.3 Overlayfs Path Translation

KSU itself does NOT handle overlayfs. The `meta-overlayfs` metamodule (userspace) mounts overlays with `source=KSU`:

```rust
// From meta-overlayfs documentation
fsconfig_set_string(fs, "source", "KSU")?;  // REQUIRED!
```

This means:
- Overlays have mount source "KSU"
- `/system/etc/X` after overlay may be served from upper/lower directory
- Inode/device numbers change based on overlay implementation
- **NoMount should check mount source "KSU" to identify KSU overlays**

---

## 4. Mount Management

### 4.1 How Mounts Are Tracked

KSU maintains a kernel-side list of paths to unmount:

```c
// From kernel/kernel_umount.h
struct mount_entry {
    char *umountable;     // Path string like "/system"
    unsigned int flags;   // Unmount flags
    struct list_head list;
};
extern struct list_head mount_list;
extern struct rw_semaphore mount_list_lock;
```

### 4.2 When Umount Happens

Umount is triggered on `setresuid` syscall (when zygote forks an app):

```c
// From kernel/setuid_hook.c
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    uid_t new_uid = ruid;
    uid_t old_uid = current_uid().val;

    // ... permission checks ...

    // Handle kernel umount
    ksu_handle_umount(old_uid, new_uid);

    return 0;
}
```

### 4.3 Umount Decision Logic

```c
// From kernel/kernel_umount.c
int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
    // Skip if no modules mounted
    if (!ksu_module_mounted) return 0;

    // Skip if kernel umount feature disabled
    if (!ksu_kernel_umount_enabled) return 0;

    // Only process app UIDs and isolated processes
    if (!is_appuid(new_uid) && !is_isolated_process(new_uid)) return 0;

    // Check if this UID should have modules unmounted
    if (!ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid)) return 0;

    // Only process children of zygote (to avoid unmounting in wrong namespace)
    bool is_zygote_child = is_zygote(get_current_cred());
    if (!is_zygote_child) return 0;

    // Schedule task_work to unmount
    // ... adds task_work to unmount mount_list entries ...
}
```

### 4.4 Mount Source Identification

KSU identifies its mounts by the mount source string "KSU":
- `meta-overlayfs` sets `fsconfig_set_string(fs, "source", "KSU")`
- This appears in `/proc/mounts` as `KSU /system overlay ...`
- Other tools (like zygisksu) can identify KSU mounts by checking for `source=KSU`

---

## 5. Implications for NoMount

### 5.1 What Paths NoMount Should Expect

1. **For stat interception**: NoMount will receive the ORIGINAL path from userspace (or KSU-modified path for `/system/bin/su`)
2. **For faccessat**: Same as stat
3. **For getdents/readdir**: NoMount gets the path after any KSU modifications

### 5.2 Hook Execution Order (KSU vs NoMount)

If NoMount hooks via kprobes on VFS functions:
```
User syscall
    |
    v
KSU tracepoint (sys_enter) - modifies syscall args
    |
    v
Kernel syscall handler
    |
    v
NoMount kprobe (if hooking VFS) - sees modified args
    |
    v
VFS function executes
```

If NoMount hooks via syscall tracepoints:
```
User syscall
    |
    v
KSU tracepoint (sys_enter) - runs FIRST (registered earlier)
    |
    v
NoMount tracepoint (sys_enter) - runs SECOND (if using tracepoints)
    |
    v
Kernel syscall handler
```

**Recommendation**: Hook at VFS level (vfs_statx, vfs_fstatat) to run AFTER KSU's syscall modifications.

### 5.3 How to Avoid Conflicts

1. **Don't modify `/system/bin/su`** path handling - KSU owns this
2. **Use VFS hooks** rather than syscall tracepoints to run after KSU
3. **Check mount source "KSU"** to identify KSU overlay mounts
4. **Don't interfere with umount** - KSU handles its own cleanup

### 5.4 Detection Considerations

When an app calls `stat("/system/etc/audio_effects.conf")`:

| Stage | Path Seen | Notes |
|-------|-----------|-------|
| App syscall | `/system/etc/audio_effects.conf` | Original path |
| KSU tracepoint | No modification | Path != `/system/bin/su` |
| VFS receives | `/system/etc/audio_effects.conf` | Same path |
| Overlayfs resolves | May be from upper/lower | Depends on overlay |
| NoMount interception | Your hook point | You decide what to return |

---

## 6. Complete Hook Function Listing

### 6.1 Syscall Hooks (via tracepoint)

| Function | Source File | Lines | Description |
|----------|-------------|-------|-------------|
| `ksu_handle_stat` | `sucompat.c` | 93-116 | Redirect su stat to sh |
| `ksu_handle_faccessat` | `sucompat.c` | 72-91 | Redirect su access to sh |
| `ksu_handle_execve_sucompat` | `sucompat.c` | 118-166 | Redirect su exec to ksud |
| `ksu_handle_setresuid` | `setuid_hook.c` | 31-74 | UID change handling, trigger umount |
| `ksu_handle_init_mark_tracker` | `syscall_hook_manager.c` | 249-280 | Track init's exec for marking |

### 6.2 Kprobe Hooks

| Function | Symbol | Source File | Description |
|----------|--------|-------------|-------------|
| `sys_execve_handler_pre` | `__arm64_sys_execve` | `ksud.c` | Detect zygote/init exec |
| `sys_read_handler_pre` | `__arm64_sys_read` | `ksud.c` | Inject KSU RC into init.rc |
| `sys_fstat_handler_pre/post` | `__arm64_sys_newfstat` | `ksud.c` | Adjust init.rc size for injection |
| `input_handle_event_handler_pre` | `input_event` | `ksud.c` | Volume key safe mode detection |
| `reboot_handler_pre` | `__arm64_sys_reboot` | `supercalls.c` | KSU fd installation |

### 6.3 Kretprobe Hooks

| Function | Symbol | Description |
|----------|--------|-------------|
| `syscall_regfunc_handler` | `syscall_regfunc` | Track tracepoint registrations |
| `syscall_unregfunc_handler` | `syscall_unregfunc` | Track tracepoint unregistrations |

---

## 7. Answers to Critical Questions

### Q1: When an app calls `stat("/system/etc/audio_effects.conf")`, does KSU intercept this?

**Answer**: YES, KSU's tracepoint fires. But NO, KSU does NOT modify this path because it only checks for `/system/bin/su`. The path passes through unchanged.

### Q2: Does KSU modify the path before it reaches the filesystem?

**Answer**: ONLY for `/system/bin/su` -> `/system/bin/sh`. All other paths are untouched.

### Q3: What path does the actual VFS see?

**Answer**: For `/system/bin/su` from allowed UIDs: `/system/bin/sh`. For all other paths: the original userspace path unchanged.

### Q4: How does KSU's overlayfs affect path resolution?

**Answer**: KSU kernel does NOT handle overlayfs. The `meta-overlayfs` userspace module mounts overlays. After overlay mount, the kernel's overlayfs driver handles path resolution transparently. The overlay is identified by mount source "KSU".

### Q5: Is `/system/etc/X` different from `/etc/X` after overlay?

**Answer**: Depends on overlay configuration. `/etc` is often a symlink to `/system/etc`. With KSU overlay, both paths resolve through the same overlay filesystem.

### Q6: What inode/device does overlay return?

**Answer**: Overlayfs provides synthesized inode numbers. Device is overlay's anonymous device number. This is standard Linux overlayfs behavior, not KSU-specific.

### Q7: What is the hook execution order (KSU hooks vs NoMount hooks)?

**Answer**:
- If NoMount uses syscall tracepoints: KSU runs first (registered earlier)
- If NoMount uses kprobes on VFS: NoMount runs after KSU's syscall modifications
- **Recommended**: Use VFS-level hooks to have cleaner separation from KSU

### Q8: What was the v3.0.0 "Remove unreachable vfs_statx handling"?

**Answer**: Dead code removal. Old code had `#if ... && 0` making it never compile. It was an unused attempt to handle `vfs_statx` directly. Since KSU uses syscall tracepoints (pre-VFS), this path was never needed.

---

## Review Summary

- KSU primarily uses syscall tracepoints, not VFS hooks
- KSU only modifies `/system/bin/su` paths, nothing else
- Overlayfs is handled by userspace `meta-overlayfs`, not kernel
- Mount source "KSU" identifies KSU overlay mounts
- Umount triggered on `setresuid` for apps that should have modules hidden
- NoMount can safely hook at VFS level without conflicting with KSU

---

*Analysis completed: January 22, 2026*
*KernelSU source: https://github.com/tiann/KernelSU (commit 7d293d5e)*
