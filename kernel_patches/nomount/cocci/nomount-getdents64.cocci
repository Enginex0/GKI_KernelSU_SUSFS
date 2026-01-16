// SPDX-License-Identifier: GPL-2.0
// Semantic patch to add NoMount hooks to SYSCALL_DEFINE3(getdents64, ...)
// Matches the function structure and injects hooks at correct positions

// Rule 1: Add initial_count declaration after error declaration
@@
identifier fd, dirent, count;
@@

SYSCALL_DEFINE3(getdents64, unsigned int, fd, struct linux_dirent64 __user *, dirent, unsigned int, count)
{
    ...
    int error;
+#ifdef CONFIG_FS_DCACHE_PREFETCH
+   int initial_count = count;
+#endif
    ...
}

// Rule 2: Add injection after iterate_dir and error check
@@
identifier fd, dirent, count;
expression E;
@@

SYSCALL_DEFINE3(getdents64, unsigned int, fd, struct linux_dirent64 __user *, dirent, unsigned int, count)
{
    ...
    error = iterate_dir(...);
    if (error >= 0)
        error = E;
+#ifdef CONFIG_FS_DCACHE_PREFETCH
+   if (error >= 0 && !signal_pending(current)) {
+       nomount_inject_dents64(f.file, (void __user **)&dirent, &count, &f.file->f_pos);
+       error = initial_count - count;
+   }
+#endif
    ...
}
