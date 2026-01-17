#!/bin/bash
# NoMount statfs.c hook injection script (FIXED)
# Hooks user_statfs() and fd_statfs() - the actual VFS entry points
# NOT do_statfs_native/do_statfs64 which are just format converters
#
# Kernel version compatibility: 5.10+

set -e

STATFS_FILE="$1"
if [ ! -f "$STATFS_FILE" ]; then
    echo "ERROR: File not found: $STATFS_FILE"
    exit 1
fi

# Check if already patched
if grep -q "nomount_spoof_statfs" "$STATFS_FILE"; then
    echo "INFO: statfs.c already has NoMount hooks"
    exit 0
fi

echo "Injecting NoMount hooks into $STATFS_FILE..."

# Create backup
cp "$STATFS_FILE" "${STATFS_FILE}.backup"

# Add include at top (after compat.h or internal.h)
if ! grep -q "linux/vfs_dcache.h" "$STATFS_FILE"; then
    # Try after compat.h first, fallback to internal.h
    if grep -q '#include <linux/compat.h>' "$STATFS_FILE"; then
        sed -i '/#include <linux\/compat.h>/a\
\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$STATFS_FILE"
    elif grep -q '#include "internal.h"' "$STATFS_FILE"; then
        sed -i '/#include "internal.h"/a\
\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$STATFS_FILE"
    else
        # Fallback: add after first #include block
        sed -i '0,/^#include/s//\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux\/vfs_dcache.h>\
#endif\
\
&/' "$STATFS_FILE"
    fi
    echo "  Added vfs_dcache.h include"
fi

# Use awk to inject hooks into user_statfs() and fd_statfs()
# These are the correct hook points - they have access to path/dentry
awk '
BEGIN {
    in_user_statfs = 0
    in_fd_statfs = 0
    added_user_hook = 0
    added_fd_hook = 0
}

# Detect start of user_statfs function
/^int user_statfs\(/ { in_user_statfs = 1 }

# In user_statfs: inject after "error = vfs_statfs(&path, st);" line
# We need to inject BEFORE path_put(&path) so we still have the dentry
in_user_statfs && /error = vfs_statfs\(&path, st\);/ && !added_user_hook {
    print $0
    print ""
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\t\t/* Spoof statfs for NoMount hidden paths */"
    print "\t\tif (!error && path.dentry && path.dentry->d_inode) {"
    print "\t\t\tnomount_spoof_statfs(path.dentry->d_inode, st);"
    print "\t\t}"
    print "#endif"
    added_user_hook = 1
    next
}

# Detect end of user_statfs
in_user_statfs && /^int fd_statfs\(|^static |^SYSCALL_DEFINE/ {
    in_user_statfs = 0
}

# Detect start of fd_statfs function
/^int fd_statfs\(/ { in_fd_statfs = 1 }

# In fd_statfs: inject after "error = vfs_statfs(&f.file->f_path, st);" line
# We need to inject BEFORE fdput(f) so we still have the file reference
in_fd_statfs && /error = vfs_statfs\(&f\.file->f_path, st\);/ && !added_fd_hook {
    print $0
    print ""
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\t\t/* Spoof statfs for NoMount hidden paths */"
    print "\t\tif (!error && f.file->f_path.dentry && f.file->f_path.dentry->d_inode) {"
    print "\t\t\tnomount_spoof_statfs(f.file->f_path.dentry->d_inode, st);"
    print "\t\t}"
    print "#endif"
    added_fd_hook = 1
    next
}

# Detect end of fd_statfs (next function)
in_fd_statfs && /^static |^SYSCALL_DEFINE|^int / && !/fd_statfs/ {
    in_fd_statfs = 0
}

{ print }

END {
    if (added_user_hook) print "# user_statfs hook added" > "/dev/stderr"
    if (added_fd_hook) print "# fd_statfs hook added" > "/dev/stderr"
}
' "$STATFS_FILE" > "${STATFS_FILE}.new"

mv "${STATFS_FILE}.new" "$STATFS_FILE"

# Verify injection succeeded
if grep -q "nomount_spoof_statfs" "$STATFS_FILE"; then
    # Count hooks
    HOOK_COUNT=$(grep -c "nomount_spoof_statfs" "$STATFS_FILE")
    echo "  SUCCESS: $HOOK_COUNT statfs hook(s) injected"
    rm -f "${STATFS_FILE}.backup"
else
    echo "  WARNING: statfs hooks may not have been injected correctly"
    echo "  Restoring backup..."
    mv "${STATFS_FILE}.backup" "$STATFS_FILE"
    exit 1
fi

echo "NoMount statfs.c injection complete"
