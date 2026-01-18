#!/bin/bash
# NoMount proc_namespace.c hook injection script
# Injects mount ID-based filtering into show_vfsmnt, show_mountinfo, show_vfsstat

set -e

TARGET="$1"
if [ ! -f "$TARGET" ]; then
    echo "ERROR: File not found: $TARGET"
    exit 1
fi

# Check if already patched
if grep -q "vfs_dcache_is_mount_hidden" "$TARGET"; then
    echo "INFO: proc_namespace.c already has NoMount hooks"
    exit 0
fi

echo "Injecting NoMount mount hiding hooks into $TARGET..."

# Create backup
cp "$TARGET" "${TARGET}.backup"

# Add include after the last local include (internal.h)
if ! grep -q "linux/vfs_dcache.h" "$TARGET"; then
    sed -i '/#include "internal.h"/a\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$TARGET"
    echo "  Added vfs_dcache.h include"
fi

# Use AWK to inject hooks into all three functions
# Must inject AFTER all variable declarations to be C90 compliant
# The functions have: struct proc_mounts *p, struct mount *r, ..., int err;
# We inject AFTER "int err;" which is the last declaration
awk '
BEGIN {
    in_target_func = 0
    injected_count = 0
    looking_for_err = 0
}

# Detect entering target functions
/^static int show_vfsmnt\(struct seq_file/ ||
/^static int show_mountinfo\(struct seq_file/ ||
/^static int show_vfsstat\(struct seq_file/ {
    in_target_func = 1
    looking_for_err = 1
}

# Find "int err;" line - this is the last declaration before code
in_target_func == 1 && looking_for_err == 1 && /^[[:space:]]*int err;/ {
    print $0
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\t{"
    print "\t\tstruct mount *__nm_r = real_mount(mnt);"
    print "\t\tif (vfs_dcache_is_mount_hidden(__nm_r->mnt_id))"
    print "\t\t\treturn 0;"
    print "\t}"
    print "#endif"
    looking_for_err = 0
    injected_count++
    next
}

# Reset when we exit a function (closing brace at column 0)
in_target_func == 1 && /^}$/ {
    in_target_func = 0
}

{ print }

END {
    if (injected_count < 3) {
        print "WARNING: Only injected " injected_count " hooks (expected 3)" > "/dev/stderr"
    }
}
' "$TARGET" > "${TARGET}.new"

mv "${TARGET}.new" "$TARGET"

# Verify injection succeeded
hook_count=$(grep -c 'vfs_dcache_is_mount_hidden' "$TARGET" || true)
if [ "$hook_count" -ge 3 ]; then
    echo "  SUCCESS: $hook_count hooks injected"
    rm -f "${TARGET}.backup"
else
    echo "  ERROR: Expected 3 hooks, found $hook_count"
    echo "  Restoring backup..."
    mv "${TARGET}.backup" "$TARGET"
    exit 1
fi

echo "Done: $hook_count hooks injected"
