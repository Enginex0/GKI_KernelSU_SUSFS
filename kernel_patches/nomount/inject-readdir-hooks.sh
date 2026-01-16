#!/bin/bash
# NoMount readdir.c hook injection script
# Uses function-name matching instead of line numbers for cross-version compatibility

set -e

READDIR_FILE="$1"
if [ ! -f "$READDIR_FILE" ]; then
    echo "ERROR: File not found: $READDIR_FILE"
    exit 1
fi

# Check if already patched
if grep -q "nomount_inject_dents64" "$READDIR_FILE"; then
    echo "INFO: readdir.c already has NoMount hooks"
    exit 0
fi

echo "Injecting NoMount hooks into $READDIR_FILE..."

# Create backup
cp "$READDIR_FILE" "${READDIR_FILE}.backup"

# Add include at top (after uaccess.h)
if ! grep -q "linux/vfs_dcache.h" "$READDIR_FILE"; then
    sed -i '/#include <linux\/uaccess.h>/a\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$READDIR_FILE"
    echo "  Added vfs_dcache.h include"
fi

# Use awk to inject hooks into SYSCALL_DEFINE3(getdents64, ...)
# This finds the function by name, not line number
awk '
BEGIN { in_getdents64 = 0; added_decl = 0; added_hook = 0 }

# Detect start of getdents64 syscall
/SYSCALL_DEFINE3\(getdents64,/ { in_getdents64 = 1 }

# Add initial_count after "int error;" within getdents64
in_getdents64 && /^[[:space:]]*int error;/ && !added_decl {
    print $0
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\tint initial_count = count;"
    print "#endif"
    added_decl = 1
    next
}

# Add injection hook after "error = buf.error;" within getdents64
in_getdents64 && /error = buf\.error;/ && !added_hook {
    print $0
    print ""
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\tif (error >= 0 && !signal_pending(current)) {"
    print "\t\tnomount_inject_dents64(f.file, (void __user **)&dirent, &count, &f.file->f_pos);"
    print "\t\terror = initial_count - count;"
    print "\t}"
    print "#endif"
    added_hook = 1
    next
}

# Detect end of getdents64 (next SYSCALL_DEFINE or end of file pattern)
in_getdents64 && /^SYSCALL_DEFINE|^COMPAT_SYSCALL_DEFINE|^static |^int / && !/getdents64/ {
    in_getdents64 = 0
    added_decl = 0
    added_hook = 0
}

{ print }
' "$READDIR_FILE" > "${READDIR_FILE}.new"

mv "${READDIR_FILE}.new" "$READDIR_FILE"

# Verify injection succeeded
if grep -q "nomount_inject_dents64" "$READDIR_FILE"; then
    echo "  SUCCESS: getdents64 hooks injected"
    rm -f "${READDIR_FILE}.backup"
else
    echo "  WARNING: getdents64 hooks may not have been injected correctly"
    # Restore backup
    mv "${READDIR_FILE}.backup" "$READDIR_FILE"
    exit 1
fi

echo "NoMount readdir.c injection complete"
