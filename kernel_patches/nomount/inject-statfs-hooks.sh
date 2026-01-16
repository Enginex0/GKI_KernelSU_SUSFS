#!/bin/bash
# NoMount statfs.c hook injection script
# Uses function-name matching instead of line numbers for cross-version compatibility

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

# Add include at top (after compat.h)
if ! grep -q "linux/vfs_dcache.h" "$STATFS_FILE"; then
    sed -i '/#include <linux\/compat.h>/a\
\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$STATFS_FILE"
    echo "  Added vfs_dcache.h include"
fi

# Use awk to inject hooks into vfs_statfs_native
awk '
BEGIN {
    in_statfs_native = 0
    in_statfs64 = 0
    added_native_hook = 0
    added_native_label = 0
    added_64_hook = 0
    added_64_label = 0
}

# Detect start of vfs_statfs_native
/^static int vfs_statfs_native\(/ { in_statfs_native = 1 }

# Add hook after "int retval;" in vfs_statfs_native
in_statfs_native && /^[[:space:]]*int retval;/ && !added_native_hook {
    print $0
    print ""
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\t/* Spoof statfs for injected files */"
    print "\tif (dentry->d_inode && nomount_is_injected_file(dentry->d_inode)) {"
    print "\t\tif (nomount_spoof_statfs(dentry->d_inode, &st) == 0)"
    print "\t\t\tgoto copy_result;"
    print "\t}"
    print "#endif"
    added_native_hook = 1
    next
}

# Add copy_result label before else { in vfs_statfs_native
in_statfs_native && /memcpy\(buf, &st, sizeof\(st\)\);/ && !added_native_label {
    print $0
    getline nextline
    if (nextline ~ /else \{/) {
        print "copy_result:"
        print nextline
        added_native_label = 1
    } else {
        print nextline
    }
    next
}

# Detect end of vfs_statfs_native
in_statfs_native && /^static int vfs_statfs64\(/ {
    in_statfs_native = 0
    in_statfs64 = 1
}

# Add hook after "int retval;" in vfs_statfs64
in_statfs64 && /^[[:space:]]*int retval;/ && !added_64_hook {
    print $0
    print ""
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\t/* Spoof statfs64 for injected files */"
    print "\tif (dentry->d_inode && nomount_is_injected_file(dentry->d_inode)) {"
    print "\t\tif (nomount_spoof_statfs(dentry->d_inode, &st) == 0)"
    print "\t\t\tgoto copy_result64;"
    print "\t}"
    print "#endif"
    added_64_hook = 1
    next
}

# Add copy_result64 label before else { in vfs_statfs64
in_statfs64 && /memcpy\(buf, &st, sizeof\(st\)\);/ && !added_64_label {
    print $0
    getline nextline
    if (nextline ~ /else \{/) {
        print "copy_result64:"
        print nextline
        added_64_label = 1
    } else {
        print nextline
    }
    next
}

# Detect end of vfs_statfs64
in_statfs64 && /^static int vfs_ustatfs\(|^SYSCALL_DEFINE/ {
    in_statfs64 = 0
}

{ print }
' "$STATFS_FILE" > "${STATFS_FILE}.new"

mv "${STATFS_FILE}.new" "$STATFS_FILE"

# Verify injection succeeded
if grep -q "nomount_spoof_statfs" "$STATFS_FILE"; then
    echo "  SUCCESS: statfs hooks injected"
    rm -f "${STATFS_FILE}.backup"
else
    echo "  WARNING: statfs hooks may not have been injected correctly"
    mv "${STATFS_FILE}.backup" "$STATFS_FILE"
    exit 1
fi

echo "NoMount statfs.c injection complete"
