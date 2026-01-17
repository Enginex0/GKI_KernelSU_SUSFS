#!/bin/bash
# NoMount xattr.c hook injection script
# Hooks __vfs_getxattr() to spoof SELinux context for injected files
#
# NOTE: In android12-5.10, vfs_getxattr() is a simple wrapper that calls
# __vfs_getxattr(). We need to hook __vfs_getxattr() instead.
#
# Kernel version compatibility: 5.10+

set -e

XATTR_FILE="$1"
if [ ! -f "$XATTR_FILE" ]; then
    echo "ERROR: File not found: $XATTR_FILE"
    exit 1
fi

# Check if already patched
if grep -q "nomount_get_spoofed_selinux_context" "$XATTR_FILE"; then
    echo "INFO: xattr.c already has NoMount hooks"
    exit 0
fi

echo "Injecting NoMount hooks into $XATTR_FILE..."

# Create backup
cp "$XATTR_FILE" "${XATTR_FILE}.backup"

# Add include at top (after security.h or existing includes)
if ! grep -q "linux/vfs_dcache.h" "$XATTR_FILE"; then
    if grep -q '#include <linux/security.h>' "$XATTR_FILE"; then
        sed -i '/#include <linux\/security.h>/a\
\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$XATTR_FILE"
    elif grep -q '#include <linux/xattr.h>' "$XATTR_FILE"; then
        sed -i '/#include <linux\/xattr.h>/a\
\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$XATTR_FILE"
    else
        # Fallback: add at the beginning of includes
        sed -i '1a\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif\
' "$XATTR_FILE"
    fi
    echo "  Added vfs_dcache.h include"
fi

# Use awk to inject hook into __vfs_getxattr
# We inject at the start of the function, before the actual xattr read
awk '
BEGIN {
    in_vfs_getxattr = 0
    added_hook = 0
    brace_count = 0
}

# Detect start of __vfs_getxattr function
# Match both "ssize_t\n__vfs_getxattr" and "__vfs_getxattr(" patterns
/__vfs_getxattr\(struct dentry \*dentry/ {
    in_vfs_getxattr = 1
    brace_count = 0
}

# Track opening braces to find function body start
in_vfs_getxattr && /{/ {
    brace_count++
    # Inject after first opening brace (function body start)
    if (brace_count == 1 && !added_hook) {
        print $0
        print ""
        print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
        print "\t/* Spoof SELinux context for NoMount injected files */"
        print "\tif (strcmp(name, XATTR_NAME_SELINUX) == 0 && inode) {"
        print "\t\tconst char *spoofed = nomount_get_spoofed_selinux_context(inode);"
        print "\t\tif (spoofed) {"
        print "\t\t\tsize_t ctx_len = strlen(spoofed) + 1;"
        print "\t\t\tif (size == 0)"
        print "\t\t\t\treturn ctx_len;"
        print "\t\t\tif (size < ctx_len)"
        print "\t\t\t\treturn -ERANGE;"
        print "\t\t\tif (value) {"
        print "\t\t\t\tmemcpy(value, spoofed, ctx_len);"
        print "\t\t\t\treturn ctx_len;"
        print "\t\t\t}"
        print "\t\t\treturn ctx_len;"
        print "\t\t}"
        print "\t}"
        print "#endif"
        added_hook = 1
        next
    }
}

# Track closing braces
in_vfs_getxattr && /}/ {
    brace_count--
    if (brace_count == 0) {
        in_vfs_getxattr = 0
    }
}

{ print }

END {
    if (added_hook) print "# __vfs_getxattr hook added" > "/dev/stderr"
}
' "$XATTR_FILE" > "${XATTR_FILE}.new"

mv "${XATTR_FILE}.new" "$XATTR_FILE"

# Verify injection succeeded
if grep -q "nomount_get_spoofed_selinux_context" "$XATTR_FILE"; then
    HOOK_COUNT=$(grep -c "nomount_get_spoofed_selinux_context" "$XATTR_FILE")
    echo "  SUCCESS: $HOOK_COUNT xattr hook(s) injected"
    rm -f "${XATTR_FILE}.backup"
else
    echo "  WARNING: xattr hooks may not have been injected correctly"
    echo "  Restoring backup..."
    mv "${XATTR_FILE}.backup" "$XATTR_FILE"
    exit 1
fi

echo "NoMount xattr.c injection complete"
