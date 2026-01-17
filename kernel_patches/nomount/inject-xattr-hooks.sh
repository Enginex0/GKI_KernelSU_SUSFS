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
if grep -q "vfs_dcache_get_ctx" "$XATTR_FILE"; then
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
# We inject AFTER variable declarations (look for first if/return statement)
awk '
BEGIN {
    in_vfs_getxattr = 0
    added_hook = 0
    found_function = 0
}

# Detect start of __vfs_getxattr function
/__vfs_getxattr\(struct dentry \*dentry/ {
    in_vfs_getxattr = 1
    found_function = 0
}

# Look for the opening brace to confirm we are in the function body
in_vfs_getxattr && /{$/ {
    found_function = 1
}

# Inject before the first "if (" statement (after declarations)
in_vfs_getxattr && found_function && /^[[:space:]]*if \(/ && !added_hook {
    # Print our hook BEFORE the existing if statement
    print ""
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\t/* Spoof SELinux context for NoMount injected files */"
    print "\tif (name && strcmp(name, XATTR_NAME_SELINUX) == 0) {"
    print "\t\tconst char *spoofed_ctx = vfs_dcache_get_ctx(inode);"
    print "\t\tif (spoofed_ctx) {"
    print "\t\t\tsize_t ctx_len = strlen(spoofed_ctx);"
    print "\t\t\tif (size == 0)"
    print "\t\t\t\treturn ctx_len;"
    print "\t\t\tif (ctx_len > size)"
    print "\t\t\t\treturn -ERANGE;"
    print "\t\t\tmemcpy(value, spoofed_ctx, ctx_len);"
    print "\t\t\treturn ctx_len;"
    print "\t\t}"
    print "\t}"
    print "#endif"
    print ""
    added_hook = 1
    # Now print the original if statement
    print $0
    next
}

# Detect end of function (EXPORT_SYMBOL line)
in_vfs_getxattr && /^EXPORT_SYMBOL/ {
    in_vfs_getxattr = 0
    found_function = 0
}

{ print }

END {
    if (added_hook) print "# __vfs_getxattr hook added" > "/dev/stderr"
}
' "$XATTR_FILE" > "${XATTR_FILE}.new"

mv "${XATTR_FILE}.new" "$XATTR_FILE"

# Verify injection succeeded
if grep -q "vfs_dcache_get_ctx" "$XATTR_FILE"; then
    HOOK_COUNT=$(grep -c "vfs_dcache_get_ctx" "$XATTR_FILE")
    echo "  SUCCESS: $HOOK_COUNT xattr hook(s) injected"
    rm -f "${XATTR_FILE}.backup"
else
    echo "  WARNING: xattr hooks may not have been injected correctly"
    echo "  Restoring backup..."
    mv "${XATTR_FILE}.backup" "$XATTR_FILE"
    exit 1
fi

echo "NoMount xattr.c injection complete"
