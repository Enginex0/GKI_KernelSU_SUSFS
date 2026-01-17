#!/bin/bash
# NoMount namei.c hook injection script
# Hooks vfs_readlink() to sanitize symlink targets for injected files
#
# This transforms paths like:
#   /data/adb/modules/MODULE/system/... -> /system/...
#   /debug_ramdisk/... -> /...
#
# Kernel version compatibility: 5.10+

set -e

NAMEI_FILE="$1"
if [ ! -f "$NAMEI_FILE" ]; then
    echo "ERROR: File not found: $NAMEI_FILE"
    exit 1
fi

# Check if vfs_readlink is already patched (specific to this hook)
# Note: Other nomount hooks may exist in namei.c from base patch
if grep -q "nomount_is_injected_file(inode)" "$NAMEI_FILE" && \
   grep -A5 "int vfs_readlink" "$NAMEI_FILE" | grep -q "nomount_is_injected_file"; then
    echo "INFO: namei.c vfs_readlink already has NoMount hooks"
    exit 0
fi

echo "Injecting NoMount hooks into $NAMEI_FILE..."

# Create backup
cp "$NAMEI_FILE" "${NAMEI_FILE}.backup"

# Add include at top (after a suitable existing include)
if ! grep -q "linux/vfs_dcache.h" "$NAMEI_FILE"; then
    if grep -q '#include <linux/namei.h>' "$NAMEI_FILE"; then
        sed -i '/#include <linux\/namei.h>/a\
\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$NAMEI_FILE"
    elif grep -q '#include "internal.h"' "$NAMEI_FILE"; then
        sed -i '/#include "internal.h"/a\
\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$NAMEI_FILE"
    else
        # Find first #include and add after it
        sed -i '0,/#include/s//#include\
\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux\/vfs_dcache.h>\
#endif\
\
#include/' "$NAMEI_FILE"
    fi
    echo "  Added vfs_dcache.h include"
fi

# Use awk to inject hook into vfs_readlink
# We inject at the start of the function, after variable declarations
awk '
BEGIN {
    in_vfs_readlink = 0
    added_hook = 0
    found_res_decl = 0
}

# Detect start of vfs_readlink function
/^int vfs_readlink\(struct dentry \*dentry/ {
    in_vfs_readlink = 1
    found_res_decl = 0
}

# Find "int res;" declaration and inject after it
in_vfs_readlink && /int res;/ && !added_hook {
    print $0
    found_res_decl = 1
    next
}

# Inject after blank line following declarations (start of function body)
in_vfs_readlink && found_res_decl && /^$/ && !added_hook {
    print $0
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\t/*"
    print "\t * For injected files that are symlinks, sanitize the symlink target"
    print "\t * to hide revealing paths. Transform module paths to virtual paths:"
    print "\t * /data/adb/modules/MODULE/system/... -> /system/..."
    print "\t */"
    print "\tif (nomount_is_injected_file(inode)) {"
    print "\t\tDEFINE_DELAYED_CALL(nm_done);"
    print "\t\tconst char *nm_link;"
    print "\t\tbool need_cleanup = false;"
    print ""
    print "\t\t/* Get the symlink target first to check it */"
    print "\t\tnm_link = READ_ONCE(inode->i_link);"
    print "\t\tif (!nm_link && inode->i_op && inode->i_op->get_link) {"
    print "\t\t\tnm_link = inode->i_op->get_link(dentry, inode, &nm_done);"
    print "\t\t\tif (IS_ERR(nm_link)) {"
    print "\t\t\t\treturn PTR_ERR(nm_link);"
    print "\t\t\t}"
    print "\t\t\tneed_cleanup = true;"
    print "\t\t}"
    print ""
    print "\t\t/* Sanitize symlink targets containing module paths */"
    print "\t\tif (nm_link) {"
    print "\t\t\tconst char *sanitized = NULL;"
    print "\t\t\tconst char *mod_prefix = strnstr(nm_link, \"/data/adb/modules/\", PATH_MAX);"
    print "\t\t\tconst char *debug_prefix = strnstr(nm_link, \"/debug_ramdisk/\", PATH_MAX);"
    print ""
    print "\t\t\tif (mod_prefix) {"
    print "\t\t\t\t/* Skip /data/adb/modules/MODULE_NAME to get /partition/... */"
    print "\t\t\t\tconst char *after_modules = mod_prefix + 18; /* strlen(\"/data/adb/modules/\") */"
    print "\t\t\t\tsanitized = strchr(after_modules, '/');"
    print "\t\t\t} else if (debug_prefix) {"
    print "\t\t\t\t/* Skip /debug_ramdisk to get /partition/... */"
    print "\t\t\t\tsanitized = debug_prefix + 14; /* strlen(\"/debug_ramdisk\") */"
    print "\t\t\t}"
    print ""
    print "\t\t\tif (sanitized) {"
    print "\t\t\t\tres = readlink_copy(buffer, buflen, sanitized);"
    print "\t\t\t\tif (need_cleanup)"
    print "\t\t\t\t\tdo_delayed_call(&nm_done);"
    print "\t\t\t\treturn res;"
    print "\t\t\t}"
    print ""
    print "\t\t\tif (need_cleanup)"
    print "\t\t\t\tdo_delayed_call(&nm_done);"
    print "\t\t}"
    print "\t}"
    print "#endif"
    added_hook = 1
    next
}

# Detect end of vfs_readlink (EXPORT_SYMBOL line)
in_vfs_readlink && /^EXPORT_SYMBOL\(vfs_readlink\)/ {
    in_vfs_readlink = 0
}

{ print }

END {
    if (added_hook) print "# vfs_readlink hook added" > "/dev/stderr"
}
' "$NAMEI_FILE" > "${NAMEI_FILE}.new"

mv "${NAMEI_FILE}.new" "$NAMEI_FILE"

# Verify injection succeeded
if grep -q "nomount_is_injected_file" "$NAMEI_FILE"; then
    HOOK_COUNT=$(grep -c "nomount_is_injected_file" "$NAMEI_FILE")
    echo "  SUCCESS: $HOOK_COUNT namei hook(s) injected"
    rm -f "${NAMEI_FILE}.backup"
else
    echo "  WARNING: namei hooks may not have been injected correctly"
    echo "  Restoring backup..."
    mv "${NAMEI_FILE}.backup" "$NAMEI_FILE"
    exit 1
fi

echo "NoMount namei.c injection complete"
