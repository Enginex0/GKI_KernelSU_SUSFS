#!/bin/bash
# NoMount fs/stat.c hook injection script
# Injects device ID spoofing into vfs_getattr_nosec()

set -e

TARGET="$1"
if [ ! -f "$TARGET" ]; then
    echo "ERROR: File not found: $TARGET"
    exit 1
fi

# Check if already patched
if grep -q "vfs_dcache_spoof_stat_dev" "$TARGET"; then
    echo "INFO: stat.c already has NoMount hooks"
    exit 0
fi

echo "Injecting NoMount stat dev spoofing hooks into $TARGET..."

# Create backup
cp "$TARGET" "${TARGET}.backup"

# Add include after mount.h
if ! grep -q "linux/vfs_dcache.h" "$TARGET"; then
    sed -i '/#include "mount.h"/a\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$TARGET"
    echo "  Added vfs_dcache.h include"
fi

# Use AWK to inject hook into vfs_getattr_nosec before return 0
# The hook spoofs device IDs for hidden mount paths
awk '
BEGIN {
    in_func = 0
    brace_depth = 0
    injected = 0
}

# Detect vfs_getattr_nosec function signature
/^int vfs_getattr_nosec\(/ {
    in_func = 1
}

# Track brace depth when inside function
in_func == 1 && /\{/ {
    brace_depth += gsub(/\{/, "{")
}

in_func == 1 && /\}/ {
    brace_depth -= gsub(/\}/, "}")
    if (brace_depth == 0) {
        in_func = 0
    }
}

# Inject before "return 0;" in vfs_getattr_nosec (the final return after generic_fillattr)
in_func == 1 && /^[[:space:]]*return 0;/ && injected == 0 {
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\t{"
    print "\t\tchar *__nm_buf = (char *)__get_free_page(GFP_KERNEL);"
    print "\t\tif (__nm_buf) {"
    print "\t\t\tchar *__nm_path = d_path(path, __nm_buf, PAGE_SIZE);"
    print "\t\t\tif (!IS_ERR(__nm_path))"
    print "\t\t\t\tvfs_dcache_spoof_stat_dev(__nm_path, stat);"
    print "\t\t\tfree_page((unsigned long)__nm_buf);"
    print "\t\t}"
    print "\t}"
    print "#endif"
    injected = 1
}

{ print }

END {
    if (injected == 0) {
        print "WARNING: Hook not injected - return 0 not found in vfs_getattr_nosec" > "/dev/stderr"
    }
}
' "$TARGET" > "${TARGET}.new"

mv "${TARGET}.new" "$TARGET"

# Verify injection succeeded
hook_count=$(grep -c 'vfs_dcache_spoof_stat_dev' "$TARGET" || true)
if [ "$hook_count" -ge 1 ]; then
    echo "  SUCCESS: stat dev spoof hook injected"
    rm -f "${TARGET}.backup"
else
    echo "  ERROR: Hook injection failed"
    echo "  Restoring backup..."
    mv "${TARGET}.backup" "$TARGET"
    exit 1
fi

echo "Done: stat dev spoof hook injected into vfs_getattr_nosec"
