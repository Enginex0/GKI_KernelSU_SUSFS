#!/bin/bash
# NoMount fs/proc/task_mmu.c hook injection script
# Injects maps filtering into show_map_vma() to hide specific paths from /proc/PID/maps

set -e

TARGET="$1"
if [ ! -f "$TARGET" ]; then
    echo "ERROR: File not found: $TARGET"
    exit 1
fi

# Check if already patched
if grep -q "vfs_dcache_should_hide_map" "$TARGET"; then
    echo "INFO: task_mmu.c already has NoMount maps hooks"
    exit 0
fi

echo "Injecting NoMount maps filtering hooks into $TARGET..."

# Create backup
cp "$TARGET" "${TARGET}.backup"

# Add include after internal.h
if ! grep -q "linux/vfs_dcache.h" "$TARGET"; then
    sed -i '/#include "internal.h"/a\
#ifdef CONFIG_FS_DCACHE_PREFETCH\
#include <linux/vfs_dcache.h>\
#endif' "$TARGET"
    echo "  Added vfs_dcache.h include"
fi

# Use AWK to inject hook into show_map_vma inside the first "if (file) {" block
# The hook filters maps entries for hidden paths
awk '
BEGIN {
    in_func = 0
    brace_depth = 0
    injected = 0
    found_if_file = 0
}

# Detect show_map_vma function signature (static void on previous line or same line)
/^show_map_vma\(/ || /^static void[[:space:]]*$/ {
    if (/^static void[[:space:]]*$/) {
        # Function signature may be on next line, mark for check
        maybe_func = 1
    }
}

/^show_map_vma\(struct seq_file/ {
    in_func = 1
    found_if_file = 0
}

# Track brace depth when inside function
in_func == 1 && /\{/ {
    n = gsub(/\{/, "{")
    brace_depth += n
}

in_func == 1 && /\}/ {
    n = gsub(/\}/, "}")
    brace_depth -= n
    if (brace_depth <= 0) {
        in_func = 0
        brace_depth = 0
    }
}

# Find the first "if (file) {" inside show_map_vma and inject after it
in_func == 1 && /^[[:space:]]*if \(file\) \{/ && found_if_file == 0 && injected == 0 {
    found_if_file = 1
    print
    print "#ifdef CONFIG_FS_DCACHE_PREFETCH"
    print "\t\t{"
    print "\t\t\tchar *__nm_buf = (char *)__get_free_page(GFP_KERNEL);"
    print "\t\t\tif (__nm_buf) {"
    print "\t\t\t\tchar *__nm_path = file_path(file, __nm_buf, PAGE_SIZE);"
    print "\t\t\t\tif (!IS_ERR(__nm_path) && vfs_dcache_should_hide_map(__nm_path)) {"
    print "\t\t\t\t\tfree_page((unsigned long)__nm_buf);"
    print "\t\t\t\t\treturn;"
    print "\t\t\t\t}"
    print "\t\t\t\tfree_page((unsigned long)__nm_buf);"
    print "\t\t\t}"
    print "\t\t}"
    print "#endif"
    injected = 1
    next
}

{ print }

END {
    if (injected == 0) {
        print "WARNING: Hook not injected - if (file) not found in show_map_vma" > "/dev/stderr"
    }
}
' "$TARGET" > "${TARGET}.new"

mv "${TARGET}.new" "$TARGET"

# Verify injection succeeded
hook_count=$(grep -c 'vfs_dcache_should_hide_map' "$TARGET" || true)
if [ "$hook_count" -ge 1 ]; then
    echo "  SUCCESS: maps filtering hook injected"
    rm -f "${TARGET}.backup"
else
    echo "  ERROR: Hook injection failed"
    echo "  Restoring backup..."
    mv "${TARGET}.backup" "$TARGET"
    exit 1
fi

echo "Done: maps filtering hook injected into show_map_vma"
