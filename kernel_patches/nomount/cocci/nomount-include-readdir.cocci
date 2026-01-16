// SPDX-License-Identifier: GPL-2.0
// Semantic patch to add vfs_dcache.h include to fs/readdir.c
// This matches the uaccess.h include and adds our header after it

@@
@@

#include <linux/uaccess.h>
+#ifdef CONFIG_FS_DCACHE_PREFETCH
+#include <linux/vfs_dcache.h>
+#endif
