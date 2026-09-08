// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-only
// Export the two ARM string-op aliases that the Samsung vendor kernel provides
// and vanilla 4.1.10 does not.
//
// exfat_core.ko / exfat_fs.ko reference __memcpy and __memset. Upstream ARM
// only exports memcpy/memset (the __-prefixed forms appear upstream later,
// introduced alongside KASAN). Samsung's tree exports them, so the vendor
// modules link against them.
//
// These are plain forwarders, semantically identical to what the vendor
// symbols do. This affects only symbol resolution, not parser behaviour: the
// code under test is untouched vendor binary.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>

void *__memcpy(void *dest, const void *src, size_t n);
void *__memcpy(void *dest, const void *src, size_t n)
{
	return memcpy(dest, src, n);
}
EXPORT_SYMBOL(__memcpy);

void *__memset(void *s, int c, size_t n);
void *__memset(void *s, int c, size_t n)
{
	return memset(s, c, n);
}
EXPORT_SYMBOL(__memset);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lab shim: vendor-kernel string-op symbol aliases");
