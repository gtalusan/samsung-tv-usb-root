// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-only
// lane-ext4 shim: supply the two symbols jbd2.ko needs that do not exist in a
// vexpress build of the vendor tree.
//
// WHY THIS IS NEEDED
// ------------------
// jbd2.ko (as shipped on the TV) has two undefined symbols that ext4.ko itself
// does NOT have:
//
//   __sdp_dma_virt_to_phys   arch/arm/mach-sdp/include/mach/memory.h:30 does
//                            #define __virt_to_phys(x) __sdp_dma_virt_to_phys(x)
//                            i.e. Samsung REPLACES the core virt->phys macro on
//                            their SoC, so every module that inlines
//                            virt_to_phys() ends up calling their function.
//                            11 of the 148 shipped modules reference it.
//                            Selecting ARCH_VEXPRESS for QEMU drops mach-sdp,
//                            hence the symbol disappears.
//
//   mem_section              CONFIG_SPARSEMEM=y in Muse.M-Tizen_release_defconfig
//                            (SPARSEMEM_EXTREME too), but the lab kernel lands
//                            on FLATMEM because ARCH_SPARSEMEM_DEFAULT is an
//                            SDP/mach property. page_to_pfn()/pfn_to_page()
//                            inline the mem_section[] lookup under SPARSEMEM.
//
// SEMANTICS
// ---------
// __sdp_dma_virt_to_phys: on SDP this consults memblock.phys_table[] for the
// lowmem-ext mapping and, when that table is not yet initialised, falls back to
// __sdp_virt_to_phys() i.e. the plain linear translation. On vexpress there is
// no discontiguous lowmem remap, so the plain linear translation is the correct
// and complete equivalent. We therefore forward to the kernel's own
// virt_to_phys().
//
// mem_section: exported so the SPARSEMEM page_to_pfn() inlined into jbd2 links.
// It is deliberately a single all-zero section array. jbd2's use of
// virt_to_page()/page_to_pfn() on the journal path is what pulled this in; the
// ext4 metadata-parsing paths this lane tests do not walk it. If a test ever
// faults inside a page_to_pfn() expansion, treat the result as HARNESS-INDUCED
// and discard it -- see the findings file.
//
// SCOPE: lane-local. Does not touch the kernel build, scripts/07, scripts/08,
// fw/modules, or any other lane. Loaded before jbd2 via the MODS list.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <asm/memory.h>

phys_addr_t __sdp_dma_virt_to_phys(unsigned long x);
phys_addr_t __sdp_dma_virt_to_phys(unsigned long x)
{
	/* vexpress has a single linear lowmem mapping: plain translation. */
	return (phys_addr_t)(x - PAGE_OFFSET) + PHYS_OFFSET;
}
EXPORT_SYMBOL(__sdp_dma_virt_to_phys);

/*
 * SPARSEMEM's mem_section[]. The lab kernel is FLATMEM so the real array does
 * not exist; jbd2 only needs the symbol to resolve. Zeroed on purpose: any
 * actual dereference would fault loudly rather than return plausible garbage,
 * which is what we want from a harness stub.
 */
#ifndef CONFIG_SPARSEMEM
struct mem_section;
struct mem_section *mem_section[1];
EXPORT_SYMBOL(mem_section);
#endif

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lane-ext4 harness shim: SDP virt_to_phys + mem_section stubs");
