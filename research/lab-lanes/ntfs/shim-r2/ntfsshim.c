// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-only
/*
 * lanes/ntfs (round 2): symbol shim so the UNMODIFIED szdrv_core.ko can be
 * insmod'ed and *run* on the shared lab kernel.
 *
 * szdrv_core.ko has 27 undefined symbols. 25 are stock kernel exports and are
 * already present. Exactly two are missing, and BOTH are missing because of a
 * documented lab/target divergence, not because of anything wrong with the
 * module:
 *
 *   1. __sdp_dma_virt_to_phys
 *      arch/arm/mach-sdp/include/mach/memory.h:30 does
 *          #define __virt_to_phys(x)  __sdp_dma_virt_to_phys(x)
 *      i.e. on the TARGET this IS virt_to_phys(); it is the SDP SoC's override,
 *      needed there because the SoC has several discontiguous DRAM channels
 *      (CONFIG_SPARSE_LOWMEM_EXT_LPAE=y in Muse.M-Tizen_release_defconfig).
 *      The lab kernel is vexpress with one contiguous lowmem region, so the
 *      generic linear mapping is the correct semantic equivalent here.
 *      Both kernels have CONFIG_PHYS_ADDR_T_64BIT=y + CONFIG_ARM_LPAE=y, so the
 *      r0:r1 return pair the module expects is produced natively.
 *
 *   2. mem_section
 *      Exported only when CONFIG_SPARSEMEM=y. The target defconfig has
 *      CONFIG_SPARSEMEM=y + CONFIG_SPARSEMEM_EXTREME=y; the shared lab kernel
 *      fell back to CONFIG_FLATMEM=y when the machine was switched to vexpress.
 *
 * ROUND 1 SHIPPED A *ZEROED* mem_section DUMMY. That is why round 1 saw a NULL
 * deref at szdrv_core+0x8068 while mounting a perfectly valid mkntfs volume:
 * +0x8068 is count_free_clusters+0x1e8, i.e. the sparsemem pfn_to_page() inline
 *
 *      8044  lsr r3, r1, #21          ; root   = pfn >> 21
 *      804c  ldr r3, [r0, r3, lsl #2] ; mem_section[root]        -> NULL
 *      805c  ubfxne r2, r2, #0, #9    ; index  = (pfn >> 12) & 0x1ff
 *      8060  addne r3, r3, r2, lsl #3 ; sizeof(struct mem_section) == 8
 *      8068  ldr r3, [r3]             ; section->section_mem_map  <- FAULT
 *      8070  bic r3, r3, #3           ; & SECTION_MAP_MASK
 *      8074  add r0, r3, r1, lsl #5   ; page = base + pfn * 32
 *
 * That crash was therefore a LAB ARTEFACT, not a szdrv defect. This version
 * emulates sparsemem properly so the mount path can complete.
 *
 * The emulation is exact for this kernel, not approximate:
 *   - the module hardcodes sizeof(struct page) == 32 (lsl #5); the lab kernel's
 *     sizeof(struct page) is also 32 (verified with gdb on vmlinux), so the
 *     linear formula base + pfn*32 reproduces FLATMEM's
 *     mem_map + (pfn - ARCH_PFN_OFFSET) exactly for every pfn;
 *   - base is taken straight from the lab kernel's own pfn_to_page(0), so no
 *     PHYS_OFFSET constant is duplicated here;
 *   - the lab has 1 GiB at 0x80000000, so pfn <= 0xbffff and pfn >> 21 == 0:
 *     only root 0 is ever consulted. Other roots stay NULL so that an
 *     unexpected pfn faults loudly instead of returning silent garbage.
 *
 * WHERE THE TWO SYMBOLS ARE USED (checked, not assumed). All six relocations
 * against them live in exactly two functions:
 *      0x7fbc,0x7fc8,0x8034 -> count_free_clusters
 *      0x865c,0x8668,0x889c -> count_free_clusters_async
 * i.e. free-space accounting over $Bitmap. NONE of them is in parse_mft_entry,
 * check_attrs, parse_attrs, proc_data_attr or proc_nres_attr -- the attribute
 * parsing code actually under test is untouched by this shim.
 *
 * FIDELITY CAVEAT (must be carried into any finding):
 * count_free_clusters IS called from load_metadata_files (+0x300), which is on
 * the mount path. So this shim is on the mount path even though it is not in
 * the parser. Any *crash inside count_free_clusters* in this lab must be
 * treated as harness-dependent and NOT reported as a target bug. Crashes in the
 * MFT/attribute parse path are unaffected by this shim and remain valid.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mmzone.h>

phys_addr_t __sdp_dma_virt_to_phys(unsigned long x);
phys_addr_t __sdp_dma_virt_to_phys(unsigned long x)
{
	return (phys_addr_t)virt_to_phys((void *)x);
}
EXPORT_SYMBOL(__sdp_dma_virt_to_phys);

#ifndef CONFIG_SPARSEMEM
/* Layout the module was compiled against (CONFIG_SPARSEMEM_EXTREME, 8-byte
 * struct mem_section, SECTION_SIZE_BITS 24 => PFN_SECTION_SHIFT 12,
 * SECTIONS_PER_ROOT = PAGE_SIZE / 8 = 512). */
#define SHIM_SECTIONS_PER_ROOT	512
#define SHIM_NR_ROOTS		16
#define SHIM_SECTION_PRESENT	1UL	/* SECTION_MARKED_PRESENT */
#define SHIM_SECTION_HAS_MAP	2UL	/* SECTION_HAS_MEM_MAP    */

struct shim_mem_section {
	unsigned long section_mem_map;
	unsigned long *pageblock_flags;
};

static struct shim_mem_section shim_root0[SHIM_SECTIONS_PER_ROOT];
static unsigned long shim_pageblock_flags[16];

struct shim_mem_section *mem_section[SHIM_NR_ROOTS];
EXPORT_SYMBOL(mem_section);

static void shim_init_sparsemem(void)
{
	unsigned long base = (unsigned long)pfn_to_page(0);
	int i;

	for (i = 0; i < SHIM_SECTIONS_PER_ROOT; i++) {
		shim_root0[i].section_mem_map =
			base | SHIM_SECTION_PRESENT | SHIM_SECTION_HAS_MAP;
		shim_root0[i].pageblock_flags = shim_pageblock_flags;
	}
	mem_section[0] = shim_root0;
	pr_err("ntfsshim: sparsemem emulation: pfn_to_page(0)=%p mem_map=%p\n",
	       (void *)base, mem_map);
}
#else
static void shim_init_sparsemem(void) { }
#endif

static int __init shim_init(void)
{
	shim_init_sparsemem();
	return 0;
}
module_init(shim_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("lanes/ntfs: SDP/sparsemem symbol shim for szdrv_core.ko");
