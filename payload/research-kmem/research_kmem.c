// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-only
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

/* Exported by the target ARMv7 kernel. */
extern void v7_coherent_kern_range(unsigned long start, unsigned long end);

static bool enable;
static unsigned long test_addr;
static char test_buffer[16] = "KMEM-ORIGINAL";
module_param(enable, bool, 0400);
module_param(test_addr, ulong, 0444);
MODULE_PARM_DESC(enable, "Enable dangerous raw kernel-memory access");
MODULE_PARM_DESC(test_addr, "Writable module-buffer address for self-test");

static int research_kmem_open(struct inode *inode, struct file *file)
{
	if (!enable || !capable(CAP_SYS_RAWIO))
		return -EPERM;
	return 0;
}

static loff_t research_kmem_llseek(struct file *file, loff_t off, int whence)
{
	loff_t pos;

	switch (whence) {
	case SEEK_SET:
		pos = off;
		break;
	case SEEK_CUR:
		pos = file->f_pos + off;
		break;
	default:
		return -EINVAL;
	}
	if (pos < 0)
		return -EINVAL;
	file->f_pos = pos;
	return pos;
}

static ssize_t research_kmem_read(struct file *file, char __user *buf,
				  size_t len, loff_t *ppos)
{
	char *tmp;
	size_t done = 0;
	int ret = 0;

	if (!enable || !capable(CAP_SYS_RAWIO))
		return -EPERM;
	tmp = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;
	while (done < len) {
		size_t n = min_t(size_t, PAGE_SIZE, len - done);
		unsigned long addr = (unsigned long)(*ppos + done);

		ret = probe_kernel_read(tmp, (const void *)addr, n);
		if (ret)
			break;
		if (copy_to_user(buf + done, tmp, n)) {
			ret = -EFAULT;
			break;
		}
		done += n;
	}
	kfree(tmp);
	if (done) {
		*ppos += done;
		return done;
	}
	return ret;
}

static ssize_t research_kmem_write(struct file *file, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	char *tmp;
	size_t done = 0;
	int ret = 0;

	if (!enable || !capable(CAP_SYS_RAWIO))
		return -EPERM;
	tmp = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;
	while (done < len) {
		size_t n = min_t(size_t, PAGE_SIZE, len - done);
		unsigned long addr = (unsigned long)(*ppos + done);

		if (copy_from_user(tmp, buf + done, n)) {
			ret = -EFAULT;
			break;
		}
		ret = probe_kernel_write((void *)addr, tmp, n);
		if (ret)
			break;
		v7_coherent_kern_range(addr, addr + n);
		done += n;
	}
	kfree(tmp);
	if (done) {
		*ppos += done;
		return done;
	}
	return ret;
}

static const struct file_operations research_kmem_fops = {
	.owner = THIS_MODULE,
	.open = research_kmem_open,
	.llseek = research_kmem_llseek,
	.read = research_kmem_read,
	.write = research_kmem_write,
};

static struct miscdevice research_kmem_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "kmem",
	.mode = 0600,
	.fops = &research_kmem_fops,
};

static int __init research_kmem_init(void)
{
	if (!enable)
		return -EPERM;
	test_addr = (unsigned long)test_buffer;
	pr_info("research_kmem: self-test buffer at 0x%lx\n", test_addr);
	return misc_register(&research_kmem_dev);
}

static void __exit research_kmem_exit(void)
{
	misc_deregister(&research_kmem_dev);
}

module_init(research_kmem_init);
module_exit(research_kmem_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Opt-in research /dev/kmem for Samsung TV lab");
