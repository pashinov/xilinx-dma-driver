/*  dma-drv.c - The simplest kernel module.
 */

 #include <linux/fs.h>
 #include <linux/err.h>
 #include <linux/time.h>
 #include <linux/init.h>
 #include <linux/delay.h>
 #include <linux/module.h>
 #include <linux/string.h>
 #include <linux/kdev_t.h>
 #include <linux/version.h>
 #include <linux/proc_fs.h>
 #include <linux/moduleparam.h>

 #include <asm/io.h>
 #include <linux/io.h>
 #include <linux/of.h>
 #include <linux/irq.h>
 #include <linux/cdev.h>
 #include <linux/ioctl.h>
 #include <linux/of_irq.h>
 #include <linux/uaccess.h>
 #include <linux/of_platform.h>
 #include <linux/of_address.h>
 #include <linux/device.h>
 #include <linux/of_device.h>
 #include <linux/dma-mapping.h>

 #include <linux/sched.h>
 #include <linux/kernel.h> 		//printk()
 #include <linux/slab.h>		//kmalloc()
 #include <linux/errno.h>		//error codes
 #include <linux/types.h>  		//size_t
 #include <linux/interrupt.h> 	//mark_bh
 #include <linux/kthread.h>
 #include <linux/jiffies.h>
 #include <linux/seq_file.h>
 #include <linux/semaphore.h>
 #include <linux/spinlock.h>

#define DRIVER_NAME "xlnx-dma-driver"
#define PROCFS_NAME "xlnx-dma-driver-procfs"

#define DMA_MAX_LEN     1024

#define DMA_CR          0x0000
#define DMA_SR          0x0004
#define DMA_SA          0x0008
#define DMA_DA          0x000C
#define DMA_SL          0x0010
#define DMA_DL          0x0014

#define REG_1           0x0018
#define REG_2           0x001C

#define START_DMA       1

#define IOC_MAGIC       1
#define IOC_MAXNR       3
#define IOC_SET         _IOW(IOC_MAGIC, 0, int)
#define IOC_GET         _IOR(IOC_MAGIC, 1, int)

static int major_number = 0;
static int minor_number = 0;

static int param_ioctl = 0;

static struct class *device_class;

struct chrdrv_private {

	void __iomem *io_base;

	int irq_rx;
	int irq_tx;

	char *src_addr;
	char *dst_addr;
	dma_addr_t src_handle;
	dma_addr_t dst_handle;

	wait_queue_head_t wq_rx;
	wait_queue_head_t wq_tx;

	spinlock_t lock;

	int flag_wait_rx;
	int flag_wait_tx;

	int device_open;

	struct device *device;
	struct kobject *mykobj;
	struct resource resource;
	struct proc_dir_entry *our_proc_file;

	struct cdev cdev;
};

static struct chrdrv_attr {
	struct attribute attr;
	int value;

	struct chrdrv_private *priv;
};

static struct chrdrv_attr chrdrv_reg2 = {
	.attr.name = "reg2",
	.attr.mode = 0644,
	.value = 0,
	.priv = NULL,
};

static struct attribute * chrdrv_attr[] = {
	&chrdrv_reg2.attr,

	NULL
};

static void chrdrv_set_attr_priv(struct chrdrv_private *priv)
{
	chrdrv_reg2.priv = priv;
}

static __inline void chrdrv_write_reg(struct chrdrv_private *priv, const unsigned int reg_addr, const unsigned int reg_value) {
	iowrite32(reg_value, (void __iomem *)(priv->io_base + reg_addr));
}

static __inline unsigned int chrdrv_read_reg(struct chrdrv_private *priv, const unsigned int reg_addr) {
	return ioread32((void __iomem *)(priv->io_base + reg_addr));
}

static int get_config(struct chrdrv_attr *a)
{
	if (!strcmp(a->attr.name, "reg2")) {
		a->value = chrdrv_read_reg(a->priv, REG_2);
	}

	return 0;
}

static ssize_t sysfs_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	unsigned long flags;
	struct chrdrv_attr *a = container_of(attr, struct chrdrv_attr, attr);

	spin_lock_irqsave(&a->priv->lock, flags);

	get_config(a);

	spin_unlock_irqrestore(&a->priv->lock, flags);

	return scnprintf(buf, PAGE_SIZE, "%d\n", a->value);
}

static int set_config(const struct chrdrv_attr *a)
{
	if (!strcmp(a->attr.name, "reg2")) {
		chrdrv_write_reg(a->priv, REG_2, a->value);
	}

	return 0;
}

static ssize_t sysfs_store(struct kobject *kobj, struct attribute *attr, const char *buf, size_t len)
{
	unsigned long flags;
	struct chrdrv_attr *a = container_of(attr, struct chrdrv_attr, attr);

	spin_lock_irqsave(&a->priv->lock, flags);

	sscanf(buf, "%d", &a->value);

	set_config(a);

	spin_unlock_irqrestore(&a->priv->lock, flags);

	return len;
}

static irqreturn_t chrdrv_irq_rx_handler(int irq, void *dev_id, struct pt_regs *regs) {
	struct chrdrv_private *priv = (struct chrdrv_private *)dev_id;

	priv->flag_wait_rx = 1;

	wake_up_interruptible(&priv->wq_rx);

	return IRQ_HANDLED;
}

static irqreturn_t chrdrv_irq_tx_handler(int irq, void *dev_id, struct pt_regs *regs) {
	struct chrdrv_private *priv = (struct chrdrv_private *)dev_id;

	priv->flag_wait_tx = 1;

	wake_up_interruptible(&priv->wq_tx);

	return IRQ_HANDLED;
}

static int chrdrv_open(struct inode *pinode, struct file *filp) {
	struct chrdrv_private *priv;

	priv = container_of(pinode->i_cdev, struct chrdrv_private, cdev);
	filp->private_data = priv;

	if (priv->device_open) {
		return -EBUSY;
	}
	priv->device_open++;

	request_irq(priv->irq_rx, (void *)chrdrv_irq_rx_handler, IRQF_SHARED, DRIVER_NAME, priv);
	request_irq(priv->irq_tx, (void *)chrdrv_irq_tx_handler, IRQF_SHARED, DRIVER_NAME, priv);

	return 0;
}

static ssize_t chrdrv_read(struct file *filp, char __user * buf, size_t len, loff_t * off) {
	struct chrdrv_private *priv = (struct chrdrv_private *)filp->private_data;

	int ret;
	int	datalen;

	ret = 0;

	if (len > DMA_MAX_LEN) {
		return -1;
	}

	ret = wait_event_interruptible_timeout(priv->wq_rx, priv->flag_wait_rx != 0, msecs_to_jiffies(1000));
	if (ret == 0) {
		return 0;
	}

	datalen = chrdrv_read_reg(priv, DMA_DL);

	copy_to_user(buf, priv->dst_addr, datalen);

	priv->flag_wait_rx = 0;

	return datalen;
}

static ssize_t chrdrv_write(struct file *filp, const char __user * buf, size_t len, loff_t * off) {
	struct chrdrv_private *priv = (struct chrdrv_private *)filp->private_data;

	int ret;

	copy_from_user(priv->src_addr, buf, len);

	chrdrv_write_reg(priv, DMA_SL, len);
	chrdrv_write_reg(priv, DMA_CR, START_DMA);

	ret = 0;

	ret = wait_event_interruptible_timeout(priv->wq_tx, priv->flag_wait_tx != 0, msecs_to_jiffies(1000));
	if (ret == 0) {
		return 0;
	}

	priv->flag_wait_tx = 0;

	return len;
}

static int chrdrv_close(struct inode *pinode, struct file *filp) {
	struct chrdrv_private *priv = (struct chrdrv_private *)filp->private_data;

	free_irq(priv->irq_rx, priv);
	free_irq(priv->irq_tx, priv);

	priv->device_open--;

	return 0;
}

static long chrdrv_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	struct chrdrv_private *priv = (struct chrdrv_private *)filp->private_data;

	if (_IOC_TYPE(cmd) != IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > IOC_MAXNR) return -ENOTTY;

	switch(cmd) {

		case IOC_SET:
			copy_from_user(&param_ioctl, (void*)arg, sizeof(param_ioctl));
			chrdrv_write_reg(priv, REG_1, param_ioctl);
			break;

		case IOC_GET:
			param_ioctl = chrdrv_read_reg(priv, REG_2);
			copy_to_user((void*)arg, &param_ioctl, sizeof(param_ioctl));
			break;

		default :
			return -ENOTTY;
	}

	return 0;
}

static int chrdrv_proc_show(struct seq_file *m, void *v) {
	char buffer[80];
	sprintf(buffer, "%s - %d\n", "major number", major_number);
	seq_printf(m, buffer);
	return 0;
}

static int chrdrv_proc_open(struct inode *inode, struct  file *file) {
	return single_open(file, chrdrv_proc_show, NULL);
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = chrdrv_open,
	.write = chrdrv_write,
	.read = chrdrv_read,
	.release = chrdrv_close,
	.unlocked_ioctl = chrdrv_ioctl,
};

static struct sysfs_ops chrdrv_ops = {
	.show = sysfs_show,
	.store = sysfs_store,
};

static struct kobj_type chrdrv_type = {
	.sysfs_ops = &chrdrv_ops,
	.default_attrs = chrdrv_attr,
};

static const struct file_operations proc_fops = {
	.owner = THIS_MODULE,
	.open = chrdrv_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static char *mydevnode(struct device *dev, umode_t *mode) {
	if(mode) {
		*mode = 0644;
	}
	return 0;
}

static int probe(struct platform_device *pdev) {
	int res = 0;
	dev_t devno = 0;

	struct chrdrv_private *priv = (struct chrdrv_private*)kmalloc(sizeof(struct chrdrv_private), GFP_KERNEL);
	if (!priv) {
		return -1;
	}
	memset(priv, 0, sizeof(struct chrdrv_private));

	priv->our_proc_file = proc_create(PROCFS_NAME, 0664, NULL, &proc_fops);
	if (priv->our_proc_file == NULL) {
		remove_proc_entry(PROCFS_NAME, NULL);
		return -ENOMEM;
	}

	res = alloc_chrdev_region(&devno, minor_number, 1, DRIVER_NAME);
	if (res) {
		goto out_alloc;
	}
	major_number = MAJOR(devno);

	device_class = class_create(THIS_MODULE, DRIVER_NAME);
	if (IS_ERR(device_class)) {
		goto out_chrdev;
	}
	device_class->devnode=mydevnode;

	cdev_init(&priv->cdev, &fops);
	priv->cdev.owner = THIS_MODULE;
	priv->cdev.ops = &fops;
	res = cdev_add(&priv->cdev, devno, 1);
	if (res < 0) {
		goto out_chrdev;
	}

	priv->mykobj = kzalloc(sizeof(*priv->mykobj), GFP_KERNEL);
	if (priv->mykobj) {
		kobject_init(priv->mykobj, &chrdrv_type);
		if (kobject_add(priv->mykobj, NULL, "%s", "dma-drv")) {
			printk(KERN_ALERT "Sysfs creation failed\n");
			kobject_put(priv->mykobj);
			priv->mykobj = NULL;
			goto out_chrdev;
		}
	}

	chrdrv_set_attr_priv(priv);

	res = of_address_to_resource(pdev->dev.of_node, 0, &priv->resource);
	if (res) {
		goto out_chrdev;
	}

	if (!request_mem_region(priv->resource.start, resource_size(&priv->resource), DRIVER_NAME)) {
		goto out_chrdev;
	}

	priv->io_base = of_iomap(pdev->dev.of_node, 0);
	if (!priv->io_base) {
		goto out_iomap;
	}

	priv->irq_rx = irq_of_parse_and_map(pdev->dev.of_node, 0);
	priv->irq_tx = irq_of_parse_and_map(pdev->dev.of_node, 1);

	priv->device = device_create(device_class, NULL, MKDEV(major_number, minor_number), NULL, DRIVER_NAME);
	if (IS_ERR(priv->device)) {
		goto out_class;
	}

	priv->device_open = 0;
	priv->flag_wait_rx = 0;
	priv->flag_wait_tx = 0;

	init_waitqueue_head(&priv->wq_rx);
	init_waitqueue_head(&priv->wq_tx);

	spin_lock_init(&priv->lock);

	/*Initialize parameters of private structure*/
	priv->src_addr = dma_zalloc_coherent(NULL, DMA_MAX_LEN, &priv->src_handle, GFP_KERNEL);
	if (!priv->src_addr) {
		return -ENOMEM;
	}

	/*Initialize parameters of private structure*/
	priv->dst_addr = dma_zalloc_coherent(NULL, DMA_MAX_LEN, &priv->dst_handle, GFP_KERNEL);
	if (!priv->dst_addr) {
		return -ENOMEM;
	}

	chrdrv_write_reg(priv, DMA_SA, priv->src_handle);
	chrdrv_write_reg(priv, DMA_DA, priv->dst_handle);

	dev_set_drvdata(&pdev->dev, priv);

	printk(KERN_INFO "%s: interface registered\n", DRIVER_NAME);
	return 0;

out_class:
	cdev_del(&priv->cdev);
	class_destroy(device_class);

out_iomap:
	release_mem_region(priv->resource.start, resource_size(&priv->resource));

out_chrdev:
	unregister_chrdev_region(devno, 1);

out_alloc:
	kfree(priv);

	return res;
}

static int remove(struct platform_device *pdev) {
	dev_t devno = 0;
	struct chrdrv_private *priv = dev_get_drvdata(&pdev->dev);

	devno = MKDEV(major_number, minor_number);

	if (priv->mykobj) {
		kobject_put(priv->mykobj);
		kfree(priv->mykobj);
	}

	dma_free_coherent(NULL, DMA_MAX_LEN, priv->src_addr, priv->src_handle);
	dma_free_coherent(NULL, DMA_MAX_LEN, priv->dst_addr, priv->dst_handle);

	iounmap(priv->io_base);
	unregister_chrdev_region(devno, 1);
	release_mem_region(priv->resource.start, resource_size(&priv->resource));
	cdev_del(&priv->cdev);
	device_destroy(device_class, devno);
	class_destroy(device_class);
	remove_proc_entry(PROCFS_NAME, NULL);

	kfree(priv);
	dev_set_drvdata(&pdev->dev, NULL);

	printk(KERN_INFO "%s: interface unregistered\n", DRIVER_NAME);

	return 0;
}

static struct of_device_id chrdrv_of_match[] = {
	{ .compatible = "xlnx,dma-drv", },
	{ .compatible = "xlnx-dma-drv", },
	{ },
};
MODULE_DEVICE_TABLE(of, chrdrv_of_match);

static struct platform_driver chrdrv_driver = {
	.probe = probe,
	.remove = remove,
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = of_match_ptr(chrdrv_of_match),
	},
};

static int __init chrdrv_init(void) {
	return platform_driver_register(&chrdrv_driver);
}

static void __exit chrdrv_exit(void) {
	return platform_driver_unregister(&chrdrv_driver);
}

module_init(chrdrv_init);
module_exit(chrdrv_exit);

MODULE_DESCRIPTION("Xilinx linux dma driver sample");
MODULE_AUTHOR("Alexey Pashinov <pashinov@outlook.com>");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
