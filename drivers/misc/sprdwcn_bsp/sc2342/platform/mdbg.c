/*
* Copyright (C) 2015 Spreadtrum Communications Inc.
*
* File:		mdbg.c
* Description:	Marlin Debug System main file. Module,device &
* driver related defination.
*
* This software is licensed under the terms of the GNU General Public
* License version 2, as published by the Free Software Foundation, and
* may be copied, distributed, and modified under those terms.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the	1
* GNU General Public License for more details.
*/

#include <linux/of.h>
#include <linux/mutex.h>
#include <linux/marlin_platform.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/sdiom_rx_api.h>
#include <linux/sdiom_tx_api.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include "mdbg.h"
#include "mdbg_sdio.h"

#define MDBG_MAX_BUFFER_LEN (64*1024)

#define MDBG_WRITE_SIZE			(64)
#define MDBG_ASSERT_SIZE		(1024)
#define MDBG_LOOPCHECK_SIZE		(128)
#define MDBG_AT_CMD_SIZE		(128)

static bool power_state_changed;
static unsigned long long rx_count;
static unsigned long long rx_count_last;

struct mdbg_device_t *mdbg_dev;
wait_queue_head_t	mdbg_wait;

struct mdbg_proc_entry {
	char *name;
	struct proc_dir_entry *entry;
	struct completion completed;
	wait_queue_head_t	rxwait;
	unsigned int	rcv_len;
	void *buf;
};

struct mdbg_proc_t {
	char *dir_name;
	struct proc_dir_entry		*procdir;
	struct mdbg_proc_entry		assert;
	struct mdbg_proc_entry		loopcheck;
	struct mdbg_proc_entry		at_cmd;
	char write_buf[MDBG_WRITE_SIZE];
	int fail_count;
	bool first_boot;
};

static struct mdbg_proc_t *mdbg_proc;


void mdbg_assert_interface(char *str)
{
	int len = MDBG_ASSERT_SIZE;

	if (strlen(str) <= MDBG_ASSERT_SIZE)
		len = strlen(str);

	strncpy(mdbg_proc->assert.buf, str, len);
	pr_info("mdbg_assert_interface:%s\n",
		(char *)(mdbg_proc->assert.buf));

	sdiom_set_carddump_status(true);
	marlin_hold_cpu();
	mdbg_clear_log();
	mdbg_proc->assert.rcv_len = 23;
	mdbg_proc->fail_count++;
	complete(&mdbg_proc->assert.completed);
	wake_up_interruptible(&mdbg_proc->assert.rxwait);
}
EXPORT_SYMBOL_GPL(mdbg_assert_interface);

unsigned int mdbg_assert_read(void *addr, unsigned int len,
				unsigned int fifo_id)
{
	if (len > MDBG_ASSERT_SIZE) {
		MDBG_ERR("assert data len:%d,beyond max read:%d",
			len, MDBG_ASSERT_SIZE);
		sdiom_pt_read_release(fifo_id);
		return -1;
	}
	memcpy(mdbg_proc->assert.buf, addr, len);
	pr_info("mdbg_assert_read:%s\n",
		(char *)(mdbg_proc->assert.buf));
	mdbg_proc->assert.rcv_len = len;
	mdbg_proc->fail_count++;
	complete(&mdbg_proc->assert.completed);
	wake_up_interruptible(&mdbg_proc->assert.rxwait);
	sdiom_pt_read_release(fifo_id);

	return 0;
}
EXPORT_SYMBOL_GPL(mdbg_assert_read);

unsigned int mdbg_loopcheck_read(void *addr, unsigned int len,
			unsigned int fifo_id)
{
	if (len > MDBG_LOOPCHECK_SIZE) {
		MDBG_ERR("The loopcheck data len:%d, beyond max read:%d",
				len, MDBG_LOOPCHECK_SIZE);
		sdiom_pt_read_release(fifo_id);

		return -1;
	}
	memcpy(mdbg_proc->loopcheck.buf, addr, len);
	pr_info("mdbg_loopcheck_read:%s\n",
		(char *)(mdbg_proc->loopcheck.buf));
	mdbg_proc->loopcheck.rcv_len = len;
	mdbg_proc->fail_count = 0;
	complete(&mdbg_proc->loopcheck.completed);
	sdiom_pt_read_release(fifo_id);

	return 0;
}
EXPORT_SYMBOL_GPL(mdbg_loopcheck_read);

unsigned int mdbg_at_cmd_read(void *addr, unsigned int len,
			unsigned int fifo_id)
{
	if (len > MDBG_AT_CMD_SIZE) {
		MDBG_ERR("The at cmd data len:%d,max read:%d",
				len, MDBG_AT_CMD_SIZE);
		sdiom_pt_read_release(fifo_id);
		return -1;
	}
	memcpy(mdbg_proc->at_cmd.buf, addr, len);
	mdbg_proc->at_cmd.rcv_len = len;
	pr_info("mdbg_at_cmd_read:%s\n",
		(char *)(mdbg_proc->at_cmd.buf));
	complete(&mdbg_proc->at_cmd.completed);
	sdiom_pt_read_release(fifo_id);

	return 0;
}
EXPORT_SYMBOL_GPL(mdbg_at_cmd_read);

bool mdbg_rx_count_change(void)
{
	rx_count = sdiom_get_rx_total_cnt();

	pr_info("rx_count:0x%llx rx_count_last:0x%llx\n",
		rx_count, rx_count_last);

	if ((rx_count == 0) && (rx_count_last == 0)) {
		return true;
	} else if (rx_count != rx_count_last) {
		rx_count_last = rx_count;
		return true;
	} else {
		return false;
	}
}

static int mdbg_proc_open(struct inode *inode, struct file *filp)
{
	struct mdbg_proc_entry *entry =
		(struct mdbg_proc_entry *)PDE_DATA(inode);
	filp->private_data = entry;

	return 0;
}

static int mdbg_proc_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static ssize_t mdbg_proc_read(struct file *filp,
		char __user *buf, size_t count, loff_t *ppos)
{
	struct mdbg_proc_entry *entry =
		(struct mdbg_proc_entry *)filp->private_data;
	char *type = entry->name;
	int timeout = -1;
	int len = 0;
	int ret;

	if (filp->f_flags & O_NONBLOCK)
		timeout = 0;

	if (strcmp(type, "assert") == 0) {
		if (timeout < 0) {
			while (1) {
				ret = wait_for_completion_timeout(
						&mdbg_proc->assert.completed,
						msecs_to_jiffies(1000));
				if (ret != -ERESTARTSYS)
					break;
			}
		}

		if (copy_to_user((void __user *)buf,
				mdbg_proc->assert.buf,
				min(count, (size_t)MDBG_ASSERT_SIZE)))
			MDBG_ERR("Read assert info error\n");
		len = mdbg_proc->assert.rcv_len;
		mdbg_proc->assert.rcv_len = 0;
		memset(mdbg_proc->assert.buf, 0, MDBG_ASSERT_SIZE);
	}

	if (strcmp(type, "loopcheck") == 0) {
		if (timeout < 0) {
			while (1) {
				ret = wait_for_completion_timeout(
						&mdbg_proc->loopcheck.completed,
						msecs_to_jiffies(1000));
				if (ret != -ERESTARTSYS)
					break;
			}
		}

		if ((marlin_get_download_status() == true) &&
			(marlin_get_module_status() == 1)) {
			if (!mdbg_proc->first_boot) {
				if (copy_to_user((void __user *)buf,
					"loopcheck_ack", 13))
					MDBG_ERR("loopcheck first error\n");
				mdbg_proc->first_boot = true;
				len = 13;
			} else if (mdbg_rx_count_change()) {
				pr_info("mdbg rx count change\n");
				if (copy_to_user((void __user *)buf,
							"loopcheck_ack", 13))
					MDBG_ERR("loopcheck gpio info error\n");
				len = 13;
			} else {
				if (copy_to_user((void __user *)buf,
					mdbg_proc->loopcheck.buf, min(count,
						(size_t)MDBG_LOOPCHECK_SIZE)))
					MDBG_ERR("loopcheck sdio info error\n");
				len = mdbg_proc->loopcheck.rcv_len;
				if (strncmp(mdbg_proc->write_buf,
					"loopcheck_ack", 13) != 0)
					mdbg_proc->fail_count++;
				pr_info("loopcheck status:%d\n",
					mdbg_proc->fail_count);
			}
		} else {
			if (copy_to_user((void __user *)buf, "poweroff", 8))
				pr_err("Read loopcheck poweroff error\n");
			len = 8;
			pr_info("mdbg loopcheck poweroff\n");
		}
		memset(mdbg_proc->loopcheck.buf, 0, MDBG_LOOPCHECK_SIZE);
		mdbg_proc->loopcheck.rcv_len = 0;
	}

	if (strcmp(type, "at_cmd") == 0) {
		if (timeout < 0) {
			while (1) {
				ret = wait_for_completion_timeout(
						&mdbg_proc->at_cmd.completed,
						msecs_to_jiffies(1000));
				if (ret != -ERESTARTSYS)
					break;
			}
		}

		if (copy_to_user((void __user *)buf,
					mdbg_proc->at_cmd.buf,
					min(count, (size_t)MDBG_AT_CMD_SIZE)))
			MDBG_ERR("Read at cmd ack info error\n");

		len = mdbg_proc->at_cmd.rcv_len;
		mdbg_proc->at_cmd.rcv_len = 0;
		memset(mdbg_proc->at_cmd.buf, 0, MDBG_AT_CMD_SIZE);
	}

	return len;
}

static ssize_t mdbg_proc_write(struct file *filp,
		const char __user *buf, size_t count, loff_t *ppos)
{

	if (count > MDBG_WRITE_SIZE) {
		MDBG_ERR("mdbg_proc_write count > MDBG_WRITE_SIZE\n");
		return -ENOMEM;
	}
	memset(mdbg_proc->write_buf, 0, MDBG_WRITE_SIZE);

	if (copy_from_user(mdbg_proc->write_buf, buf, count))
		return -EFAULT;

	pr_info("mdbg_proc->write_buf:%s\n", mdbg_proc->write_buf);

	if (strncmp(mdbg_proc->write_buf, "startwcn", 8) == 0) {
		if (start_marlin(MARLIN_MDBG)) {
			pr_err("%s power on failed\n", __func__);
			return -EIO;
		}
		return count;
	}

	if (strncmp(mdbg_proc->write_buf, "stopwcn", 7) == 0) {
		if (stop_marlin(MARLIN_MDBG)) {
			pr_err("%s power off failed\n", __func__);
			return -EIO;
		}
		return count;
	}

	if (strncmp(mdbg_proc->write_buf, "dumpmem", 7) == 0) {
		sdiom_set_carddump_status(true);

		marlin_set_sleep(MARLIN_MDBG, FALSE);
		marlin_set_wakeup(MARLIN_MDBG);
		mdbg_dump_mem();
		marlin_set_sleep(MARLIN_MDBG, TRUE);

		return count;
	}

	if (strncmp(mdbg_proc->write_buf, "poweroff_wcn", 12) == 0) {
		marlin_power_off(MARLIN_ALL);
		return count;
	}

	if (strncmp(mdbg_proc->write_buf, "rebootmarlin", 12) == 0) {
		flag_reset = 1;
		pr_info("marlin need reset\n");
		pr_info("fail_count is value %d\n", mdbg_proc->fail_count);
		pr_info("fail_reset is value %d\n", flag_reset);
		mdbg_proc->fail_count = 0;
		if (marlin_reset_func != NULL)
			marlin_reset_func(marlin_callback_para);
		return count;
	}
	if (strncmp(mdbg_proc->write_buf, "rebootwcn", 9) == 0) {
		flag_reset = 1;
		pr_info("marlin gnss need reset\n");
		pr_info("fail_count is value %d\n", mdbg_proc->fail_count);
		mdbg_proc->fail_count = 0;
		marlin_chip_en(false, true);
		if (marlin_reset_func != NULL)
			marlin_reset_func(marlin_callback_para);
		return count;
	}
	if (strncmp(mdbg_proc->write_buf, "at+getchipversion", 17) == 0) {
		struct device_node *np_marlin2 = NULL;

		pr_info("marlin get chip version\n");
		np_marlin2 = of_find_node_by_name(NULL, "sprd-marlin2");
		if (np_marlin2) {
			if (of_get_property(np_marlin2,
				"common_chip_en", NULL)) {
				pr_info("marlin common_chip_en\n");
				memcpy(mdbg_proc->at_cmd.buf,
					"2342B", strlen("2342B"));
				mdbg_proc->at_cmd.rcv_len = strlen("2342B");
			}
		}
		return count;
	}
	mdbg_send(mdbg_proc->write_buf, count, MDBG_SUBTYPE_AT);

	return count;
}

static unsigned int mdbg_proc_poll(struct file *filp, poll_table *wait)
{
	struct mdbg_proc_entry *entry =
		(struct mdbg_proc_entry *)filp->private_data;
	char *type = entry->name;
	unsigned int mask = 0;

	if (strcmp(type, "assert") == 0) {
		poll_wait(filp, &mdbg_proc->assert.rxwait, wait);
		if (mdbg_proc->assert.rcv_len > 0)
			mask |= POLLIN | POLLRDNORM;
	}

	if (strcmp(type, "loopcheck") == 0) {
		poll_wait(filp, &mdbg_proc->loopcheck.rxwait, wait);
		pr_info("loopcheck:power_state_changed:%d\n",
			power_state_changed);
		if ((power_state_changed) ||
			marlin_get_module_status_changed()) {
			power_state_changed = false;
			wcn_module_state_change = 0;
			mask |= POLLIN | POLLRDNORM;
		}
	}

	return mask;
}

const struct file_operations mdbg_proc_fops = {
	.open		= mdbg_proc_open,
	.release	= mdbg_proc_release,
	.read		= mdbg_proc_read,
	.write		= mdbg_proc_write,
	.poll		= mdbg_proc_poll,
};

static int mdbg_memory_alloc(void)
{
	mdbg_proc->assert.buf =  kzalloc(MDBG_ASSERT_SIZE, GFP_KERNEL);
	if (!mdbg_proc->assert.buf)
		return -1;

	mdbg_proc->loopcheck.buf =  kzalloc(MDBG_LOOPCHECK_SIZE, GFP_KERNEL);
	if (!mdbg_proc->loopcheck.buf) {
		kfree(mdbg_proc->assert.buf);
		return -1;
	}
	mdbg_proc->at_cmd.buf =  kzalloc(MDBG_AT_CMD_SIZE, GFP_KERNEL);
	if (!mdbg_proc->at_cmd.buf) {
		kfree(mdbg_proc->assert.buf);
		kfree(mdbg_proc->loopcheck.buf);

		return -1;
	}

	return 0;
}

static void mdbg_fs_channel_init(void)
{
	mdbg_pt_common_reg(MDBG_SUBTYPE_ASSERT, mdbg_assert_read);
	mdbg_pt_common_reg(MDBG_SUBTYPE_LOOPCHECK, mdbg_loopcheck_read);
	mdbg_pt_common_reg(MDBG_SUBTYPE_AT, mdbg_at_cmd_read);
}

static  void mdbg_memory_free(void)
{
	kfree(mdbg_proc->assert.buf);
	mdbg_proc->assert.buf = NULL;

	kfree(mdbg_proc->loopcheck.buf);
	mdbg_proc->loopcheck.buf = NULL;

	kfree(mdbg_proc->at_cmd.buf);
	mdbg_proc->at_cmd.buf = NULL;
}

static int mdbg_fs_init(void)
{
	mdbg_proc = kzalloc(sizeof(struct mdbg_proc_t), GFP_KERNEL);
	if (!mdbg_proc)
		return -1;

	mdbg_proc->dir_name = "mdbg";
	mdbg_proc->procdir = proc_mkdir(mdbg_proc->dir_name, NULL);

	mdbg_proc->assert.name = "assert";
	mdbg_proc->assert.entry = proc_create_data(mdbg_proc->assert.name,
						S_IRUSR | S_IWUSR,
						mdbg_proc->procdir,
						&mdbg_proc_fops,
						&(mdbg_proc->assert));

	mdbg_proc->loopcheck.name = "loopcheck";
	mdbg_proc->loopcheck.entry = proc_create_data(mdbg_proc->loopcheck.name,
						S_IRUSR | S_IWUSR,
						mdbg_proc->procdir,
						&mdbg_proc_fops,
						&(mdbg_proc->loopcheck));

	mdbg_proc->at_cmd.name = "at_cmd";
	mdbg_proc->at_cmd.entry = proc_create_data(mdbg_proc->at_cmd.name,
						S_IRUSR | S_IWUSR,
						mdbg_proc->procdir,
						&mdbg_proc_fops,
						&(mdbg_proc->at_cmd));

	mdbg_fs_channel_init();

	init_completion(&mdbg_proc->assert.completed);
	init_completion(&mdbg_proc->loopcheck.completed);
	init_completion(&mdbg_proc->at_cmd.completed);
	init_waitqueue_head(&mdbg_proc->assert.rxwait);
	init_waitqueue_head(&mdbg_proc->loopcheck.rxwait);
	return 0;
}

static void mdbg_fs_exit(void)
{
	mdbg_memory_free();

	remove_proc_entry(mdbg_proc->assert.name, mdbg_proc->procdir);
	remove_proc_entry(mdbg_proc->loopcheck.name, mdbg_proc->procdir);
	remove_proc_entry(mdbg_proc->at_cmd.name, mdbg_proc->procdir);
	remove_proc_entry(mdbg_proc->dir_name, NULL);

	kfree(mdbg_proc);
	mdbg_proc = NULL;
}


static ssize_t mdbg_read(struct file *filp, char __user *buf,
		size_t count, loff_t *pos)
{
	long int read_size;
	int timeout = -1;
	int rval;
	static unsigned int dum_send_size;

	if (filp->f_flags & O_NONBLOCK)
		timeout = 0;

	if (count > MDBG_MAX_BUFFER_LEN)
		count = MDBG_MAX_BUFFER_LEN;

	if (timeout < 0) {
		rval = wait_event_interruptible(mdbg_wait,
				(mdbg_content_len() > 0));
		if (rval < 0)
			MDBG_ERR("mdbg_read wait interrupted!\n");
	}

	mutex_lock(&mdbg_dev->mdbg_lock);
	read_size = mdbg_receive(buf, count);
	if (sdiom_get_carddump_status(false) == 1) {
		dum_send_size += read_size;
		pr_info("mdbg dump send size: %d\n", dum_send_size);
	} else
		printk_ratelimited("%s read_size: %ld mdbg_read_count:%ld\n",
			__func__, read_size, mdbg_content_len());

	if (read_size > 0) {
		MDBG_LOG("Show %d bytes data.", read_size);
		rval = read_size;
	} else if (read_size == 0)
		rval = -EAGAIN;
	else {
		rval = read_size;
		MDBG_ERR("read error %d\n", rval);
	}
	mutex_unlock(&mdbg_dev->mdbg_lock);

	return rval;
}

static ssize_t mdbg_write(struct file *filp,
		const char __user *buf, size_t count, loff_t *pos)
{
	long int sent_size = 0;
	char *p_data = NULL;

	if (count > MDBG_WRITE_SIZE) {
		MDBG_ERR("mdbg_write count > MDBG_WRITE_SIZE\n");
		return -ENOMEM;
	}

	if (NULL == buf || 0 == count) {
		MDBG_ERR("Param Error!");
		return count;
	}

	p_data = memdup_user(buf, count);
	mutex_lock(&mdbg_dev->mdbg_lock);
	sent_size = mdbg_send(p_data, count, MDBG_SUBTYPE_AT);
	mutex_unlock(&mdbg_dev->mdbg_lock);
	kfree(p_data);

	MDBG_LOG("sent_size = %d", sent_size);

	return sent_size;
}

static int mdbg_open(struct inode *inode, struct file *filp)
{
	if (mdbg_dev->open_count != 0)
		MDBG_ERR("mdbg_open %d\n", mdbg_dev->open_count);

	mdbg_dev->open_count++;

	return 0;
}

static int mdbg_release(struct inode *inode, struct file *filp)
{
	mdbg_dev->open_count--;
	return 0;
}

static unsigned int mdbg_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask = 0;

	poll_wait(filp, &mdbg_dev->rxwait, wait);
	if (mdbg_content_len() > 0)
		mask |= POLLIN | POLLRDNORM;

	return mask;
}

static const struct file_operations mdbg_fops = {
	.owner = THIS_MODULE,
	.read  = mdbg_read,
	.write = mdbg_write,
	.open  = mdbg_open,
	.release = mdbg_release,
	.poll		= mdbg_poll,
};
static struct miscdevice mdbg_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "slog_wcn",
	.fops = &mdbg_fops,
};

int get_loopcheck_status(void)
{
	return mdbg_proc->fail_count;
}

void power_state_notify(bool state)
{
	if (state)
		mdbg_proc->first_boot = false;

	flag_download = state;
	power_state_changed = true;
	wake_up_interruptible(&mdbg_proc->loopcheck.rxwait);
}

void open_mdbg_loopcheck_interru(void)
{
	wake_up_interruptible(&mdbg_proc->loopcheck.rxwait);
}

int mdbg_init(void)
{
	int err;

	MDBG_FUNC_ENTERY;

	mdbg_dev = kzalloc(sizeof(struct mdbg_device_t), GFP_KERNEL);
	if (!mdbg_dev)
		return -ENOMEM;

	mdbg_dev->open_count = 0;
	mutex_init(&mdbg_dev->mdbg_lock);
	init_waitqueue_head(&mdbg_dev->rxwait);
	init_waitqueue_head(&mdbg_wait);
	err = mdbg_sdio_init();
	if (err < 0)
		return -ENOMEM;

	if (mdbg_fs_init() < 0)
		return -ENOMEM;
	if (mdbg_memory_alloc() < 0)
		return -ENOMEM;

	return misc_register(&mdbg_device);
}

void mdbg_exit(void)
{
	MDBG_FUNC_ENTERY;
	mdbg_sdio_remove();
	mdbg_fs_exit();
	mutex_destroy(&mdbg_dev->mdbg_lock);
	kfree(mdbg_dev);
	misc_deregister(&mdbg_device);
}
