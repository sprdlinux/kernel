/*
* Copyright (C) 2015 Spreadtrum Communications Inc.
* This software is licensed under the terms of the GNU General Public
* License version 2, as published by the Free Software Foundation, and
* may be copied, distributed, and modified under those terms.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*/

#include <linux/interrupt.h>
#include <linux/marlin_platform.h>
#include <linux/mutex.h>
#include <linux/sdiom_rx_api.h>
#include <linux/sdiom_tx_api.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/wakelock.h>
#include "mdbg_sdio.h"
#include "mdbg_ring.h"
#include "mdbg.h"

#define MDBG_RX_RING_SIZE		(2*1024*1024)
#define CP_START_ADDR			(0)
#define FIRMWARE_MAX_SIZE		(0x90c00)
#define DUMP_PACKET_SIZE	(1024)

#define DUMP_WIFI_ADDR			(0x70000000)
#define DUMP_WIFI_ADDR_SIZE		(0x70000)

#define DUMP_BT_CMD_ADDR		(0X50000000)
#define DUMP_BT_CMD_ADDR_SIZE		(0x400)
#define DUMP_BT_ADDR			(0X50040000)
#define DUMP_BT_ADDR_SIZE		(0xa400)

#define DUMP_FM_ADDR			(0X400B0000)
#define DUMP_INTC_ADDR			(0X40010000)

#define DUMP_SYSTIMER_ADDR		(0X40020000)
#define DUMP_WDG_ADDR			(0X40040000)
#define DUMP_APB_ADDR			(0X40060000)
#define DUMP_DMA_ADDR			(0X60200000)
#define DUMP_AHB_ADDR			(0X60300000)
#define DUMP_REG_SIZE			(0X10000)
#define DUMP_SDIO_ADDR			(0x60400000)
#define DUMP_SDIO_ADDR_SIZE		(0x10000)


#define SMP_HEADERFLAG 0X7E7E7E7E
#define SMP_RESERVEDFLAG 0X5A5A
#define SMP_DSP_CHANNEL_NUM 0X88
#define SMP_DSP_TYPE 0X9D
#define SMP_DSP_DUMP_TYPE 0X32

#define SYSNC_CODE_LEN 0X4
#define CHKSUM_LEN 0X2
#define ARMLOG_HEAD 9

#define SMP_HEAD_STR "at+smphead="

struct ring_rx_data {
	unsigned char		*addr;
	unsigned int		len;
	unsigned int		fifo_id;
	struct list_head	entry;
};

struct ring_device {
	struct mdbg_ring_t	*ring;
	struct wake_lock	rw_wake_lock;
	spinlock_t		rw_lock;
	struct mutex mdbg_read_mutex;
	struct list_head        rx_head;
	struct tasklet_struct   rx_task;
};

struct ring_device *ring_dev;

struct sme_head_tag {
	unsigned int seq_num;
	unsigned short len;
	unsigned char type;
	unsigned char subtype;
};

struct smp_head {
	unsigned int sync_code;
	unsigned short length;
	unsigned char channel_num;
	unsigned char packet_type;
	unsigned short reserved;
	unsigned short check_sum;
};

enum smp_diag_subtype_t {
	NORMAL_INFO = 0X0,
	DUMP_MEM_DATA,
	DUMP_MEM_END,
};

static int long flag_smp;

long mdbg_content_len(void)
{
	if (unlikely(!ring_dev))
		return 0;

	return mdbg_ring_content_len(ring_dev->ring);
}

static unsigned int mdbg_tx_cb(void *addr)
{
	kfree(addr);

	return 0;
}

static int smp_calc_chsum(unsigned short *buf, unsigned int size)
{
	unsigned long int cksum = 0;
	unsigned short data;

	while (size > 1) {
		data = *buf;
		buf++;
		cksum += data;
		size -= sizeof(unsigned short);
	}

	if (size)
		cksum += *buf & 0xff;

	while (cksum >> 16)
		cksum = (cksum >> 16) + (cksum & 0xffff);

	return (unsigned short) (~cksum);
}

static int mdbg_write_smp_head(unsigned int len)
{
	struct smp_head *smp;
	unsigned char *smp_buf, *tmp;
	int smp_len;

	smp_len = sizeof(struct smp_head) + sizeof(struct sme_head_tag);
	smp_buf = kmalloc(smp_len, GFP_KERNEL);
	if (!smp_buf)
		return -ENOMEM;

	/* Smp header */
	smp = (struct smp_head *)smp_buf;
	smp->sync_code = SMP_HEADERFLAG;
	smp->length = smp_len + len - SYSNC_CODE_LEN;
	smp->channel_num = SMP_DSP_CHANNEL_NUM;
	smp->packet_type = SMP_DSP_TYPE;
	smp->reserved = SMP_RESERVEDFLAG;
	smp->check_sum = smp_calc_chsum(&smp->length, sizeof(struct smp_head)
		- SYSNC_CODE_LEN - CHKSUM_LEN);

	/* Diag header: Needs use these bytes for ARM log tool,
	 * And it need't 0x7e head and without 0x7e tail
	 */
	tmp = smp_buf + sizeof(struct smp_head);
	((struct sme_head_tag *)tmp)->seq_num = 0;
	((struct sme_head_tag *)tmp)->len = smp_len
		+ len - sizeof(struct smp_head);
	((struct sme_head_tag *)tmp)->type = SMP_DSP_TYPE;
	((struct sme_head_tag *)tmp)->subtype = SMP_DSP_DUMP_TYPE;

	mdbg_ring_write(ring_dev->ring, smp_buf, smp_len);

	kfree(smp_buf);

	return 0;
}
static long int mdbg_sdio_write(char *buf,
	long int len, unsigned int subtype)
{
	unsigned char *sdio_buf = NULL;
	char *str = NULL;

	if (unlikely(marlin_get_download_status() != true))
		return -EIO;

	sdio_buf = kmalloc(len, GFP_KERNEL);
	if (!sdio_buf)
		return -ENOMEM;
	memcpy(sdio_buf, buf, len);

	str = strstr(sdio_buf, SMP_HEAD_STR);
	if (!str)
		str = strstr(sdio_buf + ARMLOG_HEAD, SMP_HEAD_STR);
	pr_info("len:%ld,str:%s\n", len, str);

	if (str) {
		int err;

		str[sizeof(SMP_HEAD_STR)] = 0;
		err = kstrtol(&str[sizeof(SMP_HEAD_STR) - 1], 10, &flag_smp);
		pr_info("%s err:%d, flag_smp:%ld\n", __func__, err, flag_smp);
		kfree(sdio_buf);
	} else
		sdiom_pt_write(sdio_buf, len, MDBG_SDIO_PACKER_TYPE, subtype);

	return len;
}

static void mdbg_ring_rx_task(unsigned long data)
{
	struct ring_rx_data *rx = NULL;
	struct mdbg_ring_t *ring = NULL;

	if (unlikely(!ring_dev)) {
		pr_err("mdbg_ring_rx_task ring_dev is NULL\n");
		return;
	}

	spin_lock_bh(&ring_dev->rw_lock);
	rx = list_first_entry_or_null(&ring_dev->rx_head,
			struct ring_rx_data, entry);
	if (rx)
		list_del(&rx->entry);
	else {
		pr_err("mdbg tasklet something err\n");
		spin_unlock_bh(&ring_dev->rw_lock);
		return;
	}
	if (!list_empty(&ring_dev->rx_head))
		tasklet_schedule(&ring_dev->rx_task);
	ring = ring_dev->ring;
	spin_unlock_bh(&ring_dev->rw_lock);
	mdbg_ring_write(ring, rx->addr, rx->len);
	wake_up_interruptible(&mdbg_wait);
	wake_up_interruptible(&mdbg_dev->rxwait);
	sdiom_pt_read_release(rx->fifo_id);
	kfree(rx);
}

void mdbg_sdio_read(void *addr, unsigned int len,
				unsigned int fifo_id)
{
	struct ring_rx_data *rx;

	if (ring_dev != NULL) {
		mutex_lock(&ring_dev->mdbg_read_mutex);
		rx = kmalloc(sizeof(struct ring_rx_data), GFP_KERNEL);
		if (!rx) {
			pr_err("mdbg ring low memory\n");
			mutex_unlock(&ring_dev->mdbg_read_mutex);
			sdiom_pt_read_release(fifo_id);
			return;
		}
		mutex_unlock(&ring_dev->mdbg_read_mutex);
		spin_lock_bh(&ring_dev->rw_lock);
		rx->addr	= (unsigned char *)addr;
		rx->len		= len;
		rx->fifo_id	= fifo_id;
		list_add_tail(&rx->entry, &ring_dev->rx_head);
		spin_unlock_bh(&ring_dev->rw_lock);
		tasklet_schedule(&ring_dev->rx_task);
	}
}
EXPORT_SYMBOL_GPL(mdbg_sdio_read);

long int mdbg_send(char *buf, long int len, unsigned int subtype)
{
	long int sent_size = 0;

	MDBG_LOG("BYTE MODE");
	wake_lock(&ring_dev->rw_wake_lock);
	sent_size = mdbg_sdio_write(buf, len, subtype);
	wake_unlock(&ring_dev->rw_wake_lock);

	return sent_size;
}

long int mdbg_receive(void *buf, long int len)
{
	return mdbg_ring_read(ring_dev->ring, buf, len);
}

static int mdbg_dump_data(unsigned int start_addr,
	char *str, int len, int str_len)
{
	unsigned char *buf;
	int count, trans_size, err = 0, i, prin_temp = 0;

	if (unlikely(!ring_dev)) {
		pr_err("mdbg_dump ring_dev is NULL\n");
		return -1;
	}

	if (str != NULL) {
		msleep(20);
		pr_info("mdbg str_len:%d\n", str_len);
		if (flag_smp == 1)
			mdbg_write_smp_head(str_len);
		mdbg_ring_write(ring_dev->ring, str, str_len);
		wake_up_interruptible(&mdbg_wait);
		wake_up_interruptible(&mdbg_dev->rxwait);
	}

	if (len == 0)
		return 0;

	buf = kmalloc(DUMP_PACKET_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	count = 0;
	while (count < len) {
		trans_size = (len - count) > DUMP_PACKET_SIZE ?
			DUMP_PACKET_SIZE : (len - count);
		err = sdiom_dt_read(start_addr + count, buf, trans_size);
		if (err < 0) {
			pr_err("%s dump memory error:%d\n", __func__, err);
			goto out;
		}
		if (prin_temp == 0) {
			prin_temp = 1;
			for (i = 0; i < 5; i++)
				pr_err("mdbg *****buf[%d]:0x%x\n",
				i, buf[i]);
			}
		if (flag_smp == 1)
			mdbg_write_smp_head(trans_size);
		mdbg_ring_write(ring_dev->ring, buf, trans_size);
		count += trans_size;
		wake_up_interruptible(&mdbg_wait);
		wake_up_interruptible(&mdbg_dev->rxwait);
	}

out:
	kfree(buf);

	return count;
}

void mdbg_clear_log(void)
{
	mdbg_ring_clear(ring_dev->ring);
}

int mdbg_dump_mem(void)
{
	long int count;
	int ret;

	marlin_hold_cpu();
	msleep(100);
	mdbg_clear_log();

	count = mdbg_dump_data(CP_START_ADDR, NULL, FIRMWARE_MAX_SIZE, 0);
	if (count <= 0) {
		pr_info("mdbg start reset marlin reg!\n");
		ret = marlin_reset_reg();
		if (ret < 0)
			return 0;

		count = mdbg_dump_data(CP_START_ADDR, NULL,
			FIRMWARE_MAX_SIZE, 0);

		pr_info("mdbg only dump ram %ld ok!\n", count);

		goto end;
	}
	pr_info("mdbg dump ram %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_SDIO_ADDR, "start_dump_sdio_reg",
		DUMP_SDIO_ADDR_SIZE, strlen("start_dump_sdio_reg"));
	pr_info("mdbg dump sdio %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_INTC_ADDR, "start_dump_intc_reg",
		DUMP_REG_SIZE, strlen("start_dump_intc_reg"));
	pr_info("mdbg dump intc %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_SYSTIMER_ADDR, "start_dump_systimer_reg",
		DUMP_REG_SIZE, strlen("start_dump_systimer_reg"));
	pr_info("mdbg dump systimer %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_WDG_ADDR, "start_dump_wdg_reg",
		DUMP_REG_SIZE, strlen("start_dump_wdg_reg"));
	pr_info("mdbg dump wdg %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_APB_ADDR, "start_dump_apb_reg",
		DUMP_REG_SIZE, strlen("start_dump_apb_reg"));
	pr_info("mdbg dump apb %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_DMA_ADDR, "start_dump_dma_reg",
		DUMP_REG_SIZE, strlen("start_dump_dma_reg"));
	pr_info("mdbg dump dma %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_AHB_ADDR, "start_dump_ahb_reg",
		DUMP_REG_SIZE, strlen("start_dump_ahb_reg"));
	pr_info("mdbg dump ahb %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_FM_ADDR, "start_dump_fm_reg",
		DUMP_REG_SIZE, strlen("start_dump_fm_reg"));
	pr_info("mdbg dump fm %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_WIFI_ADDR, "start_dump_wifi_reg",
		DUMP_WIFI_ADDR_SIZE, strlen("start_dump_wifi_reg"));
	pr_info("mdbg dump wifi %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_BT_CMD_ADDR, "start_dump_bt_cmd_buf",
		DUMP_BT_CMD_ADDR_SIZE, strlen("start_dump_bt_cmd_buf"));
	pr_info("mdbg dump bt cmd %ld ok!\n", count);

	count = mdbg_dump_data(DUMP_BT_ADDR, "start_dump_bt_reg",
		DUMP_BT_ADDR_SIZE, strlen("start_dump_bt_reg"));
	pr_info("mdbg dump bt %ld ok!\n", count);

end:
	count = mdbg_dump_data(0, "marlin_memdump_finish",
		0, strlen("marlin_memdump_finish"));

	pr_info("mdbg dump memory finish\n");

	return 0;
}

static int mdbg_pt_ring_reg(void)
{
	sdiom_register_pt_rx_process(MDBG_SDIO_PACKER_TYPE,
			MDBG_SUBTYPE_RING, mdbg_sdio_read);
	sdiom_register_pt_tx_release(MDBG_SDIO_PACKER_TYPE,
			MDBG_SUBTYPE_RING, mdbg_tx_cb);

	return 0;
}

int mdbg_pt_common_reg(unsigned int subtype, void *func)
{
	sdiom_register_pt_rx_process(MDBG_SDIO_PACKER_TYPE,
			subtype, func);
	sdiom_register_pt_tx_release(MDBG_SDIO_PACKER_TYPE,
			subtype, mdbg_tx_cb);

	return 0;
}

int mdbg_sdio_init(void)
{
	int err = 0;

	ring_dev = kmalloc(sizeof(struct ring_device), GFP_KERNEL);
	if (!ring_dev)
		return -ENOMEM;

	ring_dev->ring = mdbg_ring_alloc(MDBG_RX_RING_SIZE);
	if (!(ring_dev->ring)) {
		MDBG_ERR("Ring malloc error.");
		return -MDBG_ERR_MALLOC_FAIL;
	}

	wake_lock_init(&ring_dev->rw_wake_lock, WAKE_LOCK_SUSPEND,
			"mdbg_wake_lock");
	spin_lock_init(&ring_dev->rw_lock);
	mutex_init(&ring_dev->mdbg_read_mutex);
	INIT_LIST_HEAD(&ring_dev->rx_head);
	tasklet_init(&ring_dev->rx_task, mdbg_ring_rx_task,
		(unsigned long int)ring_dev);
	mdbg_pt_ring_reg();
	MDBG_LOG("mdbg_sdio_init!");

	return err;
}

void mdbg_sdio_remove(void)
{
	struct ring_rx_data *pos, *next;

	MDBG_FUNC_ENTERY;
	wake_lock_destroy(&ring_dev->rw_wake_lock);
	mdbg_ring_destroy(ring_dev->ring);
	tasklet_kill(&ring_dev->rx_task);
	list_for_each_entry_safe(pos, next, &ring_dev->rx_head, entry) {
		if (pos) {
			list_del(&pos->entry);
			kfree(pos);
		}
	}
	kfree(ring_dev);

	ring_dev = NULL;
}
