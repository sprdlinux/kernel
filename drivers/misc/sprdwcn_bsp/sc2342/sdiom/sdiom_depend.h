#ifndef __SDIOM_DEPEND_H__
#define __SDIOM_DEPEND_H__

#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define sdiom_print	pr_debug
#define sdiom_info	pr_info
#define sdiom_err	pr_err

struct sdiom_sema_box_t {
	struct semaphore tx_core_sema;
	struct semaphore tx_trans_sema;
	struct semaphore rx_core_sema;
	struct semaphore rx_trans_sema;
};

extern void sdiom_sema_init(void);

extern void sdiom_tx_core_up(void);
extern void sdiom_tx_core_down(void);
extern void sdiom_tx_trans_up(void);
extern void sdiom_tx_trans_down(void);

extern void sdiom_rx_core_up(void);
extern void sdiom_rx_core_down(void);
extern void sdiom_rx_trans_up(void);
extern void sdiom_rx_trans_down(void);

extern void *sdiom_memset(void *dest, int c, unsigned int count);
extern void *sdiom_malloc(unsigned int size);
extern void sdiom_free(void *memblock);

extern void os_sleep(unsigned int i);
extern void sdiom_rx_cb_mutex_init(void);
extern void sdiom_rx_cb_lock(void);
extern void sdiom_rx_cb_unlock(void);

#endif /* __SDIOM_DEPEND_H__ */
