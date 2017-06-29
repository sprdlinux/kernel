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

#ifndef _MARLIN_DEBUG_H
#define _MARLIN_DEBUG_H


#include "mdbg_type.h"

struct mdbg_device_t {
	int			open_count;
	struct mutex		mdbg_lock;
	wait_queue_head_t	rxwait;
};

extern wait_queue_head_t	mdbg_wait;
extern struct mdbg_device_t	*mdbg_dev;
extern int wcn_open_module;
extern int wcn_module_state_change;
extern unsigned char flag_download;
extern unsigned char flag_reset;
extern struct completion ge2_completion;
int mdbg_init(void);
void mdbg_exit(void);
void power_state_notify(bool state);
void open_mdbg_loopcheck_interru(void);
int get_loopcheck_status(void);
void marlin_hold_cpu(void);
#endif
