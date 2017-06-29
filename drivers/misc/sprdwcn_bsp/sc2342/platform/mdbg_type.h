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

#ifndef _MDBG_TYPE_H
#define _MDBG_TYPE_H

#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/irq.h>
#include <linux/input.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define MDBG_HEADER		"MDBG: "
#define MDBG_HEADER_ERR		"MDBG_ERR: "
#define MDBG_DEBUG_MODE		0

#define MDBG_ERR(fmt, args...)	pr_err(MDBG_HEADER_ERR"%s:" fmt \
				"\n", __func__, ## args)
#if MDBG_DEBUG_MODE
#define MDBG_LOG(fmt, args...)	pr_err(MDBG_HEADER"%s:" fmt \
				"\n", __func__, ## args)
#else
#define MDBG_LOG(fmt, args...)
#endif

#define MDBG_FUNC_ENTERY	MDBG_LOG("ENTER.")
#define MDBG_FUNC_EXIT		MDBG_LOG("EXIT.")

#define MDBG_SUCCESS		0
#define MDBG_ERR_RING_FULL	1
#define MDBG_ERR_MALLOC_FAIL 2
#define MDBG_ERR_BAD_PARAM	3
#define MDBG_ERR_SDIO_ERR	4
#define MDBG_ERR_TIMEOUT	5
#define MDBG_ERR_NO_FILE	6


#endif
