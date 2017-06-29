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


#ifndef _MDBG_SDIO_H
#define _MDBG_SDIO_H

#include "mdbg_type.h"

#define MDBG_SDIO_PACKER_TYPE		3

enum {
	MDBG_SUBTYPE_RING	= 0,
	MDBG_SUBTYPE_LOOPCHECK,
	MDBG_SUBTYPE_AT,
	MDBG_SUBTYPE_ASSERT,
};

int mdbg_sdio_init(void);
void mdbg_sdio_remove(void);
long int mdbg_send(char *buf, long int len, unsigned int subtype);
long int mdbg_receive(void *buf, long int len);
int mdbg_dump_mem(void);
int mdbg_pt_common_reg(unsigned int subtype, void *func);
long mdbg_content_len(void);
void mdbg_clear_log(void);

#endif
