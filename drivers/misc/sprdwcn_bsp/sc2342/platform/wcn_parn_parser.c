/*
 * WCN partition parser for different CPU have different path with EMMC and NAND
 *
 * Copyright (c) 2017 Spreadtrum
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/delay.h>
#include <linux/dirent.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/fs_struct.h>
#include <linux/unistd.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include "wcn_parn_parser.h"

#define ROOT_PATH "/"
#define CONF_COMMENT '#'
#define CONF_DELIMITERS " =\n\r\t"
#define CONF_VALUES_DELIMITERS "=\n\r\t"
#define CONF_MAX_LINE_LEN 255
static const char *prefix = "fstab.";
static char FSTAB_NAME[255];

static char *fgets(char *buf, int buf_len, struct file *fp)
{
	int ret;
	int i = 0;

	ret = kernel_read(fp, fp->f_pos, buf, buf_len);

	if (ret <= 0)
		return NULL;

	while (buf[i++] != '\n' && i < ret)
		;

	if (i < ret)
		fp->f_pos += i;

	if (i < buf_len)
		buf[i] = 0;

	return buf;
}



static int load_fstab_conf(const char *p_path, char *WCN_PATH)
{
	struct file *p_file;
	char *p_name;
	char line[CONF_MAX_LINE_LEN+1];
	char *p;
	char *temp;

	p = line;
	pr_info("Attempt to load conf from %s\n", p_path);

	p_file = filp_open(FSTAB_NAME, O_RDONLY, 0);
	if (IS_ERR(p_file)) {
		pr_err("%s open file %s error not find\n",
			FSTAB_NAME, __func__);
		return PTR_ERR(p_file);
	}

	/* read line by line */
	while (fgets(line, CONF_MAX_LINE_LEN+1, p_file) != NULL) {

		if (line[0] == CONF_COMMENT)
			continue;

		p_name = strsep(&p, CONF_DELIMITERS);
		pr_info("wcn p_name %s\n", p_name);
		if (p_name != NULL) {
			temp = strstr(p_name, "system");
			if (temp != NULL) {
				snprintf(WCN_PATH, strlen(p_name)+2,
					"/%s", p_name);
				WCN_PATH[strlen(WCN_PATH) - strlen(temp)]
					= '\0';
				snprintf(WCN_PATH, strlen(WCN_PATH)+10,
					"%s%s", WCN_PATH, "wcnmodem");

				break;
			}
		}

	}

	filp_close(p_file, NULL);

	return 0;
}

static int prefixcmp(const char *str, const char *prefix)
{
	for (; ; str++, prefix++)
		if (!*prefix)
			return 0;
		else if (*str != *prefix)
			return (unsigned char)*prefix - (unsigned char)*str;
}

static int find_callback(struct dir_context *ctx, const char *name, int namlen,
		     loff_t offset, u64 ino, unsigned int d_type)
{
	int tmp;

	tmp = prefixcmp(name, prefix);
	if (tmp == 0) {
		snprintf(FSTAB_NAME, strlen(name)+2, "/%s", name);
		FSTAB_NAME[strlen(name)+3] = '\0';
		pr_info("FSTAB_NAME is %s\n", FSTAB_NAME);
	}

	return 0;
}

static struct dir_context ctx =  {
	.actor = find_callback,
};

int parse_firmware_path(char *FIRMWARE_PATH)
{
	struct file *file1;

	pr_info("%s entry\n", __func__);

	file1 = filp_open(ROOT_PATH, O_DIRECTORY, 0);
	if (IS_ERR(file1)) {
		pr_err("%s open file %s error\n", ROOT_PATH, __func__);
		return PTR_ERR(file1);
	}

	iterate_dir(file1, &ctx);

	load_fstab_conf(FSTAB_NAME, FIRMWARE_PATH);

	fput(file1);

	return 0;

}

