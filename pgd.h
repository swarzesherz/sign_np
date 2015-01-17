// Copyright (C) 2013       tpu
// Copyright (C) 2015       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libkirk/kirk_engine.h"
#include "libkirk/amctrl.h"
#include "utils.h"

static unsigned char dnas_key1A90[] = {0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5, 0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43};
static unsigned char dnas_key1AA0[] = {0x27, 0x74, 0xFB, 0xEB, 0xA4, 0xA0, 0x01, 0xD7, 0x02, 0x56, 0x9E, 0x33, 0x8C, 0x19, 0x57, 0x83};

typedef struct {
	unsigned char vkey[16];

	int open_flag;
	int key_index;
	int drm_type;
	int mac_type;
	int cipher_type;

	int data_size;
	int align_size;
	int block_size;
	int block_nr;
	int data_offset;
	int table_offset;

	unsigned char *buf;
} PGD_HEADER;

int encrypt_pgd(u8* data, int data_size, int block_size, int key_index, int drm_type, int flag, u8* key, u8* pgd_data);
int decrypt_pgd(u8* pgd_data, int pgd_size, int flag, u8* key);