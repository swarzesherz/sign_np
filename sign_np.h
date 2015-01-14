// Copyright (C) 2015       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libkirk/kirk_engine.h"
#include "libkirk/amctrl.h"
#include "isoreader.h"
#include "eboot.h"
#include "tlzrc.h"
#include "utils.h"

#define RATIO_LIMIT 90
#define PSF_MAGIC 0x46535000

static u8 npumdimg_private_key[0x14] = {0x14, 0xB0, 0x22, 0xE8, 0x92, 0xCF, 0x86, 0x14, 0xA4, 0x45, 0x57, 0xDB, 0x09, 0x5C, 0x92, 0x8D, 0xE9, 0xB8, 0x99, 0x70};
static u8 npumdimg_public_key[0x28] = {
		0x01, 0x21, 0xEA, 0x6E, 0xCD, 0xB2, 0x3A, 0x3E,
		0x23, 0x75, 0x67, 0x1C, 0x53, 0x62, 0xE8, 0xE2,
		0x8B, 0x1E, 0x78, 0x3B, 0x1A, 0x27, 0x32, 0x15,
		0x8B, 0x8C, 0xED, 0x98, 0x46, 0x6C, 0x18, 0xA3,
		0xAC, 0x3B, 0x11, 0x06, 0xAF, 0xB4, 0xEC, 0x3B
};

typedef struct {
	u32 magic;
	u32 version;
	u32 key_offset;
	u32 val_offset;
	u32 key_count;
} SFO_Header;

typedef struct {
	u16 name_offset;
	u8  align;
	u8  type;
	u32 val_size;
	u32 align_size;
	u32 data_offset;
} SFO_Entry;

typedef struct {
	u16 sector_size; 	// 0x0800
	u16 unk_2;			// 0xE000
	u32 unk_4;
	u32 unk_8;
	u32 unk_12;
	u32 unk_16;
	u32 lba_start;
	u32 unk_24;
	u32 nsectors;
	u32 unk_32;
	u32 lba_end;
	u32 unk_40;
	u32 block_entry_offset;
	char disc_id[0x10];
	u32 startdat_offset;
	u32 unk_68;
	u8 unk_72;
	u8 bbmac_param;
	u8 unk_74;
	u8 unk_75;
	u32 unk_76;
	u32 unk_80;
	u32 unk_84;
	u32 unk_88;
	u32 unk_92;
} NPUMDIMG_HEADER_BODY;

typedef struct {
	u8 magic[0x08];  // NPUMDIMG
	u32 np_flags;
	u32 block_basis;
	u8 content_id[0x30];
	NPUMDIMG_HEADER_BODY body;	
	u8 header_key[0x10];
	u8 data_key[0x10];
	u8 header_hash[0x10];
	u8 padding[0x8];
	u8 ecdsa_sig[0x28];
} NPUMDIMG_HEADER;