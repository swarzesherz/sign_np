// Copyright (C) 2013       tpu
// Copyright (C) 2015       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#include "eboot.h"

TAG_KEY *tkey;
u8 tag_key[0x100];
char *strtable;
int e_shnum;
Elf32_Shdr *section;

/*
	PSP header building functions.
*/
Elf32_Shdr *find_section(char *name)
{
	int i;

	for (i = 0; i < e_shnum; i++) {
		if (strcmp(name, strtable+section[i].sh_name) == 0)
			return &section[i];
	}

	return NULL;
}

void fix_reloc7(u8 *ebuf)
{
	Elf32_Rel *rel;
	int i, j, count;

	count = 0;
	for (i = 0; i < e_shnum; i++) 
	{
		if (section[i].sh_type == 0x700000A0) 
		{
			rel = (Elf32_Rel*)(ebuf+section[i].sh_offset);
			for (j = 0; j < section[i].sh_size / sizeof(Elf32_Rel); j++) 
			{
				if ((rel[j].r_info & 0xFF) == 7) {
					rel[j].r_info = 0;
					count++;
				}
			}
		}
	}
}

void build_psp_header(PSP_Header2 *psph, u8 *ebuf, int esize)
{
	Elf32_Ehdr *elf;
	Elf32_Shdr *sh;
	Elf32_Phdr *ph;
	SceModuleInfo *modinfo;
	int i, j, shtab_size;

	elf = (Elf32_Ehdr*)(ebuf);

	section = (Elf32_Shdr *)(ebuf+elf->e_shoff);
	e_shnum = elf->e_shnum;

	shtab_size = e_shnum*elf->e_shentsize;
	if (elf->e_shoff + shtab_size>esize) {
		e_shnum = 0;
	} else {
		strtable = (char*)(ebuf + section[elf->e_shstrndx].sh_offset);
		fix_reloc7(ebuf);
	}

	memset(psph, 0, sizeof(PSP_Header2));

	psph->signature = 0x5053507E;
	psph->mod_attribute = 0;
	psph->comp_attribute = 0;
	psph->module_ver_lo = 1;
	psph->module_ver_hi = 1;
	psph->mod_version = 1;
	psph->devkit_version = 0x06020010;
	psph->decrypt_mode = 9;
	psph->overlap_size = 0;

	psph->comp_size = esize;
	psph->_80 = 0x80;

	psph->boot_entry = elf->e_entry;
	psph->elf_size = esize;
	psph->psp_size = ((esize + 15) & 0xfffffff0) + 0x150;

	ph = (Elf32_Phdr*)(ebuf + elf->e_phoff);
	sh = find_section(".rodata.sceModuleInfo");
	
	if (sh) {
		psph->modinfo_offset = sh->sh_offset;
		modinfo = (SceModuleInfo*)(ebuf + sh->sh_offset);
	} else {
		psph->modinfo_offset = ph[0].p_paddr;
		modinfo = (SceModuleInfo*)(ebuf+ph[0].p_paddr);
	}

	strcpy(psph->modname, modinfo->modname);

	j = 0;
	for (i = 0; i < elf->e_phnum; i++)
	{
		if (ph[i].p_type == PT_LOAD) {
			if (j > 3) {
				printf("ERROR: Too many EBOOT PH segments!\n");
				continue;
			}
			psph->seg_align[j]   = ph[i].p_align;
			psph->seg_address[j] = ph[i].p_vaddr;
			psph->seg_size[j]    = ph[i].p_memsz;
			psph->bss_size = ph[i].p_memsz-ph[i].p_filesz;
			j++;
		}
	}

	psph->nsegments = j;
}

/*
	PSP tag generating function.
*/
void build_tag_key(TAG_KEY *tk)
{
	int i;
	u32 *k7 = (u32*)tag_key;

	for (i = 0; i < 9; i++) {
		memcpy(tag_key + 0x14 + (i * 16), tk->key, 0x10);
		tag_key[0x14 + (i * 16)] = i;
	}

	k7[0] = KIRK_MODE_DECRYPT_CBC;
	k7[1] = 0;
	k7[2] = 0;
	k7[3] = tk->code;
	k7[4] = 0x90;

	kirk_CMD7(tag_key, tag_key, 0x90 + 0x14);
}

/*
	PSP KIRK1 forging function.
*/
void build_psp_kirk1(u8 *kbuf, u8 *pbuf, int esize)
{
	KIRK_CMD1_HEADER *k1 = (KIRK_CMD1_HEADER *)kbuf;
	int i;

	memcpy(kbuf, test_kirk1, 32);

	k1->mode = KIRK_MODE_CMD1;
	k1->data_size = esize;
	k1->data_offset = 0x80;
	
	if (tkey->type == 6)
		k1->ecdsa_hash = 1;

	memcpy(kbuf + 0x90, pbuf, 0x80);

	if (esize % 16) {
		for (i = 0; i < (16 - (esize % 16)); i++) {
			kbuf[0x110 + esize + i] = 0xFF - i * 0x11;
		}
	}
	
	kirk_CMD0(kbuf, kbuf, esize, 0);
}

/*
	PSP SHA1 generating function.
*/
void build_psp_SHA1(u8 *ebuf, u8 *pbuf)
{
	u8 tmp[0x150];
	u32 *k4 = (u32*)tmp;
	int i;

	memset(tmp, 0, 0x150);

	for (i = 0; i < 0x40; i++) {
		tmp[0x14 + i] = ebuf[0x40 + i] ^ tag_key[0x50 + i];
	}
	memcpy(tmp + 0xd0, pbuf, 0x80);

	k4[0] = KIRK_MODE_ENCRYPT_CBC;
	k4[1] = 0;
	k4[2] = 0;
	k4[3] = tkey->code;
	k4[4] = 0x40;
	kirk_CMD4(tmp + 0x80 - 0x14, tmp, 0x40 + 0x14);

	for (i = 0; i < 0x40; i++) {
		tmp[0x80 + i] ^=  tag_key[0x10 + i];
	}

	memcpy(tmp + 0xd0, pbuf, 0x80);
	memcpy(tmp + 0xc0, pbuf + 0xb0, 0x10);
	memcpy(tmp + 0x70, test_k140, 0x10);
	memset(tmp, 0, 0x70);
	
	if (tkey->type == 6)
		memcpy(tmp + 0x50, ebuf + 0x40 + 0x40, 0x20);
	
	memcpy(tmp + 0x08, tag_key, 0x10);
	
	k4[0] = 0x014c;
	k4[1] = tkey->tag;

	kirk_CMD11(tmp, tmp, 0x150);

	memcpy(tmp + 0x5c, test_k140, 0x10);
	memcpy(tmp + 0x6c, tmp, 0x14);

	k4 = (u32*)(tmp + 0x48);
	k4[0] = KIRK_MODE_ENCRYPT_CBC;
	k4[1] = 0;
	k4[2] = 0;
	k4[3] = tkey->code;
	k4[4] = 0x60;
	kirk_CMD4(tmp + 0x48, tmp + 0x48, 0x60);

	memset(tmp, 0, 0x5c);
	
	if (tkey->type == 6)
		memcpy(tmp + 0x3c, ebuf + 0x40 + 0x40, 0x20);
	
	k4 = (u32*)tmp;
	k4[0] = tkey->tag;

	memcpy(ebuf + 0x000, tmp + 0xd0, 0x80);
	memcpy(ebuf + 0x080, tmp + 0x80, 0x30);
	memcpy(ebuf + 0x0b0, tmp + 0xc0, 0x10);
	memcpy(ebuf + 0x0c0, tmp + 0xb0, 0x10);
	memcpy(ebuf + 0x0d0, tmp + 0x00, 0x5c);
	memcpy(ebuf + 0x12c, tmp + 0x6c, 0x14);
	memcpy(ebuf + 0x140, tmp + 0x5c, 0x10);
}

/*
	PSP EBOOT signing function.
*/
int sign_eboot(u8 *eboot, int eboot_size, int tag, u8 *seboot)
{
	PSP_Header2 psp_header;
	
	// Select tag.
	tkey = &key_list[tag];

	// Allocate buffer for EBOOT data.
	int esize = eboot_size;
	u8 *ebuf = (u8 *) malloc(esize + 4096);
	memset(ebuf, 0, esize + 4096);

	// Read EBOOT data.
	memcpy(ebuf + 0x150, eboot, esize);
	
	if (*(u32*)(ebuf + 0x150) != 0x464C457F) {
		printf("ERROR: Invalid ELF file for EBOOT resigning!\n");
		return -1;
	}
	
	printf("Resigning EBOOT file with tag %08X\n", tkey->tag);

	// Build ~PSP header.
	build_psp_header(&psp_header, ebuf + 0x150, esize);
	
	// Encrypt and sign data with KIRK1.
	build_psp_kirk1(ebuf + 0x40, (u8*)&psp_header, esize);
	
	// Generate PRX tag key.
	build_tag_key(tkey);
	
	// Hash the data.
	build_psp_SHA1(ebuf, (u8*)&psp_header);

	// Copy back the generated EBOOT.
	esize = (esize + 15) &~ 15;
	memcpy(seboot, ebuf, esize + 0x150);
	
	return (esize + 0x150);
}