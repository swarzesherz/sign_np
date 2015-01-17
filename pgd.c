// Copyright (C) 2013       tpu
// Copyright (C) 2015       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#include "pgd.h"

/*
	PGD encrypt function.
*/
int encrypt_pgd(u8* data, int data_size, int block_size, int key_index, int drm_type, int flag, u8* key, u8* pgd_data)
{	
	MAC_KEY mkey;
	CIPHER_KEY ckey;

	// Additional size variables.
	int data_offset = 0x90;
	int align_size = (data_size + 15) &~ 15;
	int table_offset = data_offset + align_size;
	int block_nr = ((align_size + block_size - 1) &~ (block_size - 1)) / block_size;
	int pgd_size = 0x90 + align_size + block_nr * 16;
	
	// Build new PGD header.
	u8* pgd = (u8 *) malloc (pgd_size);
	memset(pgd, 0, pgd_size);
	memcpy(pgd + data_offset, data, data_size);

	// Set magic PGD.
	pgd[0] = 0x00;
	pgd[1] = 0x50;
	pgd[2] = 0x47;
	pgd[3] = 0x44;

	// Set key index and drm type.
	*(u32*)(pgd + 4) = key_index;
	*(u32*)(pgd + 8) = drm_type;
	
	// Select the hashing, crypto and open modes.
	int mac_type;
	int cipher_type;
	int open_flag = flag;
	if (drm_type == 1)
	{
		mac_type = 1;
		open_flag |= 4;
		if (key_index > 1)
		{
			mac_type = 3;
			open_flag |= 8;
		}
		cipher_type = 1;
	}
	else
	{
		mac_type = 2;
		cipher_type = 2;
	}
	
	// Select the fixed DNAS key.
	u8* fkey = NULL;
	if ((open_flag & 0x2) == 0x2)
		fkey = dnas_key1A90;
	if ((open_flag & 0x1) == 0x1)
		fkey = dnas_key1AA0;

	if (fkey == NULL)
	{
		printf("PGD: Invalid PGD DNAS flag! %08x\n", flag);
		return -1;
	}
	
	// Set the decryption parameters in the decrypted header.
	*(u32*)(pgd + 0x44) = data_size;
	*(u32*)(pgd + 0x48) = block_size;
	*(u32*)(pgd + 0x4C) = data_offset;
	
	// Generate random header and data keys.
	sceUtilsBufferCopyWithRange(pgd + 0x10, 0x30, 0, 0, KIRK_CMD_PRNG);
	
	// Encrypt the data.
	sceDrmBBCipherInit(&ckey, cipher_type, 2, pgd + 0x30, key, 0);
	sceDrmBBCipherUpdate(&ckey, pgd + data_offset, align_size);
	sceDrmBBCipherFinal(&ckey);
	
	// Build data MAC hash.
	int i;
	for (i = 0; i < block_nr; i++)
	{
		int rsize = align_size - i * block_size;
		if (rsize > block_size)
			rsize = block_size;

		sceDrmBBMacInit(&mkey, mac_type);
		sceDrmBBMacUpdate(&mkey, pgd + data_offset + i * block_size, rsize);
		sceDrmBBMacFinal(&mkey, pgd + table_offset + i * 16, key);
	}
	
	// Build table MAC hash.
	sceDrmBBMacInit(&mkey, mac_type);
	sceDrmBBMacUpdate(&mkey, pgd + table_offset, block_nr * 16);
	sceDrmBBMacFinal(&mkey, pgd + 0x60, key);
	
	// Encrypt the PGD header block (0x30 bytes).
	sceDrmBBCipherInit(&ckey, cipher_type, 2, pgd + 0x10, key, 0);
	sceDrmBBCipherUpdate(&ckey, pgd + 0x30, 0x30);
	sceDrmBBCipherFinal(&ckey);
	
	// Build MAC hash at 0x70 (key hash).
	sceDrmBBMacInit(&mkey, mac_type);
	sceDrmBBMacUpdate(&mkey, pgd + 0x00, 0x70);
	sceDrmBBMacFinal(&mkey, pgd + 0x70, key);

	// Build MAC hash at 0x80 (DNAS hash).
	sceDrmBBMacInit(&mkey, mac_type);
	sceDrmBBMacUpdate(&mkey, pgd + 0x00, 0x80);
	sceDrmBBMacFinal(&mkey, pgd + 0x80, fkey);
	
	// Copy back the generated PGD file.
	memcpy(pgd_data, pgd, pgd_size);

	return pgd_size;
}

/*
	PGD decrypt function.
*/
int decrypt_pgd(u8* pgd_data, int pgd_size, int flag, u8* key)
{
	int result;
	PGD_HEADER PGD[sizeof(PGD_HEADER)];
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	u8* fkey;

	// Read in the PGD header parameters.
	memset(PGD, 0, sizeof(PGD_HEADER));

	PGD->buf = pgd_data;
	PGD->key_index = *(u32*)(pgd_data + 4);
	PGD->drm_type  = *(u32*)(pgd_data + 8);

	// Set the hashing, crypto and open modes.
	if (PGD->drm_type == 1)
	{
		PGD->mac_type = 1;
		flag |= 4;

		if(PGD->key_index > 1)
		{
			PGD->mac_type = 3;
			flag |= 8;
		}
		PGD->cipher_type = 1;
	}
	else
	{
		PGD->mac_type = 2;
		PGD->cipher_type = 2;
	}
	PGD->open_flag = flag;

	// Get the fixed DNAS key.
	fkey = NULL;
	if ((flag & 0x2) == 0x2)
		fkey = dnas_key1A90;
	if ((flag & 0x1) == 0x1)
		fkey = dnas_key1AA0;

	if (fkey == NULL)
	{
		printf("PGD: Invalid PGD DNAS flag! %08x\n", flag);
		return -1;
	}

	// Test MAC hash at 0x80 (DNAS hash).
	sceDrmBBMacInit(&mkey, PGD->mac_type);
	sceDrmBBMacUpdate(&mkey, pgd_data, 0x80);
	result = sceDrmBBMacFinal2(&mkey, pgd_data + 0x80, fkey);

	if (result)
	{
		printf("PGD: Invalid PGD 0x80 MAC hash!\n");
		return -1;
	}

	// Test MAC hash at 0x70 (key hash).
	sceDrmBBMacInit(&mkey, PGD->mac_type);
	sceDrmBBMacUpdate(&mkey, pgd_data, 0x70);

	// If a key was provided, check it against MAC 0x70.
	if (!isEmpty(key, 0x10))
	{
		result = sceDrmBBMacFinal2(&mkey, pgd_data + 0x70, key);
		if (result)
		{
			printf("PGD: Invalid PGD 0x70 MAC hash!\n");
			return -1;
		}
		else
		{
			memcpy(PGD->vkey, key, 16);
		}
	}
	else
	{
		// Generate the key from MAC 0x70.
		bbmac_getkey(&mkey, pgd_data + 0x70, PGD->vkey);
	}

	// Decrypt the PGD header block (0x30 bytes).
	sceDrmBBCipherInit(&ckey, PGD->cipher_type, 2, pgd_data + 0x10, PGD->vkey, 0);
	sceDrmBBCipherUpdate(&ckey, pgd_data + 0x30, 0x30);
	sceDrmBBCipherFinal(&ckey);

	// Get the decryption parameters from the decrypted header.
	PGD->data_size   = *(u32*)(pgd_data + 0x44);
	PGD->block_size  = *(u32*)(pgd_data + 0x48);
	PGD->data_offset = *(u32*)(pgd_data + 0x4c);

	// Additional size variables.
	PGD->align_size = (PGD->data_size + 15) &~ 15;
	PGD->table_offset = PGD->data_offset + PGD->align_size;
	PGD->block_nr = (PGD->align_size + PGD->block_size - 1) &~ (PGD->block_size - 1);
	PGD->block_nr = PGD->block_nr / PGD->block_size;

	if ((PGD->align_size + PGD->block_nr * 16) > pgd_size)
	{
		printf("ERROR: Invalid PGD data size!\n");
		return -1;
	}

	// Test MAC hash at 0x60 (table hash).
	sceDrmBBMacInit(&mkey, PGD->mac_type);
	sceDrmBBMacUpdate(&mkey, pgd_data + PGD->table_offset, PGD->block_nr * 16);
	result = sceDrmBBMacFinal2(&mkey, pgd_data + 0x60, PGD->vkey);

	if (result)
	{
		printf("ERROR: Invalid PGD 0x60 MAC hash!\n");
		return -1;
	}

	// Decrypt the data.
	sceDrmBBCipherInit(&ckey, PGD->cipher_type, 2, pgd_data + 0x30, PGD->vkey, 0);
	sceDrmBBCipherUpdate(&ckey, pgd_data + 0x90, PGD->align_size);
	sceDrmBBCipherFinal(&ckey);

	return PGD->data_size;
}