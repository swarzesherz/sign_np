// Copyright (C) 2015       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#include "utils.h"

// Auxiliary functions.
u16 se16(u16 i)
{
	return (((i & 0xFF00) >> 8) | ((i & 0xFF) << 8));
}

u32 se32(u32 i)
{
	return ((i & 0xFF000000) >> 24) | ((i & 0xFF0000) >>  8) | ((i & 0xFF00) <<  8) | ((i & 0xFF) << 24);
}

u64 se64(u64 i)
{
	return ((i & 0x00000000000000ff) << 56) | ((i & 0x000000000000ff00) << 40) |
		((i & 0x0000000000ff0000) << 24) | ((i & 0x00000000ff000000) <<  8) |
		((i & 0x000000ff00000000) >>  8) | ((i & 0x0000ff0000000000) >> 24) |
		((i & 0x00ff000000000000) >> 40) | ((i & 0xff00000000000000) >> 56);
}

bool isEmpty(unsigned char* buf, int buf_size)
{
	if (buf != NULL)
	{
		int i;
		for(i = 0; i < buf_size; i++)
		{
			if (buf[i] != 0) return false;
		}
	}
	return true;
}

u64 hex_to_u64(const char* hex_str)
{
	u32 length = strlen(hex_str);
	u64 tmp = 0;
	u64 result = 0;
	char c;

	while (length--)
	{
		c = *hex_str++;
		if((c >= '0') && (c <= '9'))
			tmp = c - '0';
		else if((c >= 'a') && (c <= 'f'))
			tmp = c - 'a' + 10;
		else if((c >= 'A') && (c <= 'F'))
			tmp = c - 'A' + 10;
		else
			tmp = 0;
		result |= (tmp << (length * 4));
	}

	return result;
}

void hex_to_bytes(unsigned char *data, const char *hex_str, unsigned int str_length)
{
	u32 data_length = str_length / 2;
	char tmp_buf[3] = {0, 0, 0};

	// Don't convert if the string length is odd.
	if (!(str_length % 2))
	{
		u8 *out = (u8 *) malloc (str_length * sizeof(u8));
		u8 *pos = out;

		while (str_length--)
		{
			tmp_buf[0] = *hex_str++;
			tmp_buf[1] = *hex_str++;

			*pos++ = (u8)(hex_to_u64(tmp_buf) & 0xFF);
		}

		// Copy back to our array.
		memcpy(data, out, data_length);
	}
}

bool is_hex(const char* hex_str, unsigned int str_length)
{
    static const char hex_chars[] = "0123456789abcdefABCDEF";

    if (hex_str == NULL)
        return false;

    unsigned int i;
    for (i = 0; i < str_length; i++)
	{
		if (strchr(hex_chars, hex_str[i]) == 0)
			return false;
	}

    return true;
}