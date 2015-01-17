// Copyright (C) 2015       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

typedef unsigned long long u64;
typedef unsigned int   u32;
typedef unsigned short u16;
typedef unsigned char  u8;

u16 se16(u16 i);
u32 se32(u32 i);
u64 se64(u64 i);

bool isEmpty(unsigned char* buf, int buf_size);
u64 hex_to_u64(const char* hex_str);
void hex_to_bytes(unsigned char *data, const char *hex_str, unsigned int str_length);
bool is_hex(const char* hex_str, unsigned int str_length);