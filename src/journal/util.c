// SPDX-License-Identifier: BSD-3-Clause

#include "util.h"

#include <string.h>

void util_write_le64(unsigned char buf[static 8], uint64_t val)
{
	buf[0] = (unsigned char)(val);
	buf[1] = (unsigned char)(val >> 8);
	buf[2] = (unsigned char)(val >> 16);
	buf[3] = (unsigned char)(val >> 24);
	buf[4] = (unsigned char)(val >> 32);
	buf[5] = (unsigned char)(val >> 40);
	buf[6] = (unsigned char)(val >> 48);
	buf[7] = (unsigned char)(val >> 56);
}

int util_count_printf_conversions(const char *fmt)
{
	int count = 0;

	if (!fmt)
		return 0;

	while (*fmt)
	{
		if (*fmt == '%')
		{
			fmt++;
			if (*fmt == '%')
			{
				fmt++;
				continue;
			}
			while (*fmt && strchr("-+ #0", *fmt))
				fmt++;
			if (*fmt == '*')
			{
				count++;
				fmt++;
			}
			while (*fmt && *fmt >= '0' && *fmt <= '9')
				fmt++;
			if (*fmt == '.')
			{
				fmt++;
				if (*fmt == '*')
				{
					count++;
					fmt++;
				}
				while (*fmt && *fmt >= '0' && *fmt <= '9')
					fmt++;
			}
			if (*fmt == 'h' || *fmt == 'l' || *fmt == 'j' || *fmt == 'z' || *fmt == 't' ||
				*fmt == 'L')
			{
				if ((*fmt == 'h' && *(fmt + 1) == 'h') || (*fmt == 'l' && *(fmt + 1) == 'l'))
					fmt++;
				fmt++;
			}
			if (*fmt && strchr("diouxXfFeEgGaAcspn%", *fmt))
			{
				if (*fmt != '%')
					count++;
				fmt++;
			}
		}
		else
		{
			fmt++;
		}
	}
	return count;
}
