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

void util_consume_va_args(va_list ap, const char *fmt)
{
	if (!fmt)
		return;

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
				(void)va_arg(ap, int);
				fmt++;
			}
			while (*fmt && *fmt >= '0' && *fmt <= '9')
				fmt++;
			if (*fmt == '.')
			{
				fmt++;
				if (*fmt == '*')
				{
					(void)va_arg(ap, int);
					fmt++;
				}
				while (*fmt && *fmt >= '0' && *fmt <= '9')
					fmt++;
			}

			int is_long_double = 0;
			int int_mod = 0; /* 0=none, 1=h, 2=hh, 3=l, 4=ll, 5=j, 6=z, 7=t */
			if (*fmt == 'h')
			{
				fmt++;
				if (*fmt == 'h')
				{
					fmt++;
					int_mod = 2;
				}
				else
				{
					int_mod = 1;
				}
			}
			else if (*fmt == 'l')
			{
				fmt++;
				if (*fmt == 'l')
				{
					fmt++;
					int_mod = 4;
				}
				else
				{
					int_mod = 3;
				}
			}
			else if (*fmt == 'j')
			{
				fmt++;
				int_mod = 5;
			}
			else if (*fmt == 'z')
			{
				fmt++;
				int_mod = 6;
			}
			else if (*fmt == 't')
			{
				fmt++;
				int_mod = 7;
			}
			else if (*fmt == 'L')
			{
				fmt++;
				is_long_double = 1;
			}

			if (*fmt)
			{
				switch (*fmt)
				{
				case 'd':
				case 'i':
				case 'o':
				case 'u':
				case 'x':
				case 'X':
				case 'c':
					switch (int_mod)
					{
					case 0:
					case 1:
					case 2:
						(void)va_arg(ap, int);
						break;
					case 3:
						(void)va_arg(ap, long);
						break;
					case 4:
						(void)va_arg(ap, long long);
						break;
					case 5:
						(void)va_arg(ap, intmax_t);
						break;
					case 6:
						(void)va_arg(ap, size_t);
						break;
					case 7:
						(void)va_arg(ap, ptrdiff_t);
						break;
					}
					break;
				case 'e':
				case 'E':
				case 'f':
				case 'F':
				case 'g':
				case 'G':
				case 'a':
				case 'A':
					if (is_long_double)
						(void)va_arg(ap, long double);
					else
						(void)va_arg(ap, double);
					break;
				case 's':
				case 'p':
				case 'n':
					(void)va_arg(ap, void *);
					break;
				}
				fmt++;
			}
		}
		else
		{
			fmt++;
		}
	}
}
