/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for string-related functions
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

#undef strlen
size_t FTLstrlen(const char *s, const char *file, const char *func, const int line)
{
	// The strlen() function calculates the length of the string s, not
	// including the terminating '\0' character.
	if(s == NULL)
	{
		log_err("Trying to get the length of a NULL string in %s() (%s:%i)", func, file, line);
		return 0;
	}
	return strlen(s);
}

#undef strnlen
size_t FTLstrnlen(const char *s, const size_t maxlen, const char *file, const char *func, const int line)
{
	// The strnlen() function returns the number of characters in the string s,
	// not including the terminating '\0' character, but at most maxlen. In
	// doing this, strnlen() looks only at the first maxlen characters at s and
	// never beyond s+maxlen.
	if(s == NULL)
	{
		log_err("Trying to get the length of a NULL string in %s() (%s:%i)", func, file, line);
		return 0;
	}
	return strnlen(s, maxlen);
}

#undef strstr
char *FTLstrstr(const char *haystack, const char *needle, const char *file, const char *func, const int line)
{
	// The strstr() function finds the first occurrence of the substring needle
	// in the string haystack. The terminating '\0' characters are not
	// compared.
	if(haystack == NULL || needle == NULL)
	{
		log_err("Trying to find a NULL (%s%s) string in %s() (%s:%i)",
		        haystack == NULL ? "L" : "", needle == NULL ? "R" : "", func, file, line);
		return NULL;
	}
	return strstr(haystack, needle);
}

#undef strcmp
int FTLstrcmp(const char *s1, const char *s2, const char *file, const char *func, const int line)
{
	// The strcmp() function compares the two strings s1 and s2. It returns an
	// integer less than, equal to, or greater than zero if s1 is found,
	// respectively, to be less than, to match, or be greater than s2.
	if(s1 == NULL || s2 == NULL)
	{
		log_err("Trying to compare a NULL (%s%s) string in %s() (%s:%i)",
		        s1 == NULL ? "L" : "", s2 == NULL ? "R" : "", func, file, line);
		return -1;
	}
	return strcmp(s1, s2);
}

#undef strncmp
int FTLstrncmp(const char *s1, const char *s2, const size_t n, const char *file, const char *func, const int line)
{
	// The strncmp() function is similar, except it compares only the first (at
	// most) n bytes of s1 and s2.
	if(s1 == NULL || s2 == NULL)
	{
		log_err("Trying to compare a NULL (%s%s) string in %s() (%s:%i)",
		        s1 == NULL ? "L" : "", s2 == NULL ? "R" : "", func, file, line);
		return -1;
	}
	return strncmp(s1, s2, n);
}

#undef strcasecmp
int FTLstrcasecmp(const char *s1, const char *s2, const char *file, const char *func, const int line)
{
	// The strcasecmp() function performs a byte-by-byte comparison of the
	// strings s1 and s2, ignoring the case of the characters. It returns an
	// integer less than, equal to, or greater than zero if s1 is found,
	// respectively, to be less than, to match, or be greater than s2.
	if(s1 == NULL || s2 == NULL)
	{
		log_err("Trying to compare a NULL (%s%s) string in %s() (%s:%i)",
		        s1 == NULL ? "L" : "", s2 == NULL ? "R" : "", func, file, line);
		return -1;
	}
	return strcasecmp(s1, s2);
}

#undef strncasecmp
int FTLstrncasecmp(const char *s1, const char *s2, const size_t n, const char *file, const char *func, const int line)
{
	// The strncasecmp() function is similar, except it compares only the first
	// (at most) n bytes of s1 and s2.
	if(s1 == NULL || s2 == NULL)
	{
		log_err("Trying to compare a NULL (%s%s) string in %s() (%s:%i)",
		        s1 == NULL ? "L" : "", s2 == NULL ? "R" : "", func, file, line);
		return -1;
	}
	return strncasecmp(s1, s2, n);
}

#undef strcat
char *FTLstrcat(char *dest, const char *src, const char *file, const char *func, const int line)
{
	// The strcat() function appends the src string to the dest string,
	// overwriting the terminating null byte ('\0') at the end of dest, and then
	// adds a terminating null byte. The strings may not overlap, and the dest
	// string must have enough space for the result. If dest is not large enough,
	// program behavior is unpredictable; buffer overruns are a favorite avenue
	// for attacking secure programs.
	if(dest == NULL || src == NULL)
	{
		log_err("Trying to concatenate a NULL (%s%s) string in %s() (%s:%i)",
		        dest == NULL ? "L" : "", src == NULL ? "R" : "", func, file, line);
		return NULL;
	}
	return strcat(dest, src);
}

#undef strncat
char *FTLstrncat(char *dest, const char *src, const size_t n, const char *file, const char *func, const int line)
{
	// The strncat() function is similar, except that it will use at most n bytes
	// from src; and src does not need to be null-terminated if it contains n or
	// more bytes.
	if(dest == NULL || src == NULL)
	{
		log_err("Trying to concatenate a NULL (%s%s) string in %s() (%s:%i)",
		        dest == NULL ? "L" : "", src == NULL ? "R" : "", func, file, line);
		return NULL;
	}
	return strncat(dest, src, n);
}

#undef strcpy
char *FTLstrcpy(char *dest, const char *src, const char *file, const char *func, const int line)
{
	// The strcpy() function copies the string src to dest (including the
	// terminating '\0' character.)
	if(dest == NULL || src == NULL)
	{
		log_err("Trying to copy a NULL (%s%s) string in %s() (%s:%i)",
		        dest == NULL ? "L" : "", src == NULL ? "R" : "", func, file, line);
		return NULL;
	}
	return strcpy(dest, src);
}

#undef strncpy
char *FTLstrncpy(char *dest, const char *src, const size_t n, const char *file, const char *func, const int line)
{
	// The strncpy() function is similar, except that at most n bytes of src are
	// copied. Warning: If there is no null byte among the first n bytes of src,
	// the string placed in dest will not be null-terminated.
	if(dest == NULL || src == NULL)
	{
		log_err("Trying to copy a NULL (%s%s) string in %s() (%s:%i)",
		        dest == NULL ? "L" : "", src == NULL ? "R" : "", func, file, line);
		return NULL;
	}
	return strncpy(dest, src, n);
}

#undef memset
void *FTLmemset(void *s, const int c, const size_t n, const char *file, const char *func, const int line)
{
	// The memset() function fills the first n bytes of the memory area pointed
	// to by s with the constant byte c.
	if(s == NULL)
	{
		log_err("Trying to fill a NULL memory area in %s() (%s:%i)", func, file, line);
		return NULL;
	}
	return memset(s, c, n);
}

#undef memcpy
void *FTLmemcpy(void *dest, const void *src, const size_t n, const char *file, const char *func, const int line)
{
	// The memcpy() function copies n bytes from memory area src to memory area
	// dest. The memory areas must not overlap. Use memmove(3) if the memory
	// areas do overlap.
	if(dest == NULL || src == NULL)
	{
		log_err("Trying to copy a NULL (%s%s) memory area in %s() (%s:%i)",
		        dest == NULL ? "L" : "", src == NULL ? "R" : "", func, file, line);
		return NULL;
	}
	return memcpy(dest, src, n);
}

#undef memmove
void *FTLmemmove(void *dest, const void *src, const size_t n, const char *file, const char *func, const int line)
{
	// The memmove() function copies n bytes from memory area src to memory area
	// dest. The memory areas may overlap: copying takes place as though the
	// bytes in src are first copied into a temporary array that does not
	// overlap src or dest, and the bytes are then copied from the temporary
	// array to dest.
	if(dest == NULL || src == NULL)
	{
		log_err("Trying to move a NULL (%s%s) memory area in %s() (%s:%i)",
		        dest == NULL ? "L" : "", src == NULL ? "R" : "", func, file, line);
		return NULL;
	}
	return memmove(dest, src, n);
}

#undef memcmp
int FTLmemcmp(const void *s1, const void *s2, const size_t n, const char *file, const char *func, const int line)
{
	// The memcmp() function compares the first n bytes (each interpreted as
	// unsigned char) of the memory areas s1 and s2.
	if(s1 == NULL || s2 == NULL)
	{
		log_err("Trying to compare a NULL (%s%s) memory area in %s() (%s:%i)",
		        s1 == NULL ? "L" : "", s2 == NULL ? "R" : "", func, file, line);
		return -1;
	}
	return memcmp(s1, s2, n);
}

#undef memmem
void *FTLmemmem(const void *haystack, const size_t haystacklen, const void *needle, const size_t needlelen, const char *file, const char *func, const int line)
{
	// The memmem() function finds the start of the first occurrence of the
	// substring needle of length needlelen in the memory area haystack of
	// length haystacklen.
	if(haystack == NULL || needle == NULL)
	{
		log_err("Trying to find a NULL (%s%s) memory area in %s() (%s:%i)",
		        haystack == NULL ? "L" : "", needle == NULL ? "R" : "", func, file, line);
		return NULL;
	}
	return memmem(haystack, haystacklen, needle, needlelen);
}
