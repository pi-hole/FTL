/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  TOML config writer routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "toml_helper.h"
#include "../config/config.h"

FILE * __attribute((malloc)) __attribute((nonnull(1))) openFTLtoml(const char *mode)
{
	FILE *fp;
	// If reading: first check if there is a local file
	if(strcmp(mode, "r") == 0 &&
	   (fp = fopen("pihole-FTL.toml", mode)) != NULL)
		return fp;

	// No readable local file found, try global file
	fp = fopen(GLOBALTOMLPATH, mode);

	return fp;
}

static inline void print_string(FILE *fp, const char *s)
{
	// Substitute empty string if pointer is NULL
	if(s == NULL)
		 s = "";

	bool ok = true;
	for (const char* p = s; *p && ok; p++)
	{
		int ch = *p;
		ok = isprint(ch) && ch != '"' && ch != '\\';
	}

	if (ok)
	{
		fprintf(fp, "\"%s\"", s);
		return;
	}

	int len = strlen(s);

	fprintf(fp, "\"");
	for ( ; len; len--, s++)
	{
		int ch = *s;
		if (isprint(ch) && ch != '"' && ch != '\\')
		{
			putc(ch, fp);
			continue;
		}

		switch (ch) {
		case 0x08: fprintf(fp, "\\b"); continue;
		case 0x09: fprintf(fp, "\\t"); continue;
		case 0x0a: fprintf(fp, "\\n"); continue;
		case 0x0c: fprintf(fp, "\\f"); continue;
		case 0x0d: fprintf(fp, "\\r"); continue;
		case '"':  fprintf(fp, "\\\""); continue;
		case '\\': fprintf(fp, "\\\\"); continue;
		default:   fprintf(fp, "\\0x%02x", ch & 0xff); continue;
		}
	}
	fprintf(fp, "\"");
}

// Indentation (tabs and/or spaces) is allowed but not required, we use it for
// the sake of readability
static inline void indentTOML(FILE *fp, const unsigned int indent)
{
	for (unsigned int i = 0; i < 2*indent; i++)
		fputc(' ', fp);
}

void catTOMLsection(FILE *fp, const unsigned int indent, const char *key)
{
	indentTOML(fp, indent);
	fprintf(fp, "[%s]\n", key);
}

void catTOMLextrainfo(FILE *fp, const unsigned int indent, const char *infostr)
{
	indentTOML(fp, indent);
	fprintf(fp, "# %s\n", infostr);
}

void catTOMLstring(FILE *fp, const unsigned int indent, const char *key, const char *description, const char *values, const char *val, const char *dval)
{
	indentTOML(fp, indent);
	fprintf(fp, "# %s\n", description);
	indentTOML(fp, indent);
	fprintf(fp, "# Possible values are: %s\n", values);
	indentTOML(fp, indent);
	fprintf(fp, "%s = ", key);
	print_string(fp, val);

	// Compare with default value and comment on difference
	if(val != NULL && dval != NULL && strcmp(val, dval) != 0)
	{
		fprintf(fp, " ### CHANGED, default = ");
		print_string(fp, dval);
	}

	fputs("\n\n", fp);
}

void catTOMLbool(FILE *fp, const unsigned int indent, const char *key, const char *description, const bool val, const bool dval)
{
	indentTOML(fp, indent);
	fprintf(fp, "# %s\n", description);
	indentTOML(fp, indent);
	fprintf(fp, "%s = %s", key, val ? "true" : "false");

	// Compare with default value and comment on difference
	if(val != dval)
	{
		fprintf(fp, " ### CHANGED, default = %s", dval ? "true" : "false");
	}

	fputs("\n\n", fp);
}

void catTOMLint(FILE *fp, const unsigned int indent, const char *key, const char *description, const int val, const int dval)
{
	indentTOML(fp, indent);
	fprintf(fp, "# %s\n", description);
	indentTOML(fp, indent);
	fprintf(fp, "%s = %i", key, val);

	// Compare with default value and comment on difference
	if(val != dval)
	{
		fprintf(fp, " ### CHANGED, default = %i", dval);
	}

	fputs("\n\n", fp);
}

void catTOMLuint(FILE *fp, const unsigned int indent, const char *key, const char *description, const unsigned int val, const unsigned int dval)
{
	indentTOML(fp, indent);
	fprintf(fp, "# %s\n", description);
	indentTOML(fp, indent);
	fprintf(fp, "%s = %u", key, val);

	// Compare with default value and comment on difference
	if(val != dval)
	{
		fprintf(fp, " ### CHANGED, default = %u", dval);
	}

	fputs("\n\n", fp);
}
