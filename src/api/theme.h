/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API route prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef THEME_H
#define THEME_H

#include <stdbool.h>

enum web_theme {
	THEME_DEFAULT_AUTO = 0,
	THEME_DEFAULT_LIGHT,
	THEME_DEFAULT_DARK,
	THEME_DEFAULT_DARKER,
	THEME_HIGH_CONTRAST,
	THEME_HIGH_CONTRAST_DARK,
	THEME_LCARS,
	THEME_MAX // This needs to be the last element in this enum
} __attribute__ ((packed));

struct web_themes{
	const enum web_theme id;
	const char *name;
	const char *description;
	const bool dark;
	const char *color;
};

// defined in theme.c
extern struct web_themes webthemes[THEME_MAX];

// Prototypes
const char * __attribute__ ((pure)) get_web_theme_str(const enum web_theme web_theme);
int __attribute__ ((pure)) get_web_theme_val(const char *web_theme);

#endif // THEME_H
