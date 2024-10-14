/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Theme-related routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// NULL
#include <stddef.h>
// strcasecmp()
#include <strings.h>

#include "theme.h"

struct web_themes webthemes[THEME_MAX] = {
	{
		/* name */ "default-auto",
		/* description */ "Pi-hole auto",
		/* color */ "#367fa9",
		/* id */ THEME_DEFAULT_AUTO,
		/* dark */ true,
	},
	{
		/* name */ "default-light",
		/* description */ "Pi-hole day",
		/* color */ "#367fa9",
		/* id */ THEME_DEFAULT_LIGHT,
		/* dark */ false,
	},
	{
		/* name */ "default-dark",
		/* description */ "Pi-hole midnight",
		/* color */ "#272c30",
		/* id */ THEME_DEFAULT_DARK,
		/* dark */ true,
	},
	{
		/* name */ "default-darker",
		/* description */ "Pi-hole deep-midnight",
		/* color */ "#2e6786",
		/* id */ THEME_DEFAULT_DARKER,
		/* dark */ true,
	},
	{
		/* name */ "high-contrast",
		/* description */ "High-contrast light",
		/* color */ "#0078a0",
		/* id */ THEME_HIGH_CONTRAST,
		/* dark */ false,
	},
	{
		/* name */ "high-contrast-dark",
		/* description */ "High-contrast dark",
		/* color */ "#0077c7",
		/* id */ THEME_HIGH_CONTRAST_DARK,
		/* dark */ true,
	},
	{
		/* name */ "lcars",
		/* description */ "Star Trek LCARS",
		/* color */ "#4488FF",
		/* id */ THEME_LCARS,
		/* dark */ true,
	},
};

const char * __attribute__ ((pure)) get_web_theme_str(const enum web_theme web_theme)
{
	for(enum web_theme i = 0; i < THEME_MAX; i++)
		if(webthemes[i].id == web_theme)
			return webthemes[i].name;
	return NULL;
}

int __attribute__ ((pure)) get_web_theme_val(const char *web_theme)
{
	// Iterate over all possible theme values
	for(enum web_theme i = 0; i < THEME_MAX; i++)
	{
		if(strcasecmp(web_theme, webthemes[i].name) == 0)
			return i;
	}

	// Invalid value
	return -1;
}
