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
#include <string.h>

#include "theme.h"

struct web_themes webthemes[THEME_MAX] = {
	{
		/* id */ THEME_DEFAULT_AUTO,
		/* name */ "default-auto",
		/* description */ "Pi-hole auto",
		/* dark */ true,
		/* color */ "#367fa9"
	},
	{
		/* id */ THEME_DEFAULT_LIGHT,
		/* name */ "default-light",
		/* description */ "Pi-hole day",
		/* dark */ false,
		/* color */ "#367fa9"
	},
	{
		/* id */ THEME_DEFAULT_DARK,
		/* name */ "default-dark",
		/* description */ "Pi-hole midnight",
		/* dark */ true,
		/* color */ "#272c30"
	},
	{
		/* id */ THEME_DEFAULT_DARKER,
		/* name */ "default-darker",
		/* description */ "Pi-hole deep-midnight",
		/* dark */ true,
		/* color */ "#2e6786"
	},
	{
		/* id */ THEME_HIGH_CONTRAST,
		/* name */ "high-contrast",
		/* description */ "High-contrast light",
		/* dark */ false,
		/* color */ "#0078a0"
	},
	{
		/* id */ THEME_HIGH_CONTRAST_DARK,
		/* name */ "high-contrast-dark",
		/* description */ "High-contrast dark",
		/* dark */ true,
		/* color */ "#0077c7"
	},
	{
		/* id */ THEME_LCARS,
		/* name */ "lcars",
		/* description */ "Star Trek LCARS",
		/* dark */ true,
		/* color */ "#4488FF"
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
