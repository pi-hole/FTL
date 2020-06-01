/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  PH7 extension prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef PH7_EXT_H
#define PH7_EXT_H

// Function prototypes
int gethostname_impl(ph7_context *pCtx, int argc, ph7_value **argv);

#ifdef PH7_CORE // Include this section only in ../ph7.c
// Container for the foreign functions defined above.
// These functions will be registered later using a call
// to [ph7_create_function()].
static const struct foreign_func {
	const char *zName; /* Name of the foreign function*/
	int (*xProc)(ph7_context *, int, ph7_value **); /* Pointer to the C function performing the computation*/
}aFunc[] = {
	{"gethostname", gethostname_impl}
};
#endif // PH7_CORE
#endif // PH7_EXT_H