/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  PH7 virtual machine routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
// strncpy()
#include <string.h>
#include "../log.h"
#include "../ph7/ph7.h"
#include "../civetweb/civetweb.h"
#include "ph7.h"
// struct httpsettings
#include "../config.h"
// mmap
#include <sys/mman.h>
// stat
#include <sys/types.h>
#include <sys/stat.h>
// open
#include <fcntl.h>

// PH7 virtual machine engine
static ph7 *pEngine; /* PH7 engine */
static ph7_vm *pVm;  /* Compiled PHP program */

static char *webroot_with_home = NULL;
static char *webroot_with_home_and_scripts = NULL;

/*
 * VM output consumer callback.
 * Each time the virtual machine generates some outputs, the following
 * function gets called by the underlying virtual machine to consume
 * the generated output.
 * This function is registered later via a call to ph7_vm_config()
 * with a configuration verb set to: PH7_VM_CONFIG_OUTPUT.
 */
static int Output_Consumer(const void *pOutput, unsigned int nOutputLen, void *pUserData /* Unused */)
{
	logg("PH7 error:");
	logg("%.*s", nOutputLen, (const char*)pOutput);
	return PH7_OK;
}

int ph7_handler(struct mg_connection *conn, void *cbdata)
{

	int rc;
	const void *pOut;
	unsigned int nLen;

	/* Handler may access the request info using mg_get_request_info */
	const struct mg_request_info * req_info = mg_get_request_info(conn);

	// Build full path of PHP script on our machine
	const size_t webroot_len = strlen(httpsettings.webroot);
	const size_t local_uri_len = strlen(req_info->local_uri+1);
	char full_path[webroot_len + local_uri_len + 2];
	strncpy(full_path, httpsettings.webroot, webroot_len);
	full_path[webroot_len] = '/';
	strncpy(full_path + webroot_len + 1u, req_info->local_uri + 1, local_uri_len);
	full_path[webroot_len + local_uri_len + 1u] = '\0';
	if(config.debug & DEBUG_API)
		logg("Full path of PHP script: %s", full_path);

	/* Now,it's time to compile our PHP file */
	rc = ph7_compile_file(
		pEngine, /* PH7 Engine */
		full_path, /* Path to the PHP file to compile */
		&pVm,    /* OUT: Compiled PHP program */
		0        /* IN: Compile flags */
	);

	/* Report script run-time errors */
	ph7_vm_config(pVm, PH7_VM_CONFIG_ERR_REPORT);

	/* Configure include paths */
	ph7_vm_config(pVm, PH7_VM_CONFIG_IMPORT_PATH, webroot_with_home);
	ph7_vm_config(pVm, PH7_VM_CONFIG_IMPORT_PATH, webroot_with_home_and_scripts);

	if( rc != PH7_OK ){ /* Compile error */
		if( rc == PH7_IO_ERR )
		{
			logg("IO error while opening the target file");
			return 0;
		}
		else if( rc == PH7_VM_ERR )
		{
			logg("VM initialization error");
			return 0;
		}
		else
		{
			logg("Compile error (%d)", rc);

			/* Extract error log */
			const char *zErrLog;
			int niLen;
			ph7_config(pEngine, PH7_CONFIG_ERR_LOG, &zErrLog, &niLen);
			if( niLen > 0 ){
				/* zErrLog is null terminated */
				logg("PH7 error: %s", zErrLog);
			}
			return 0;
		}
	}

	rc = ph7_vm_exec(pVm,0);
	if( rc != PH7_OK )
	{
		logg("VM execution error");
		return 0;
	}

	/*
	* Now we have our script compiled,it's time to configure our VM.
	* We will install the VM output consumer callback defined above
	* so that we can consume the VM output and redirect it to STDOUT.
	*/

	/* Extract the output */
	rc = ph7_vm_config(pVm, PH7_VM_CONFIG_EXTRACT_OUTPUT, &pOut, &nLen);

	if(nLen > 0)
	{
		mg_printf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n");
		mg_write(conn, pOut, nLen);
		logg("Output length: %u", nLen);
	}

#if 0
	const char *zErrLog;
	int niLen;
	/* Extract error log */
	ph7_config(
		pEngine,
		PH7_CONFIG_ERR_LOG,
		&zErrLog, /* First arg*/
		&niLen /* Second arg */
	);

	if( niLen > 0 ){
		logg("%s", zErrLog); /* Output*/
	}
#endif

	ph7_vm_reset(pVm);

	return 1;
}

void init_ph7(void)
{
	if(ph7_init(&pEngine) != PH7_OK )
	{
		logg("Error while allocating a new PH7 engine instance");
		return;
	}

	/* Set an error log consumer callback. This callback [Output_Consumer()] will
	* redirect all compile-time error messages to STDOUT.
	*/
	ph7_config(pEngine,PH7_VM_CONFIG_OUTPUT,
		Output_Consumer, // Error log consumer
		0 // NULL: Callback Private data
		);
/*
	ph7_config(pEngine,PH7_CONFIG_ERR_OUTPUT,
		Output_Consumer, // Error log consumer
		0 // NULL: Callback Private data
		);*/

	// Prepare include paths
	// var/www/html/admin (may be different due to user configuration)
	const size_t webroot_len = strlen(httpsettings.webroot);
	const size_t webhome_len = strlen(httpsettings.webhome);
	webroot_with_home = calloc(webroot_len+webhome_len+1, sizeof(char));
	strncpy(webroot_with_home, httpsettings.webroot, webroot_len);
	strncpy(webroot_with_home + webroot_len, httpsettings.webhome, webhome_len);
	webroot_with_home[webroot_len + webhome_len] = '\0';

	// var/www/html/admin/scripts/pi-hole/php (may be different due to user configuration)
	const char scripts_dir[] = "/scripts/pi-hole/php";
	size_t webroot_with_home_len = strlen(webroot_with_home);
	size_t scripts_dir_len = strlen(scripts_dir);
	webroot_with_home_and_scripts = calloc(webroot_with_home_len+scripts_dir_len+1, sizeof(char));
	strncpy(webroot_with_home_and_scripts, webroot_with_home, webroot_with_home_len);
	strncpy(webroot_with_home_and_scripts + webroot_with_home_len, scripts_dir, scripts_dir_len);
	webroot_with_home_and_scripts[webroot_with_home_len + scripts_dir_len] = '\0';
}

void ph7_terminate(void)
{
	ph7_vm_release(pVm);
	ph7_release(pEngine);
	free(webroot_with_home);
	free(webroot_with_home_and_scripts);
}
