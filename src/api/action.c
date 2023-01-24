/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/action
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
// wait()
#include <sys/wait.h>
// reboot()
#include <sys/reboot.h>
#include <unistd.h>

static int run_and_stream_command(struct ftl_conn *api, const char *path, const char *const args[])
{
	// Create a pipe for communication with our child
	int pipefd[2];
	if(pipe(pipefd) !=0)
	{
		log_err("Cannot create pipe while running gravity action: %s", strerror(errno));
		return false;
	}

	// Fork!
	pid_t cpid = fork();
	int code = -1;
	bool crashed = false;
	if (cpid == 0)
	{
		/*** CHILD ***/
		// Close the reading end of the pipe
		close(pipefd[0]);

		// Disable logging
		log_ctrl(false, false);

		// Flush STDERR
		fflush(stderr);

		// Redirect STDERR into our pipe
		dup2(pipefd[1], STDERR_FILENO);
		dup2(pipefd[1], STDOUT_FILENO);

		// Run pihole -g
		execv(path, (char *const *)args);

		// Exit the fork
		exit(EXIT_SUCCESS);
	}
	else
	{
		/*** PARENT ***/
		// Close the writing end of the pipe
		close(pipefd[1]);

		// Send 200 OK with chunked size (-1)
		mg_send_http_ok(api->conn, "text/plain", -1);

		// Read readirected STDOUT/STDERR until EOF
		// We are only interested in the last pipe line
		char errbuf[1024] = "";
		while(read(pipefd[0], errbuf, sizeof(errbuf)) > 0)
		{
			// Send chunked data
			// The chunked size is the length of the string in hex and has to be
			// transferred in advance, followed by \r\n as line separator and
			// followed by a chunk of data (the string itself) of the specified
			// size
			mg_printf(api->conn, "%zX\r\n%s\r\n", strlen(errbuf), errbuf);

			// Reset buffer
			memset(errbuf, 0, sizeof(errbuf));
		}

		// Wait until child has exited to get its return code
		int status;
		waitpid(cpid, &status, 0);
		code = WEXITSTATUS(status);

		if(WIFSIGNALED(status))
		{
			crashed = true;
			log_err("gravity failed with signal %d %s",
			        WTERMSIG(status),
			        WCOREDUMP(status) ? "(core dumped)" : "");
		}

		log_debug(DEBUG_API, "Gravity return code: %d", code);

		// Close the reading end of the pipe
		close(pipefd[0]);
	}

	// Send final chunk of size 0 showing end of data
	mg_printf(api->conn, "0\r\n\r\n");

	return code == EXIT_SUCCESS && !crashed ? 200 : 500;
}

int api_action_gravity(struct ftl_conn *api)
{
	return run_and_stream_command(api, "/usr/local/bin/pihole", (const char *const []){ "pihole", "-g", NULL });
}

int api_action_poweroff(struct ftl_conn *api)
{
	// Sync filesystems and power off
	sync();
	// Needs capabiliy CAP_SYS_BOOT
	if(reboot(RB_POWER_OFF) != 0)
		return send_json_error(api, 500,
		                       "server_error",
		                       "Cannot power off the system, power off has been cancelled",
		                       strerror(errno));
	return 200;
}

int api_action_reboot(struct ftl_conn *api)
{
	// Sync filesystems and reboot
	sync();
	// Needs capabiliy CAP_SYS_BOOT
	if(reboot(RB_AUTOBOOT) != 0)
		return send_json_error(api, 500,
		                       "server_error",
		                       "Cannot reboot the system, reboot has been cancelled",
		                       strerror(errno));
	return 200;
}
