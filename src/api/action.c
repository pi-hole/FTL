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
// exit_code
#include "signals.h"
// flush_network_table()
#include "database/network-table.h"
#include "config/config.h"
// gravity_running
#include "daemon.h"

static int run_and_stream_command(struct ftl_conn *api, const char *path, const char *const args[], const char *extra_env)
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

		// Set extra environment variable if requested
		if(extra_env != NULL)
			setenv(extra_env, "1", 1);

		// Detach child into its own session/process group so signals
		// sent to the parent's process group (like SIGTERM) do not
		// propagate to this child.
		(void)setsid();

		// Ignore SIGTERM so systemd's cgroup-level kill (the
		// default KillMode=control-group sends SIGTERM to ALL
		// processes in the cgroup) doesn't terminate gravity
		// mid-run. SIG_IGN is preserved across execv(), unlike
		// custom handlers which are reset to SIG_DFL.
		signal(SIGTERM, SIG_IGN);

		// Run pihole -g
		execv(path, (char *const *)args);

		// execv() only returns if it failed, so the command never ran.
		// Exit non-zero so the parent reports the action as failed.
		exit(EXIT_FAILURE);
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
		ssize_t nread;
		while((nread = read(pipefd[0], errbuf, sizeof(errbuf) - 1)) > 0)
		{
			// NUL-terminate what we just read so the string
			// operations below cannot read past the buffer
			errbuf[nread] = '\0';
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

		log_web_debug(DEBUG_API, "Gravity return code: %d", code);

		// Close the reading end of the pipe
		close(pipefd[0]);
	}

	// Send final chunk of size 0 showing end of data
	mg_printf(api->conn, "0\r\n\r\n");

	if(code == EXIT_SUCCESS && !crashed)
		return send_json_success(api);
	else
		return send_json_error(api, 500,
		                       "server_error",
		                       "Gravity failed",
		                       NULL);
}

int api_action_gravity(struct ftl_conn *api)
{
	// Only set FORCE_COLOR if the client explicitly requests it via "color=true" query parameter
	// This prevents ANSI escape codes from being included in the output for API consumers that don't need them
	bool color = false;
	const char *query = api->request != NULL ? api->request->query_string : "";
	if(query != NULL)
		get_bool_var(query, "color", &color);

	const char *extra_env = color ? "FORCE_COLOR" : NULL;

	gravity_running = 1;
	const int ret = run_and_stream_command(api, "/usr/local/bin/pihole", (const char *const []){ "pihole", "-g", NULL }, extra_env);
	gravity_running = 0;

	// If a termination/restart was requested while gravity was running,
	// act on it now rather than waiting up to ~1s for the GC thread to pick it up
	check_if_want_terminate();

	return ret;
}

int api_action_restartDNS(struct ftl_conn *api)
{
	if(!config.webserver.api.allow_destructive.v.b)
		return send_json_error(api, 403,
		                       "forbidden",
		                       "Restarting DNS is not allowed",
		                       "Check setting webserver.api.allow_destructive");

	restart_ftl("API action request");

	return send_json_success(api);
}

int api_action_flush_logs(struct ftl_conn *api)
{
	if(!config.webserver.api.allow_destructive.v.b)
		return send_json_error(api, 403,
		                       "forbidden",
		                       "Flushing the logs is not allowed",
		                       "Check setting webserver.api.allow_destructive");

	log_web(LOG_INFO, "Received API request to flush the logs");

	// Flush the logs
	if(flush_dnsmasq_log())
		return send_json_success(api);
	else
		return send_json_error(api, 500,
		                       "server_error",
		                       "Cannot flush the logs",
		                       NULL);
}

int api_action_flush_network(struct ftl_conn *api)
{
	if(!config.webserver.api.allow_destructive.v.b)
		return send_json_error(api, 403,
		                       "forbidden",
		                       "Flushing the network tables is not allowed",
		                       "Check setting webserver.api.allow_destructive");

	log_web(LOG_INFO, "Received API request to flush the network tables");

	// Flush the network tables
	if(flush_network_table())
		return send_json_success(api);
	else
		return send_json_error(api, 500,
		                       "server_error",
		                       "Cannot flush the network tables",
		                       NULL);
}
