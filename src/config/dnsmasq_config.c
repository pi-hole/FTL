/* Pi-hole: A black hole for Internet advertisements
*  (c) 2022 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq config writer routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "dnsmasq_config.h"
// logging routines
#include "log.h"
// get_blocking_mode_str()
#include "datastructure.h"
// flock(), LOCK_SH
#include <sys/file.h>
// struct config
#include "config/config.h"
// JSON array functions
#include "webserver/cJSON/cJSON.h"
// directory_exists()
#include "files.h"
// trim_whitespace()
#include "config/setupVars.h"
// run_dnsmasq_main()
#include "args.h"
// optind
#include <unistd.h>
// wait
#include <sys/wait.h>

#define HEADER_WIDTH 80

static bool test_dnsmasq_config(char errbuf[ERRBUF_SIZE])
{
	// Create a pipe for communication with our child
	int pipefd[2];
	if(pipe(pipefd) !=0)
	{
		log_err("Cannot create pipe while testing new dnsmasq config: %s", strerror(errno));
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

		const char *argv[3];
		argv[0] = "X";
		argv[1] = "--conf-file="DNSMASQ_TEMP_CONF;
		argv[2] = "--test";

		// Disable logging
		log_ctrl(false, false);

		// Flush STDERR
		fflush(stderr);

		// Redirect STDERR into our pipe
		dup2(pipefd[1], STDERR_FILENO);

		// Call dnsmasq's option parser
		test_dnsmasq_options(3, argv);

		// We'll never actually reach this point as test_dnsmasq_options() will
		// exit. We still close the fork nicely in case other stumble upon this
		// code and want to use it in their projects

		// Close the writing end of the pipe, thus sending EOF to the reader
		close(pipefd[1]);

		// Exit the fork
		exit(EXIT_SUCCESS);
	}
	else
	{
		/*** PARENT ***/
		// Close the writing end of the pipe
		close(pipefd[1]);

		// Read readirected STDERR until EOF
		if(errbuf != NULL)
		{
			// We are only interested in the last pipe line
			while(read(pipefd[0], errbuf, ERRBUF_SIZE) > 0)
			{
				// Remove initial newline character (if present)
				if(errbuf[0] == '\n')
					memmove(errbuf, &errbuf[1], ERRBUF_SIZE-1);
				// Strip newline character (if present)
				if(errbuf[strlen(errbuf)-1] == '\n')
					errbuf[strlen(errbuf)-1] = '\0';
				// Replace any possible internal newline characters by spaces
				char *ptr = errbuf;
				while((ptr = strchr(ptr, '\n')) != NULL)
					*ptr = ' ';
				log_debug(DEBUG_CONFIG, "dnsmasq pipe: %s", errbuf);
			}
		}

		// Wait until child has exited to get its return code
		int status;
		waitpid(cpid, &status, 0);

		// Get return code if child exited normally
		if(WIFEXITED(status))
			code = WEXITSTATUS(status);

		// Check if child crashed
		if(WIFSIGNALED(status))
		{
			crashed = true;
			log_err("dnsmasq test failed with signal %d %s",
			        WTERMSIG(status),
			        WCOREDUMP(status) ? "(core dumped)" : "");
		}

		if(code != EXIT_SUCCESS)
		{
			int lineno = get_lineno_from_string(errbuf);
			if(lineno > 0)
			{
				const size_t errbuf_size = strlen(errbuf);
				char *line = get_dnsmasq_line(lineno);
				// Append line to error message
				snprintf(errbuf+errbuf_size, ERRBUF_SIZE-errbuf_size, ": \"%s\"", line);
				free(line);
			}
		}

		log_debug(DEBUG_CONFIG, "Code: %d", code);

		// Close the reading end of the pipe
		close(pipefd[0]);
	}

	return code == EXIT_SUCCESS && !crashed;
}

int get_lineno_from_string(const char *string)
{
	int lineno = -1;
	char *ptr = strstr(string, " at line ");
	if(ptr == NULL)
		return -1;
	if(sscanf(ptr, " at line %d of ", &lineno) == 1)
		return lineno;
	else
		return -1;
}

char *get_dnsmasq_line(const unsigned int lineno)
{
	// Open temporary file
	FILE *fp = fopen(DNSMASQ_TEMP_CONF, "r");
	if (fp == NULL)
	{
		log_warn("Cannot read "DNSMASQ_TEMP_CONF);
		return NULL;
	}

	// Read file line-by-line until we reach the requested line
	char *linebuffer = NULL;
	size_t size = 0u;
	unsigned int count = 1;
	while(getline(&linebuffer, &size, fp) != -1)
	{
		if (count == lineno)
		{
			fclose(fp);
			// Strip newline characters (if present)
			while(strlen(linebuffer) > 0 && linebuffer[strlen(linebuffer)-1] == '\n')
				linebuffer[strlen(linebuffer)-1] = '\0';
			return linebuffer;
		}
		else
			count++;
	}
	fclose(fp);
	return NULL;
}

static void write_config_header(FILE *fp, const char *description)
{
	const time_t now = time(NULL);
	char timestring[TIMESTR_SIZE] = "";
	get_timestr(timestring, now, false, false);
	fputs("# Pi-hole: A black hole for Internet advertisements\n", fp);
	fprintf(fp, "# (c) %u Pi-hole, LLC (https://pi-hole.net)\n", get_year(now));
	fputs("# Network-wide ad blocking via your own hardware.\n", fp);
	fputs("#\n", fp);
	fputs("# ", fp);
	fputs(description, fp);
	fputs("\n", fp);
	fputs("#\n", fp);
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "################################################################################");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "FILE AUTOMATICALLY POPULATED BY PI-HOLE");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "ANY CHANGES MADE TO THIS FILE WILL BE LOST WHEN THE CONFIGURATION CHANGES");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "IF YOU WISH TO CHANGE ANY OF THESE VALUES, CHANGE THEM IN");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "/etc/pihole/pihole.toml");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "and restart pihole-FTL");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "ANY OTHER CHANGES SHOULD BE MADE IN A SEPARATE CONFIG FILE");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "WITHIN /etc/dnsmasq.d/yourname.conf");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "(make sure misc.etc_dnsmasq_d is set to true in /etc/pihole/pihole.toml)");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "");
	CONFIG_CENTER(fp, HEADER_WIDTH, "Last updated: %s", timestring);
	CONFIG_CENTER(fp, HEADER_WIDTH, "by FTL version %s", get_FTL_version());
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "");
	CONFIG_CENTER(fp, HEADER_WIDTH, "%s", "################################################################################");
}

bool __attribute__((const)) write_dnsmasq_config(struct config *conf, bool test_config, char errbuf[ERRBUF_SIZE])
{
	// Early config checks
	if(conf->dhcp.active.v.b)
	{
		// Check if the addresses are valid
		// The addresses should neither be 0.0.0.0 nor 255.255.255.255
		if((ntohl(conf->dhcp.start.v.in_addr.s_addr) == 0) ||
		   (ntohl(conf->dhcp.start.v.in_addr.s_addr) == 0xFFFFFFFF))
		{
			strncpy(errbuf, "DHCP start address is not valid", ERRBUF_SIZE);
			log_err("Unable to update dnsmasq configuration: %s", errbuf);
			return false;
		}
		if((ntohl(conf->dhcp.end.v.in_addr.s_addr) == 0) ||
		   (ntohl(conf->dhcp.end.v.in_addr.s_addr) == 0xFFFFFFFF))
		{
			strncpy(errbuf, "DHCP end address is not valid", ERRBUF_SIZE);
			log_err("Unable to update dnsmasq configuration: %s", errbuf);
			return false;
		}
		if((ntohl(conf->dhcp.router.v.in_addr.s_addr) == 0) ||
		   (ntohl(conf->dhcp.router.v.in_addr.s_addr) == 0xFFFFFFFF))
		{
			strncpy(errbuf, "DHCP router address is not valid", ERRBUF_SIZE);
			log_err("Unable to update dnsmasq configuration: %s", errbuf);
			return false;
		}
		// The addresses should neither end in .0 or .255 in the last octet
		if((ntohl(conf->dhcp.start.v.in_addr.s_addr) & 0xFF) == 0 ||
		   (ntohl(conf->dhcp.start.v.in_addr.s_addr) & 0xFF) == 0xFF)
		{
			strncpy(errbuf, "DHCP start address is not valid", ERRBUF_SIZE);
			log_err("Unable to update dnsmasq configuration: %s", errbuf);
			return false;
		}
		if((ntohl(conf->dhcp.end.v.in_addr.s_addr) & 0xFF) == 0 ||
		   (ntohl(conf->dhcp.end.v.in_addr.s_addr) & 0xFF) == 0xFF)
		{
			strncpy(errbuf, "DHCP end address is not valid", ERRBUF_SIZE);
			log_err("Unable to update dnsmasq configuration: %s", errbuf);
			return false;
		}
		if((ntohl(conf->dhcp.router.v.in_addr.s_addr) & 0xFF) == 0 ||
		   (ntohl(conf->dhcp.router.v.in_addr.s_addr) & 0xFF) == 0xFF)
		{
			strncpy(errbuf, "DHCP router address is not valid", ERRBUF_SIZE);
			log_err("Unable to update dnsmasq configuration: %s", errbuf);
			return false;
		}

		// Check if the DHCP range is valid (start needs to be smaller than end)
		if(ntohl(conf->dhcp.start.v.in_addr.s_addr) >= ntohl(conf->dhcp.end.v.in_addr.s_addr))
		{
			strncpy(errbuf, "DHCP range start address is larger than or equal to the end address", ERRBUF_SIZE);
			log_err("Unable to update dnsmasq configuration: %s", errbuf);
			return false;
		}

		// Check if the router address is within the DHCP range
		if(ntohl(conf->dhcp.router.v.in_addr.s_addr) >= ntohl(conf->dhcp.start.v.in_addr.s_addr) &&
		   ntohl(conf->dhcp.router.v.in_addr.s_addr) <= ntohl(conf->dhcp.end.v.in_addr.s_addr))
		{
			strncpy(errbuf, "DHCP router address should not be within DHCP range", ERRBUF_SIZE);
			log_err("Unable to update dnsmasq configuration: %s", errbuf);
			return false;
		}
	}

	log_debug(DEBUG_CONFIG, "Opening "DNSMASQ_TEMP_CONF" for writing");
	FILE *pihole_conf = fopen(DNSMASQ_TEMP_CONF, "w");
	// Return early if opening failed
	if(!pihole_conf)
	{
		log_err("Cannot open "DNSMASQ_TEMP_CONF" for writing, unable to update dnsmasq configuration: %s", strerror(errno));
		return false;
	}

	// Lock file, may block if the file is currently opened
	if(flock(fileno(pihole_conf), LOCK_EX) != 0)
	{
		log_err("Cannot open "DNSMASQ_TEMP_CONF" in exclusive mode: %s", strerror(errno));
		fclose(pihole_conf);
		return false;
	}

	write_config_header(pihole_conf, "Dnsmasq config for Pi-hole's FTLDNS");
	fputs("hostsdir="DNSMASQ_HOSTSDIR"\n", pihole_conf);
	fputs("\n", pihole_conf);
	fputs("# Don't read /etc/resolv.conf. Get upstream servers only from the configuration\n", pihole_conf);
	fputs("no-resolv\n", pihole_conf);
	fputs("\n", pihole_conf);
	fputs("# DNS port to be used\n", pihole_conf);
	fprintf(pihole_conf, "port=%u\n", conf->dns.port.v.u16);
	fputs("\n", pihole_conf);
	if(cJSON_GetArraySize(conf->dns.upstreams.v.json) > 0)
	{
		fputs("# List of upstream DNS server\n", pihole_conf);
		const int n = cJSON_GetArraySize(conf->dns.upstreams.v.json);
		for(int i = 0; i < n; i++)
		{
			cJSON *server = cJSON_GetArrayItem(conf->dns.upstreams.v.json, i);
			if(server != NULL && cJSON_IsString(server))
				fprintf(pihole_conf, "server=%s\n", server->valuestring);
		}
		fputs("\n", pihole_conf);
	}
	fputs("# Set the size of dnsmasq's cache. The default is 150 names. Setting the cache\n", pihole_conf);
	fputs("# size to zero disables caching. Note: huge cache size impacts performance\n", pihole_conf);
	fprintf(pihole_conf, "cache-size=%u\n", conf->dns.cache.size.v.ui);
	fputs("\n", pihole_conf);

	fputs("# Return answers to DNS queries from /etc/hosts and interface-name and\n", pihole_conf);
	fputs("# dynamic-host which depend on the interface over which the query was\n", pihole_conf);
	fputs("# received. If a name has more than one address associated with it, and\n", pihole_conf);
	fputs("# at least one of those addresses is on the same subnet as the interface\n", pihole_conf);
	fputs("# to which the query was sent, then return only the address(es) on that\n", pihole_conf);
	fputs("# subnet and return all the available addresses otherwise.\n", pihole_conf);
	fputs("localise-queries\n", pihole_conf);
	fputs("\n", pihole_conf);

	if(conf->dns.queryLogging.v.b)
	{
		fputs("# Enable query logging\n", pihole_conf);
		if(conf->misc.extraLogging.v.b)
			fputs("log-queries=extra\n", pihole_conf);
		else
			fputs("log-queries\n", pihole_conf);
		fputs("log-async\n", pihole_conf);
		fputs("\n", pihole_conf);
	}
	else
	{
		fputs("# Disable query logging\n", pihole_conf);
		fputs("#log-queries\n", pihole_conf);
		fputs("#log-async\n", pihole_conf);
		fputs("\n", pihole_conf);
	}

	if(strlen(conf->files.log.dnsmasq.v.s) > 0)
	{
		fputs("# Specify the log file to use\n", pihole_conf);
		fputs("# We set this even if logging is disabled to store warnings\n", pihole_conf);
		fputs("# and errors in this file. This is useful for debugging.\n", pihole_conf);
		fprintf(pihole_conf, "log-facility=%s\n", conf->files.log.dnsmasq.v.s);
		fputs("\n", pihole_conf);
	}

	if(conf->dns.bogusPriv.v.b)
	{
		fputs("# Bogus private reverse lookups. All reverse lookups for private IP\n", pihole_conf);
		fputs("# ranges (ie 192.168.x.x, etc) which are not found in /etc/hosts or the\n", pihole_conf);
		fputs("# DHCP leases file are answered with NXDOMAIN rather than being forwarded\n", pihole_conf);
		fputs("bogus-priv\n", pihole_conf);
		fputs("\n", pihole_conf);
	}

	if(conf->dns.domainNeeded.v.b)
	{
		fputs("# Add the domain to simple names (without a period) in /etc/hosts in\n", pihole_conf);
		fputs("# the same way as for DHCP-derived names\n", pihole_conf);
		fputs("domain-needed\n", pihole_conf);
		fputs("\n", pihole_conf);
	}

	if(conf->dns.expandHosts.v.b)
	{
		fputs("# Never forward A or AAAA queries for plain names, without dots or\n", pihole_conf);
		fputs("# domain parts, to upstream nameservers\n", pihole_conf);
		fputs("expand-hosts\n", pihole_conf);
		fputs("\n", pihole_conf);
	}

	if(conf->dns.dnssec.v.b)
	{
		fputs("# Use DNNSEC\n", pihole_conf);
		fputs("dnssec\n", pihole_conf);
		fputs("# 2017-02-02 root zone trust anchor\n", pihole_conf);
		fputs("trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n",
		      pihole_conf);
		fputs("\n", pihole_conf);
	}

	if(strlen(conf->dns.hostRecord.v.s) > 0)
	{
		fputs("# Add A, AAAA and PTR records to the DNS\n", pihole_conf);
		fprintf(pihole_conf, "host-record=%s\n", conf->dns.hostRecord.v.s);
		fputs("\n", pihole_conf);
	}

	if(conf->dns.cache.optimizer.v.i > -1)
	{
		fputs("# Use stale cache entries for a given number of seconds to optimize cache utilization\n", pihole_conf);
		fputs("# Setting the time to zero will serve stale cache data regardless how long it has expired.\n", pihole_conf);
		fprintf(pihole_conf, "use-stale-cache=%i\n", conf->dns.cache.optimizer.v.i);
		fputs("\n", pihole_conf);
	}

	const char *interface = conf->dns.interface.v.s;
	// Use eth0 as fallback interface if the interface is missing
	if(strlen(interface) == 0)
		interface = "eth0";

	switch(conf->dns.listeningMode.v.listeningMode)
	{
		case LISTEN_LOCAL:
			fputs("# Only respond to queries from devices that are at most one hop away (local devices)\n",
			      pihole_conf);
			fputs("local-service\n", pihole_conf);
			break;
		case LISTEN_ALL:
			fputs("# Listen on all interfaces, permit all origins\n", pihole_conf);
			fputs("except-interface=nonexisting\n", pihole_conf);
			break;
		case LISTEN_SINGLE:
			fputs("# Listen on one interface\n", pihole_conf);
			fprintf(pihole_conf, "interface=%s\n", interface);
			break;
		case LISTEN_BIND:
			fputs("# Bind to one interface\n", pihole_conf);
			fprintf(pihole_conf, "interface=%s\n", interface);
			fputs("bind-interfaces\n", pihole_conf);
			break;
		case LISTEN_NONE:
			fputs("# No interface configuration applied, make sure to cover this yourself\n", pihole_conf);
			break;
	}
	fputs("\n", pihole_conf);

	const unsigned int revServers = cJSON_GetArraySize(conf->dns.revServers.v.json);
	for(unsigned int i = 0; i < revServers; i++)
	{
		cJSON *revServer = cJSON_GetArrayItem(conf->dns.revServers.v.json, i);

		// Split comma-separated string into its components
		char *copy = strdup(revServer->valuestring);
		char *active = strtok(copy, ",");
		char *cidr = strtok(NULL, ",");
		char *target = strtok(NULL, ",");
		char *domain = strtok(NULL, ",");

		// Skip inactive reverse servers
		if(active != NULL &&
		   strcmp(active, "true") != 0 &&
		   strcmp(active, "1") != 0)
		{
			log_debug(DEBUG_CONFIG, "Skipping inactive reverse server: %s", revServer->valuestring);
			free(copy);
			continue;
		}

		if(active == NULL || cidr == NULL || target == NULL || domain == NULL)
		{
			log_err("Skipped invalid dns.revServers[%u]: %s", i, revServer->valuestring);
			free(copy);
			continue;
		}

		fprintf(pihole_conf, "# Reverse server setting (%u%s server)\n",
		        i+1, get_ordinal_suffix(i+1));
		fprintf(pihole_conf, "rev-server=%s,%s\n", cidr, target);

		// If we have a reverse domain, we forward all queries to this domain to
		// the same destination
		if(strlen(domain) > 0)
			fprintf(pihole_conf, "server=/%s/%s\n", domain, target);

		// Forward unqualified names to the target only when the "never forward
		// non-FQDN" option is NOT ticked
		if(!conf->dns.domainNeeded.v.b)
			fprintf(pihole_conf, "server=//%s\n", target);
		fputs("\n", pihole_conf);

		// Free copy of string
		free(copy);
	}

	// When there is a Pi-hole domain set and "Never forward non-FQDNs" is
	// ticked, we add `local=/domain/` to signal that this domain is purely
	// local and FTL may answer queries from /etc/hosts or DHCP but should
	// never forward queries on that domain to any upstream servers
	if(conf->dns.domainNeeded.v.b)
	{
		fputs("# Never forward A or AAAA queries for plain names, without\n",pihole_conf);
		fputs("# dots or domain parts, to upstream nameservers. If the name\n", pihole_conf);
		fputs("# is not known from /etc/hosts or DHCP a NXDOMAIN is returned\n", pihole_conf);
		if(strlen(conf->dns.domain.v.s))
			fprintf(pihole_conf, "local=/%s/\n\n", conf->dns.domain.v.s);
		else
			fputs("\n", pihole_conf);
	}

	// Add domain to DNS server. It will also be used for DHCP if the DHCP
	// server is enabled below
	if(strlen(conf->dns.domain.v.s) > 0)
	{
		fputs("# DNS domain for both the DNS and DHCP server\n", pihole_conf);
		fprintf(pihole_conf, "domain=%s\n\n", conf->dns.domain.v.s);
	}

	if(conf->dhcp.active.v.b)
	{
		fputs("# DHCP server setting\n", pihole_conf);
		fputs("dhcp-authoritative\n", pihole_conf);
		fputs("dhcp-leasefile="DHCPLEASESFILE"\n", pihole_conf);
		char start[INET_ADDRSTRLEN] = { 0 },
		     end[INET_ADDRSTRLEN] = { 0 },
		     router[INET_ADDRSTRLEN] = { 0 };
		inet_ntop(AF_INET, &conf->dhcp.start.v.in_addr, start, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &conf->dhcp.end.v.in_addr, end, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &conf->dhcp.router.v.in_addr, router, INET_ADDRSTRLEN);
		fprintf(pihole_conf, "dhcp-range=%s,%s", start, end);
		// Net mask is optional, only add if it is not 0.0.0.0
		const struct in_addr inaddr_empty = {0};
		if(memcmp(&conf->dhcp.netmask.v.in_addr, &inaddr_empty, sizeof(inaddr_empty)) != 0)
		{
			char netmask[INET_ADDRSTRLEN] = { 0 };
			inet_ntop(AF_INET, &conf->dhcp.netmask.v.in_addr, netmask, INET_ADDRSTRLEN);
			fprintf(pihole_conf, ",%s", netmask);
		}
		// Lease time is optional, only add it if it is set
		if(strlen(conf->dhcp.leaseTime.v.s) > 0)
			fprintf(pihole_conf, ",%s", conf->dhcp.leaseTime.v.s);
		fprintf(pihole_conf, "\ndhcp-option=option:router,%s\n", router);

		if(conf->dhcp.rapidCommit.v.b)
			fputs("dhcp-rapid-commit\n", pihole_conf);

		if(conf->dhcp.multiDNS.v.b)
		{
			// The address 0.0.0.0 has the special meaning to take
			// the address of the interface on which the DHCP
			// request was received. Similarly, :: has the special
			// meaning to take the global address of the interface
			// on which the DHCP request was received for IPv6,
			// whilst [fd00::] is replaced with the ULA, if it
			// exists, and [fe80::] with the link-local address.
			fputs("# Advertise the DNS server multiple times to work around\n", pihole_conf);
			fputs("# issues with some clients adding their own servers if only\n", pihole_conf);
			fputs("# one DNS server is advertised by the DHCP server.\n", pihole_conf);
			fputs("dhcp-option=option:dns-server,0.0.0.0,0.0.0.0,0.0.0.0\n", pihole_conf);
		}

		if(conf->dhcp.ipv6.v.b)
		{
			// Add dns-server option only if not already done above (dhcp.multiDNS)
			if(conf->dhcp.multiDNS.v.b)
				fputs("dhcp-option=option6:dns-server,[::],[::],[fd00::],[fd00::],[fe80::],[fe80::]\n", pihole_conf);
			else
				fputs("dhcp-option=option6:dns-server,[::]\n", pihole_conf);
			fputs("# Enable IPv6 DHCP variant\n", pihole_conf);
			fprintf(pihole_conf, "dhcp-range=::,constructor:%s,ra-names,ra-stateless,64\n", interface);
		}
		fputs("\n", pihole_conf);

		// Enable DHCP logging if requested
		if(conf->dhcp.logging.v.b)
		{
			fputs("# Enable DHCP logging\n", pihole_conf);
			fputs("log-dhcp\n\n", pihole_conf);
		}

		// Add per-host parameters
		if(cJSON_GetArraySize(conf->dhcp.hosts.v.json) > 0)
		{
			fputs("# Per host parameters for the DHCP server\n", pihole_conf);
			const int n = cJSON_GetArraySize(conf->dhcp.hosts.v.json);
			for(int i = 0; i < n; i++)
			{
				cJSON *server = cJSON_GetArrayItem(conf->dhcp.hosts.v.json, i);
				if(server != NULL && cJSON_IsString(server))
					fprintf(pihole_conf, "dhcp-host=%s\n", server->valuestring);
			}
			fputs("\n", pihole_conf);
		}
	}

	if(cJSON_GetArraySize(conf->dns.cnameRecords.v.json) > 0)
	{
		fputs("# User-defined custom CNAMEs\n", pihole_conf);
		const int n = cJSON_GetArraySize(conf->dns.cnameRecords.v.json);
		for(int i = 0; i < n; i++)
		{
			cJSON *server = cJSON_GetArrayItem(conf->dns.cnameRecords.v.json, i);
			if(server != NULL && cJSON_IsString(server))
				fprintf(pihole_conf, "cname=%s\n", server->valuestring);
		}
		fputs("\n", pihole_conf);
	}

	fputs("# RFC 6761: Caching DNS servers SHOULD recognize\n", pihole_conf);
	fputs("#     test, localhost, invalid\n", pihole_conf);
	fputs("# names as special and SHOULD NOT attempt to look up NS records for them, or\n", pihole_conf);
	fputs("# otherwise query authoritative DNS servers in an attempt to resolve these\n", pihole_conf);
	fputs("# names.\n", pihole_conf);
	fputs("server=/test/\n", pihole_conf);
	fputs("server=/localhost/\n", pihole_conf);
	fputs("server=/invalid/\n", pihole_conf);
	fputs("\n", pihole_conf);
	fputs("# The same RFC requests something similar for\n", pihole_conf);
	fputs("#     10.in-addr.arpa.      21.172.in-addr.arpa.  27.172.in-addr.arpa.\n", pihole_conf);
	fputs("#     16.172.in-addr.arpa.  22.172.in-addr.arpa.  28.172.in-addr.arpa.\n", pihole_conf);
	fputs("#     17.172.in-addr.arpa.  23.172.in-addr.arpa.  29.172.in-addr.arpa.\n", pihole_conf);
	fputs("#     18.172.in-addr.arpa.  24.172.in-addr.arpa.  30.172.in-addr.arpa.\n", pihole_conf);
	fputs("#     19.172.in-addr.arpa.  25.172.in-addr.arpa.  31.172.in-addr.arpa.\n", pihole_conf);
	fputs("#     20.172.in-addr.arpa.  26.172.in-addr.arpa.  168.192.in-addr.arpa.\n", pihole_conf);
	fputs("# Pi-hole implements this via the dnsmasq option \"bogus-priv\" above\n", pihole_conf);
	fputs("# (if enabled!) as this option also covers IPv6.\n", pihole_conf);
	fputs("\n", pihole_conf);
	fputs("# OpenWRT furthermore blocks bind, local, onion domains\n", pihole_conf);
	fputs("# see https://git.openwrt.org/?p=openwrt/openwrt.git;a=blob_plain;f=package/network/services/dnsmasq/files/rfc6761.conf;hb=HEAD\n", pihole_conf);
	fputs("# and https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml\n", pihole_conf);
	fputs("# We do not include the \".local\" rule ourselves, see https://github.com/pi-hole/pi-hole/pull/4282#discussion_r689112972\n", pihole_conf);
	fputs("server=/bind/\n", pihole_conf);
	fputs("server=/onion/\n", pihole_conf);
	fputs("\n", pihole_conf);

	if(directory_exists("/etc/dnsmasq.d") && conf->misc.etc_dnsmasq_d.v.b)
	{
		// Load additional user scripts from /etc/dnsmasq.d if the
		// directory exists (it may not, e.g., in a container)
		fputs("# Load additional user scripts\n", pihole_conf);
		fputs("conf-dir=/etc/dnsmasq.d\n", pihole_conf);
		fputs("\n", pihole_conf);
	}

	// Add option for caching all DNS records
	fputs("# Cache all DNS records\n", pihole_conf);
	fputs("cache-rr=ANY\n", pihole_conf);
	fputs("\n", pihole_conf);

	// Add option for PCAP file recording
	if(strlen(conf->files.pcap.v.s) > 0)
	{
		if(file_writeable(conf->files.pcap.v.s))
		{
			fputs("# PCAP network traffic recording\n", pihole_conf);
			fprintf(pihole_conf, "dumpmask=0xFFFF\n");
			fprintf(pihole_conf, "dumpfile=%s\n", conf->files.pcap.v.s);
			fputs("\n", pihole_conf);
		}
		else
		{
			log_err("Cannot write to %s, disabling PCAP recording", conf->files.pcap.v.s);
		}
	}

	// Add ANY filtering
	fputs("# RFC 8482: Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY\n", pihole_conf);
	fputs("# Filters replies to queries for type ANY. Everything other than A, AAAA, MX and CNAME\n", pihole_conf);
	fputs("# records are removed. Since ANY queries with forged source addresses can be used in DNS amplification attacks\n", pihole_conf);
	fputs("# replies to ANY queries can be large) this defangs such attacks, whilst still supporting the\n", pihole_conf);
	fputs("# one remaining possible use of ANY queries. See RFC 8482 para 4.3 for details.\n", pihole_conf);
	fputs("filter-rr=ANY\n", pihole_conf);
	fputs("\n", pihole_conf);

	// Add additional config lines to disk (if present)
	if(conf->misc.dnsmasq_lines.v.json != NULL &&
	   cJSON_GetArraySize(conf->misc.dnsmasq_lines.v.json) > 0)
	{
		fputs("#### Additional user configuration - START ####\n", pihole_conf);
		cJSON *line = NULL;
		cJSON_ArrayForEach(line, conf->misc.dnsmasq_lines.v.json)
		{
			if(line != NULL && cJSON_IsString(line))
			{
				fputs(line->valuestring, pihole_conf);
				fputc('\n', pihole_conf);
			}
		}
		fputs("#### Additional user configuration - END ####\n\n", pihole_conf);
	}

	// Flush config file to disk
	fflush(pihole_conf);

	// Unlock file
	if(flock(fileno(pihole_conf), LOCK_UN) != 0)
	{
		log_err("Cannot release lock on dnsmasq config file: %s", strerror(errno));
		fclose(pihole_conf);
		return false;
	}

	// Close file
	if(fclose(pihole_conf) != 0)
	{
		log_err("Cannot close dnsmasq config file: %s", strerror(errno));
		return false;
	}

	log_debug(DEBUG_CONFIG, "Testing "DNSMASQ_TEMP_CONF);
	if(test_config && !test_dnsmasq_config(errbuf))
	{
		log_warn("New dnsmasq configuration is not valid (%s), config remains unchanged", errbuf);

		// Remove temporary config file
		if(remove(DNSMASQ_TEMP_CONF) != 0)
		{
			log_err("Cannot remove temporary dnsmasq config file: %s", strerror(errno));
			return false;
		}

		return false;
	}

	// Check if the new config file is different from the old one
	// Skip the first 24 lines as they contain the header
	if(files_different(DNSMASQ_TEMP_CONF, DNSMASQ_PH_CONFIG, 24))
	{
		if(rename(DNSMASQ_TEMP_CONF, DNSMASQ_PH_CONFIG) != 0)
		{
			log_err("Cannot install dnsmasq config file: %s", strerror(errno));

			// Remove temporary config file
			if(remove(DNSMASQ_TEMP_CONF) != 0)
				log_err("Cannot remove temporary dnsmasq config file: %s", strerror(errno));

			return false;
		}

		log_debug(DEBUG_CONFIG, "Config file written to "DNSMASQ_PH_CONFIG);
	}
	else
	{
		log_debug(DEBUG_CONFIG, "dnsmasq.conf unchanged");
		// Remove temporary config file
		if(remove(DNSMASQ_TEMP_CONF) != 0)
		{
			log_err("Cannot remove temporary dnsmasq config file: %s", strerror(errno));
			return false;
		}
	}
	return true;
}

bool read_legacy_dhcp_static_config(void)
{
	// Check if file exists, if not, there is nothing to do
	const char *path = DNSMASQ_STATIC_LEASES;
	const char *target = DNSMASQ_STATIC_LEASES".bck";
	if(!file_exists(path))
		return true;

	FILE *fp = fopen(path, "r");
	if(!fp)
	{
		log_err("Cannot read %s for reading, unable to import static leases: %s",
		        path, strerror(errno));
		return false;
	}

	char *linebuffer = NULL;
	size_t size = 0u;
	errno = 0;
	unsigned int j = 0;
	while(getline(&linebuffer, &size, fp) != -1)
	{
		// Check if memory allocation failed
		if(linebuffer == NULL)
			break;

		// Skip lines with other keys
		if((strstr(linebuffer, "dhcp-host=")) == NULL)
			continue;

		// Note: value is still a pointer into the linebuffer
		char *value = find_equals(linebuffer) + 1;
		// Trim whitespace at beginning and end, this function
		// modifies the string inplace
		trim_whitespace(value);

		// Add entry to config.dhcp.hosts
		cJSON *item = cJSON_CreateString(value);
		cJSON_AddItemToArray(config.dhcp.hosts.v.json, item);

		log_debug(DEBUG_CONFIG, DNSMASQ_STATIC_LEASES": Setting %s[%u] = %s\n",
		          config.dhcp.hosts.k, j++, item->valuestring);
	}

	// Free allocated memory
	free(linebuffer);

	// Close file
	if(fclose(fp) != 0)
	{
		log_err("Cannot close %s: %s", path, strerror(errno));
		return false;
	}

	// Move file to backup location
	log_info("Moving %s to %s", path, target);
	if(rename(path, target) != 0)
		log_warn("Unable to move %s to %s: %s", path, target, strerror(errno));

	return true;
}


bool read_legacy_cnames_config(void)
{
	// Check if file exists, if not, there is nothing to do
	const char *path = DNSMASQ_CNAMES;
	const char *target = DNSMASQ_CNAMES".bck";
	if(!file_exists(path))
		return true;

	FILE *fp = fopen(path, "r");
	if(!fp)
	{
		log_err("Cannot read %s for reading, unable to import list of custom cnames: %s",
		        path, strerror(errno));
		return false;
	}

	char *linebuffer = NULL;
	size_t size = 0u;
	errno = 0;
	unsigned int j = 0;
	while(getline(&linebuffer, &size, fp) != -1)
	{
		// Check if memory allocation failed
		if(linebuffer == NULL)
			break;

		// Skip lines with other keys
		if((strstr(linebuffer, "cname=")) == NULL)
			continue;

		// Note: value is still a pointer into the linebuffer
		char *value = find_equals(linebuffer) + 1;
		// Trim whitespace at beginning and end, this function
		// modifies the string inplace
		trim_whitespace(value);

		// Add entry to config.dns.cnameRecords
		cJSON *item = cJSON_CreateString(value);
		cJSON_AddItemToArray(config.dns.cnameRecords.v.json, item);

		log_debug(DEBUG_CONFIG, DNSMASQ_CNAMES": Setting %s[%u] = %s\n",
		          config.dns.cnameRecords.k, j++, item->valuestring);
	}

	// Free allocated memory
	free(linebuffer);

	// Close file
	if(fclose(fp) != 0)
	{
		log_err("Cannot close %s: %s", path, strerror(errno));
		return false;
	}

	// Move file to backup location
	log_info("Moving %s to %s", path, target);
	if(rename(path, target) != 0)
		log_warn("Unable to move %s to %s: %s", path, target, strerror(errno));

	return true;
}

bool read_legacy_custom_hosts_config(void)
{
	// Check if file exists, if not, there is nothing to do
	const char *path = DNSMASQ_CUSTOM_LIST_LEGACY;
	const char *target = DNSMASQ_CUSTOM_LIST_LEGACY".bck";
	if(!file_exists(path))
		return true;

	FILE *fp = fopen(path, "r");
	if(!fp)
	{
		log_err("Cannot read %s for reading, unable to import list of custom cnames: %s",
		        path, strerror(errno));
		return false;
	}

	char *linebuffer = NULL;
	size_t size = 0u;
	errno = 0;
	while(getline(&linebuffer, &size, fp) != -1)
	{
		// Check if memory allocation failed
		if(linebuffer == NULL)
			break;

		// Import lines in the file
		// Trim whitespace at beginning and end, this function
		// modifies the string inplace
		trim_whitespace(linebuffer);

		// Skip empty lines
		if(strlen(linebuffer) == 0 ||
		   linebuffer[0] == '\n' ||
		   linebuffer[0] == '\r' ||
		   linebuffer[0] == '\0')
			continue;

		// Skip comments
		if(linebuffer[0] == '#')
			continue;

		// Add entry to config.dns.hosts
		cJSON *item = cJSON_CreateString(linebuffer);
		cJSON_AddItemToArray(config.dns.hosts.v.json, item);
	}

	// Free allocated memory
	free(linebuffer);

	// Close file
	if(fclose(fp) != 0)
	{
		log_err("Cannot close %s: %s", path, strerror(errno));
		return false;
	}

	// Move file to backup location
	log_info("Moving %s to %s", path, target);
	if(rename(path, target) != 0)
		log_warn("Unable to move %s to %s: %s", path, target, strerror(errno));

	return true;
}

bool write_custom_list(void)
{
	// Ensure that the directory exists
	if(!directory_exists(DNSMASQ_HOSTSDIR))
	{
		log_debug(DEBUG_CONFIG, "Creating directory "DNSMASQ_HOSTSDIR);
		if(mkdir(DNSMASQ_HOSTSDIR, 0755) != 0)
		{
			log_err("Cannot create directory "DNSMASQ_HOSTSDIR": %s", strerror(errno));
			return false;
		}
	}

	log_debug(DEBUG_CONFIG, "Opening "DNSMASQ_CUSTOM_LIST_LEGACY".tmp for writing");
	FILE *custom_list = fopen(DNSMASQ_CUSTOM_LIST_LEGACY".tmp", "w");
	// Return early if opening failed
	if(!custom_list)
	{
		log_err("Cannot open "DNSMASQ_CUSTOM_LIST_LEGACY".tmp for writing, unable to update custom.list: %s", strerror(errno));
		return false;
	}

	// Lock file, may block if the file is currently opened
	if(flock(fileno(custom_list), LOCK_EX) != 0)
	{
		log_err("Cannot open "DNSMASQ_CUSTOM_LIST_LEGACY".tmp in exclusive mode: %s", strerror(errno));
		fclose(custom_list);
		return false;
	}

	write_config_header(custom_list, "Custom DNS entries (HOSTS file)");
	fputc('\n', custom_list);

	const int N = cJSON_GetArraySize(config.dns.hosts.v.json);
	if(N > 0)
	{
		for(int i = 0; i < N; i++)
		{
			cJSON *entry = cJSON_GetArrayItem(config.dns.hosts.v.json, i);
			if(entry != NULL && cJSON_IsString(entry))
				fprintf(custom_list, "%s\n", entry->valuestring);
		}
		fputc('\n', custom_list);
	}

	if(N == 1)
		fprintf(custom_list, "\n# There is %d entry in this file\n", N);
	else if(N > 1)
		fprintf(custom_list, "\n# There are %d entries in this file\n", N);
	else if(N == 0)
		fputs("\n# There are currently no entries in this file\n", custom_list);

	// Unlock file
	if(flock(fileno(custom_list), LOCK_UN) != 0)
	{
		log_err("Cannot release lock on custom.list: %s", strerror(errno));
		fclose(custom_list);
		return false;
	}

	// Close file
	if(fclose(custom_list) != 0)
	{
		log_err("Cannot close custom.list: %s", strerror(errno));
		return false;
	}

	// Check if the new config file is different from the old one
	// Skip the first 24 lines as they contain the header
	if(files_different(DNSMASQ_CUSTOM_LIST_LEGACY".tmp", DNSMASQ_CUSTOM_LIST, 24))
	{
		if(rename(DNSMASQ_CUSTOM_LIST_LEGACY".tmp", DNSMASQ_CUSTOM_LIST) != 0)
		{
			log_err("Cannot install custom.list: %s", strerror(errno));
			return false;
		}
		log_debug(DEBUG_CONFIG, "HOSTS file written to "DNSMASQ_CUSTOM_LIST);
	}
	else
	{
		log_debug(DEBUG_CONFIG, "custom.list unchanged");
		// Remove temporary config file
		if(remove(DNSMASQ_CUSTOM_LIST_LEGACY".tmp") != 0)
		{
			log_err("Cannot remove temporary custom.list: %s", strerror(errno));
			return false;
		}
	}

	return true;
}
