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
#include "cJSON/cJSON.h"
// directory_exists()
#include "files.h"
// trim_whitespace()
#include "setupVars.h"

#define DNSMASQ_PH_CONFIG "/etc/pihole/dnsmasq.conf"
#define DNSMASQ_TEMP_CONF "/etc/pihole/dnsmasq.conf.temp"
#define DNSMASQ_STATIC_LEASES "/etc/pihole/04-pihole-static-dhcp.conf"

static bool test_dnsmasq_config(void)
{
	FILE *pipe = popen("pihole-FTL dnsmasq-test-file "DNSMASQ_TEMP_CONF, "r");
	if(!pipe)
	{
		log_err("Cannot open pipe to pihole-FTL dnsmasq-test-file: %s", strerror(errno));
		return false;
	}
	return WEXITSTATUS(pclose(pipe)) == EXIT_SUCCESS;
}

static void write_config_header(FILE *fp)
{
	fputs("# Pi-hole: A black hole for Internet advertisements\n", fp);
	fputs("# (c) 2023 Pi-hole, LLC (https://pi-hole.net)\n", fp);
	fputs("# Network-wide ad blocking via your own hardware.\n", fp);
	fputs("#\n", fp);
	fputs("# Dnsmasq config for Pi-hole's FTLDNS\n", fp);
	fputs("#\n", fp);
	fputs("# This file is copyright under the latest version of the EUPL.\n", fp);
	fputs("# Please see LICENSE file for your rights under this license.\n\n", fp);
	fputs("###############################################################################\n", fp);
	fputs("#                  FILE AUTOMATICALLY POPULATED BY PI-HOLE                    #\n", fp);
	fputs("#  ANY CHANGES MADE TO THIS FILE WILL BE LOST WHEN THE CONFIGURATION CHANGES  #\n", fp);
	fputs("#                                                                             #\n", fp);
	fputs("#        IF YOU WISH TO CHANGE THE UPSTREAM SERVERS, CHANGE THEM IN:          #\n", fp);
	fputs("#                      /etc/pihole/pihole-FTL.toml                            #\n", fp);
	fputs("#                         and restart pihole-FTL                              #\n", fp);
	fputs("#                                                                             #\n", fp);
	fputs("#                                                                             #\n", fp);
	fputs("#        ANY OTHER CHANGES SHOULD BE MADE IN A SEPARATE CONFIG FILE           #\n", fp);
	fputs("#                    WITHIN /etc/dnsmasq.d/yourname.conf                      #\n", fp);
	fputs("#                                                                             #\n", fp);
	char timestring[84] = "";
	get_timestr(timestring, time(NULL), false);
	fputs("#                      Last update: ", fp);
	fputs(timestring, fp);
	fputs("                       #\n", fp);
	fputs("###############################################################################\n\n", fp);
}

bool __attribute__((const)) write_dnsmasq_config(bool test_config)
{
	FILE *pihole_conf = fopen(DNSMASQ_TEMP_CONF, "w");
	// Return early if opening failed
	if(!pihole_conf)
	{
		log_err("Cannot open "DNSMASQ_TEMP_CONF" for writing, unable to update dnsmasq configuration: %s", strerror(errno));
		return false;
	}

	write_config_header(pihole_conf);
	fputs("addn-hosts=/etc/pihole/local.list\n", pihole_conf);
	fputs("addn-hosts=/etc/pihole/custom.list\n", pihole_conf);
	fputs("\n", pihole_conf);
	fputs("# Don't read /etc/resolv.conf. Get upstream servers only from the configuration\n", pihole_conf);
	fputs("no-resolv\n", pihole_conf);
	fputs("\n", pihole_conf);
	if(cJSON_GetArraySize(config.dnsmasq.upstreams.v.json) > 0)
	{
		fputs("# List of upstream DNS server\n", pihole_conf);
		const int n = cJSON_GetArraySize(config.dnsmasq.upstreams.v.json);
		for(int i = 0; i < n; i++)
		{
			cJSON *server = cJSON_GetArrayItem(config.dnsmasq.upstreams.v.json, i);
			if(server != NULL && cJSON_IsString(server))
				fprintf(pihole_conf, "server=%s\n", server->valuestring);
		}
		fputs("\n", pihole_conf);
	}
	fputs("# Set the size of dnsmasq's cache. The default is 150 names. Setting the cache\n", pihole_conf);
	fputs("# size to zero disables caching. Note: huge cache size impacts performance\n", pihole_conf);
	fprintf(pihole_conf, "cache-size=%u\n", config.dnsmasq.cache_size.v.ui);
	fputs("\n", pihole_conf);

	fputs("# Return answers to DNS queries from /etc/hosts and interface-name and\n", pihole_conf);
	fputs("# dynamic-host which depend on the interface over which the query was\n", pihole_conf);
	fputs("# received. If a name has more than one address associated with it, and\n", pihole_conf);
	fputs("# at least one of those addresses is on the same subnet as the interface\n", pihole_conf);
	fputs("# to which the query was sent, then return only the address(es) on that\n", pihole_conf);
	fputs("# subnet and return all the available addresses otherwise.\n", pihole_conf);
	fputs("localise-queries\n", pihole_conf);
	fputs("\n", pihole_conf);

	if(config.dnsmasq.logging.v.b)
	{
		fputs("# Enable query logging\n", pihole_conf);
		fputs("log-queries\n", pihole_conf);
		fputs("log-async\n", pihole_conf);
	}
	else
	{
		fputs("# Disable query logging\n", pihole_conf);
		fputs("#log-queries\n", pihole_conf);
		fputs("#log-async\n", pihole_conf);
	}

	if(strlen(config.files.log.dnsmasq.v.s) > 0)
	{
		fputs("# Specify the log file to use\n", pihole_conf);
		fputs("# We set this even if logging is disabled to store warnings\n", pihole_conf);
		fputs("# and errors in this file. This is useful for debugging.\n", pihole_conf);
		fprintf(pihole_conf, "log-facility=%s\n", config.files.log.dnsmasq.v.s);
		fputs("\n", pihole_conf);
	}

	if(config.dnsmasq.bogus_priv.v.b)
	{
		fputs("# Bogus private reverse lookups. All reverse lookups for private IP\n", pihole_conf);
		fputs("# ranges (ie 192.168.x.x, etc) which are not found in /etc/hosts or the\n", pihole_conf);
		fputs("# DHCP leases file are answered with NXDOMAIN rather than being forwarded\n", pihole_conf);
		fputs("bogus-priv\n", pihole_conf);
		fputs("\n", pihole_conf);
	}

	if(config.dnsmasq.domain_needed.v.b)
	{
		fputs("# Add the domain to simple names (without a period) in /etc/hosts in\n", pihole_conf);
		fputs("# the same way as for DHCP-derived names\n", pihole_conf);
		fputs("domain-needed\n", pihole_conf);
		fputs("\n", pihole_conf);
	}

	if(config.dnsmasq.expand_hosts.v.b)
	{
		fputs("# Never forward A or AAAA queries for plain names, without dots or\n", pihole_conf);
		fputs("# domain parts, to upstream nameservers\n", pihole_conf);
		fputs("expand-hosts\n", pihole_conf);
		fputs("\n", pihole_conf);
	}

	if(config.dnsmasq.dnssec.v.b)
	{
		fputs("# Use DNNSEC\n", pihole_conf);
		fputs("dnssec\n", pihole_conf);
		fputs("# 2017-02-02 root zone trust anchor\n", pihole_conf);
		fputs("trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n",
		      pihole_conf);
		fputs("\n", pihole_conf);
	}

	if(strlen(config.dnsmasq.domain.v.s) > 0 && strcasecmp("none", config.dnsmasq.domain.v.s) != 0)
	{
		fputs("# DNS domain for the DNS server\n", pihole_conf);
		fprintf(pihole_conf, "domain=%s\n", config.dnsmasq.domain.v.s);
		fputs("\n", pihole_conf);
		// When there is a Pi-hole domain set and "Never forward non-FQDNs" is
		// ticked, we add `local=/domain/` to signal that this domain is purely
		// local and FTL may answer queries from /etc/hosts or DHCP but should
		// never forward queries on that domain to any upstream servers
		if(config.dnsmasq.domain_needed.v.b)
		{
			fputs("# Never forward A or AAAA queries for plain names, without\n",pihole_conf);
			fputs("# dots or domain parts, to upstream nameservers. If the name\n", pihole_conf);
			fputs("# is not known from /etc/hosts or DHCP a NXDOMAIN is returned\n", pihole_conf);
				fprintf(pihole_conf, "local=/%s/\n",
				        config.dnsmasq.domain.v.s);
			fputs("\n", pihole_conf);
		}
	}

	if(strlen(config.dnsmasq.host_record.v.s) > 0)
	{
		fputs("# Add A, AAAA and PTR records to the DNS\n", pihole_conf);
		fprintf(pihole_conf, "host-record=%s\n", config.dnsmasq.host_record.v.s);
	}

	const char *interface = config.dnsmasq.interface.v.s;
	// Use eth0 as fallback interface if the interface is missing
	if(strlen(interface) == 0)
		interface = "eth0";

	switch(config.dnsmasq.listening_mode.v.listening_mode)
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
	}
	fputs("\n", pihole_conf);

	if(config.dnsmasq.rev_server.active.v.b)
	{
		fputs("# Reverse server setting\n", pihole_conf);
		fprintf(pihole_conf, "rev-server=%s,%s\n",
		        config.dnsmasq.rev_server.cidr.v.s, config.dnsmasq.rev_server.target.v.s);

		// If we have a reverse domain, we forward all queries to this domain to
		// the same destination
		if(strlen(config.dnsmasq.rev_server.domain.v.s) > 0)
			fprintf(pihole_conf, "server=/%s/%s\n",
			        config.dnsmasq.rev_server.domain.v.s, config.dnsmasq.rev_server.target.v.s);

		// Forward unqualified names to the target only when the "never forward
		// non-FQDN" option is NOT ticked
		if(!config.dnsmasq.domain_needed.v.b)
			fprintf(pihole_conf, "server=//%s\n",
			        config.dnsmasq.rev_server.target.v.s);
		fputs("\n", pihole_conf);
	}

	if(config.dnsmasq.dhcp.active.v.b)
	{
		fputs("# DHCP server setting\n", pihole_conf);
		fputs("dhcp-authoritative\n", pihole_conf);
		fputs("dhcp-leasefile=/etc/pihole/dhcp.leases\n", pihole_conf);
		fprintf(pihole_conf, "dhcp-range=%s,%s,%s\n",
		        config.dnsmasq.dhcp.start.v.s,
				config.dnsmasq.dhcp.end.v.s,
				config.dnsmasq.dhcp.leasetime.v.s);
		fprintf(pihole_conf, "dhcp-option=option:router,%s\n",
		        config.dnsmasq.dhcp.router.v.s);

		if(config.dnsmasq.dhcp.rapid_commit.v.b)
			fputs("dhcp-rapid-commit\n", pihole_conf);

		if(config.dnsmasq.dhcp.ipv6.v.b)
		{
			fputs("dhcp-option=option6:dns-server,[::]\n", pihole_conf);
			fprintf(pihole_conf, "dhcp-range=::,constructor:%s,ra-names,ra-stateless,64\n", interface);
		}
		fputs("\n", pihole_conf);
		if(cJSON_GetArraySize(config.dnsmasq.dhcp.hosts.v.json) > 0)
		{
			fputs("# Per host parameters for the DHCP server\n", pihole_conf);
			const int n = cJSON_GetArraySize(config.dnsmasq.dhcp.hosts.v.json);
			for(int i = 0; i < n; i++)
			{
				cJSON *server = cJSON_GetArrayItem(config.dnsmasq.dhcp.hosts.v.json, i);
				if(server != NULL && cJSON_IsString(server))
					fprintf(pihole_conf, "dhcp-host=%s\n", server->valuestring);
			}
			fputs("\n", pihole_conf);
		}
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
	fputs("# OpenWRT furthermore blocks    bind, local, onion    domains\n", pihole_conf);
	fputs("# see https://git.openwrt.org/?p=openwrt/openwrt.git;a=blob_plain;f=package/network/services/dnsmasq/files/rfc6761.conf;hb=HEAD\n", pihole_conf);
	fputs("# and https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml\n", pihole_conf);
	fputs("# We do not include the \".local\" rule ourselves, see https://github.com/pi-hole/pi-hole/pull/4282#discussion_r689112972\n", pihole_conf);
	fputs("server=/bind/\n", pihole_conf);
	fputs("server=/onion/\n", pihole_conf);

	if(directory_exists("/etc/dnsmasq.d"))
	{
		// Load possible additional user scripts from /etc/dnsmasq.d if
		// the directory exists (it may not, e.g., in a container)
		fputs("# Load possible additional user scripts\n", pihole_conf);
		fputs("conf-dir=/etc/dnsmasq.d\n", pihole_conf);
		fputs("\n", pihole_conf);
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

	if(test_config && !test_dnsmasq_config())
	{
		log_warn("New dnsmasq configuration is not valid, using previous one");
		return false;
	}

	if(rename(DNSMASQ_TEMP_CONF, DNSMASQ_PH_CONFIG) != 0)
	{
		log_err("Cannot install dnsmasq config file: %s", strerror(errno));
		return false;
	}

	// Close file
	if(fclose(pihole_conf) != 0)
	{
		log_err("Cannot close dnsmasq config file: %s", strerror(errno));
		return false;
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

		// Add entry to config.dnsmasq.dhcp.hosts
		cJSON *item = cJSON_CreateString(value);
		cJSON_AddItemToArray(config.dnsmasq.dhcp.hosts.v.json, item);

		log_debug(DEBUG_CONFIG, DNSMASQ_STATIC_LEASES": Setting %s[%d] = %s\n",
		          config.dnsmasq.dhcp.hosts.k, j++, item->valuestring);
	}

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
