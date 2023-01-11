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

#define DNSMASQ_01_PIHOLE "/tmp/etc_dnsmasq.d_01-pihole.conf"

static void write_config_header(FILE *fp)
{
	fputs("# Pi-hole: A black hole for Internet advertisements\n", fp);
	fputs("# (c) 2023 Pi-hole, LLC (https://pi-hole.net)\n", fp);
	fputs("# Network-wide ad blocking via your own hardware.\n", fp);
	fputs("#\n", fp);
	fputs("# Dnsmasq config for Pi-hole's FTLDNS\n", fp);
	fputs("#\n", fp);
	fputs("# This file is copyright under the latest version of the EUPL.\n", fp);
	fputs("# Please see LICENSE file for your rights under this license.\n", fp);
	fputc('\n', fp);
	fputs("###############################################################################\n", fp);
	fputs("#                  FILE AUTOMATICALLY POPULATED BY PI-HOLE                    #\n", fp);
	fputs("#  ANY CHANGES MADE TO THIS FILE WILL BE LOST WHEN THE CONFIGURATION CHANGES  #\n", fp);
	fputs("#                                                                             #\n", fp);
	fputs("#        IF YOU WISH TO CHANGE THE UPSTREAM SERVERS, CHANGE THEM IN:          #\n", fp);
	fputs("#                      /etc/pihole/pihole-FTL.toml                            #\n", fp);
	fputs("#                         and restart pihole-FTL                              #\n", fp);
	fputs("#                                                                             #\n", fp);
	fputs("#        ANY OTHER CHANGES SHOULD BE MADE IN A SEPARATE CONFIG FILE           #\n", fp);
	fputs("#                    WITHIN /etc/dnsmasq.d/yourname.conf                      #\n", fp);
	fputs("###############################################################################\n", fp);
	fputc('\n', fp);
}

bool __attribute__((const)) write_dnsmasq_config(bool test_config)
{
	FILE *pihole_conf = fopen(DNSMASQ_01_PIHOLE, "w");
	// Return early if opening failed
	if(!pihole_conf)
		return false;

	// Lock file, may block if the file is currently opened
	if(flock(fileno(pihole_conf), LOCK_EX) != 0)
	{
		log_err("Cannot open dnsmasq config file "DNSMASQ_01_PIHOLE" in exclusive mode: %s", strerror(errno));
		return false;
	}

	write_config_header(pihole_conf);
	fputs("# Additional hosts lists\n", pihole_conf);
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

	if(strlen(config.files.log.dnsmasq.v.s) > 0)
	{
		fputs("# Enable query logging\n", pihole_conf);
		fputs("log-queries\n", pihole_conf);
		fputs("log-async\n", pihole_conf);
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
			fputs("# Never forward A or AAAA queries for plain names, without \n", pihole_conf);
			fputs("# dots or domain parts, to upstream nameservers. If the name \n", pihole_conf);
			fputs("# is not known from /etc/hosts or DHCP a NXDOMAIN is returned. \n", pihole_conf);
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
	}

	// Unlock file
	if(flock(fileno(pihole_conf), LOCK_UN) != 0)
	{
		log_err("Cannot release lock on dnsmasq config file "DNSMASQ_01_PIHOLE": %s", strerror(errno));
		fclose(pihole_conf);
		return false;
	}

	// Close file
	if(fclose(pihole_conf) != 0)
	{
		log_err("Cannot close dnsmasq config file "DNSMASQ_01_PIHOLE": %s", strerror(errno));
		return false;
	}

	return true;
}
