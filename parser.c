/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Log parsing routine
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

char *resolveHostname(char *addr);

int dnsmasqlogpos = 0;

int checkLogForChanges(void)
{
	// seek to the end of the file
	fseek(dnsmasqlog, 0L, SEEK_END);
	// ask for the position
	int pos = ftell(dnsmasqlog);
	if(pos > dnsmasqlogpos)
	{
		// Go back to to previous position
		fseek(dnsmasqlog, dnsmasqlogpos, SEEK_SET);
	}
	return (pos-dnsmasqlogpos);
}

void open_pihole_log(void)
{
	if((dnsmasqlog = fopen(files.log, "r")) == NULL) {
		logg("FATAL: Opening of pihole.log failed!");
		logg("       Make sure it exists and is readable");
		// Return failure in exit status
		exit(1);
	}
}

void *pihole_log_thread(void *val)
{
	prctl(PR_SET_NAME,"loganalyzer",0,0,0);
	while(!killed)
	{
		int newdata = checkLogForChanges();

		if(newdata != 0)
		{
			// Lock FTL's data structure, since it is likely that it will be changed here
			// Requests should not be processed/answered when data is about to change
			enable_lock("pihole_log_thread");

			if(newdata > 0)
			{
				// Process new data if found only in main log (file 0)
				process_pihole_log(0);
			}
			else if(newdata < 0)
			{
				// Process flushed log
				// Flush internal datastructure
				pihole_log_flushed(true);
				// Rescan files 0 (pihole.log) and 1 (pihole.log.1)
				initialscan = true;
				process_pihole_log(1);
				process_pihole_log(0);
				initialscan = false;
			}

			// Release thread lock
			disable_lock("pihole_log_thread");
		}

		// Wait some time before looking again at the log files
		sleepms(50);
	}
	return NULL;
}

void process_pihole_log(int file)
{
	int i;
	char readbuffer[1024] = "";
	char readbuffer2[1024] = "";
	FILE *fp;

	if(file == 0)
	{
		// Read from pihole.log
		fp = dnsmasqlog;
	}
	else if(file == 1)
	{
		// Read from pihole.log.1
		if((fp = fopen(files.log1,"r")) == NULL) {
			logg("Warning: Reading of rotated log file failed");
			return;
		}
	}
	else
	{
		logg_int("Error: Passed unknwon file identifier ", file);
		return;
	}

	int fposbck = ftell(fp);

	// Read pihole log from current position until EOF line by line
	while( fgets (readbuffer , sizeof(readbuffer)-1 , fp) != NULL )
	{
		// Ensure that the line we read ended with a newline
		// It can happen that we read too fast and dnsmasq didn't had the time
		// to finish writing to the log. In this case, fgets() will not stop
		// at a newline character, but at EOF. If we detect this scenario, we
		// have to wait a little longer and re-try reading
		if(feof(fp))
		{
			fseek(fp, fposbck, SEEK_SET);
			sleepms(10);
			if(fgets (readbuffer , sizeof(readbuffer)-1 , fp) == NULL)
				break;
		}

		// Test if the read line is a query line
		if(strstr(readbuffer,"]: query[A") != NULL)
		{
			// Ensure we have enough space in the queries struct
			memory_check(QUERIES);

			// Get timestamp
			char timestamp[16] = "";
			strncpy(timestamp,readbuffer,(size_t)15);
			timestamp[15] = '\0';
			// Get local time
			time_t rawtime;
			struct tm * timeinfo;
			time(&rawtime);
			timeinfo = localtime (&rawtime);
			// Interpret dnsmasq timestamp
			struct tm querytime = { 0 };
			// Expected format: Mmm dd hh:mm:ss
			// %b = Abbreviated month name
			// %e = Day of the month, space-padded ( 1-31)
			// %H = Hour in 24h format (00-23)
			// %M = Minute (00-59)
			// %S = Second (00-59)
			strptime(timestamp, "%b %e %H:%M:%S", &querytime);
			// Year is missing in dnsmasq's output - add the current year
			querytime.tm_year = (*timeinfo).tm_year;
			int querytimestamp = (int)mktime(&querytime);

			// Skip parsing of this log entry if it is too old
			if(((time(NULL) - GCdelay) - querytimestamp) > MAXLOGAGE) continue;

			// Now, we modify the minutes (and seconds), but that is fine, since
			// we don't need the querytime anymore (querytimestamp is already set)
			querytime.tm_min = querytime.tm_min - (querytime.tm_min%10) + 5;
			querytime.tm_sec = 0;

			int timeidx;
			int overTimeUNIXstamp = (int)mktime(&querytime);
			bool found = false;
			for(i=0; i < counters.overTime; i++)
			{
				if(overTime[i].timestamp == overTimeUNIXstamp)
				{
					found = true;
					timeidx = i;
					break;
				}
			}
			if(!found)
			{
				memory_check(OVERTIME);
				timeidx = counters.overTime;
				overTime[counters.overTime].timestamp = overTimeUNIXstamp;
				overTime[counters.overTime].total = 0;
				overTime[counters.overTime].blocked = 0;
				counters.overTime++;
			}

			// Get domain
			// domainstart = pointer to | in "query[AAAA] |host.name from ww.xx.yy.zz\n"
			const char *domainstart = strstr(readbuffer, "] ");
			// Check if buffer pointer is valid
			if(domainstart == NULL)
			{
				logg_str("Notice: Skipping malformated log line (domain start missing): ",strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}
			// domainend = pointer to | in "query[AAAA] host.name| from ww.xx.yy.zz\n"
			const char *domainend = strstr(domainstart+2, " from");
			// Check if buffer pointer is valid
			if(domainend == NULL)
			{
				logg_str("Notice: Skipping malformated log line (domain end missing): ",strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}
			size_t domainlen = domainend-(domainstart+2);
			char *domain = calloc(domainlen+1,sizeof(char));
			strncpy(domain,domainstart+2,domainlen);

			// Get client
			// domainend+6 = pointer to | in "query[AAAA] host.name from |ww.xx.yy.zz\n"
			const char *clientend = strstr(domainend+6, "\n");
			// Check if buffer pointer is valid
			if(clientend == NULL)
			{
				logg_str("Notice: Skipping malformated log line (client end missing): ",strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}
			size_t clientlen = (clientend-domainend)-6;
			char *client = calloc(clientlen+1,sizeof(char));
			strncpy(client,domainend+6,clientlen);

			// Get type
			unsigned char type = 0;
			if(strstr(readbuffer,"query[A]") != NULL)
			{
				type = 1;
				counters.IPv4++;
			}
			else if(strstr(readbuffer,"query[AAAA]") != NULL)
			{
				type = 2;
				counters.IPv6++;
			}

			// Save current file pointer position
			int fpos = ftell(fp);
			unsigned char status = 0;

			// Try to find either a matching
			// - "gravity.list" + domain
			// - "forwarded" + domain
			// - "cached" + domain
			// in the following up to 200 lines
			bool firsttime = true;
			for(i=0; i<200; i++)
			{
				if(fgets (readbuffer2 , sizeof(readbuffer2) , fp) != NULL)
				{
					// Process only matching lines
					if(strstr(readbuffer2,domain) != NULL)
					{
						// Blocked by gravity.list ?
						if(strstr(readbuffer2,"gravity.list ") != NULL)
						{
							status = 1;
							break;
						}
						// Forwarded to upstream server?
						else if(strstr(readbuffer2,": forwarded ") != NULL)
						{
							status = 2;
							break;
						}
						// Answered by local cache?
						else if((strstr(readbuffer2,"cached ") != NULL) ||
						        (strstr(readbuffer2,"local.list") != NULL) ||
						        (strstr(readbuffer2,"hostname.list") != NULL) ||
						        (strstr(readbuffer2,"DHCP ") != NULL) ||
						        (strstr(readbuffer2,"/etc/hosts") != NULL))
						{
							status = 3;
							break;
						}
						// wildcard blocking?
						else if((strstr(readbuffer2,"config ") != NULL))
						{
							status = detectStatus(domain);
							break;
						}
					}
				}
				else
				{
					if(firsttime)
					{
						// Reached EOF without finding the action
						// wait 100msec and try again to read dnsmasq's response
						i = 0;
						fseek(fp, fpos, SEEK_SET);
						firsttime = false;
						sleepms(100);
					}
					else
					{
						// Failed second time
						break;
					}
				}
			}
			// Return to previous file pointer position
			fseek(fp, fpos, SEEK_SET);

			// Go through already knows domains and see if it is one of them
			bool processed = false;
			int domainID;
			for(i=0; i < counters.domains; i++)
			{
				if(strcmp(domains[i].domain,domain) == 0)
				{
					domains[i].count++;
					processed = true;
					domainID = i;
					break;
				}
			}
			if(!processed)
			{
				// This domain is not known
				// Check struct size
				memory_check(DOMAINS);
				// Store ID
				domainID = counters.domains;
				// Set its counter to 1
				domains[domainID].count = 1;
				// Set blocked counter to zero
				domains[domainID].blockedcount = 0;
				// Initialize wildcard blocking flag with false
				domains[domainID].wildcard = false;
				// Store domain name
				domains[domainID].domain = calloc(strlen(domain)+1,sizeof(char));
				memory.domainnames += (strlen(domain) + 1) * sizeof(char);
				strcpy(domains[domainID].domain, domain);
				// Increase counter by one
				counters.domains++;
//				logg_str("Added one new domain: ", domain);
			}

			// Go through already knows clients and see if it is one of them
			processed = false;
			int clientID;
			for(i=0; i < counters.clients; i++)
			{
				if(strcmp(clients[i].ip,client) == 0)
				{
					clients[i].count++;
					processed = true;
					clientID = i;
					break;
				}
			}
			if(!processed)
			{
				// This client is not known
				// Check struct size
				memory_check(CLIENTS);
				// Store ID
				clientID = counters.clients;
				// Set its counter to 1
				clients[clientID].count = 1;
				// Store client IP
				clients[clientID].ip = calloc(strlen(client)+1,sizeof(char));
				memory.clientips += (strlen(client) + 1) * sizeof(char);
				strcpy(clients[clientID].ip, client);
				//Get client host name
				char *hostname = resolveHostname(client);
				clients[clientID].name = calloc(strlen(hostname)+1,sizeof(char));
				memory.clientnames += (strlen(hostname) + 1) * sizeof(char);
				strcpy(clients[clientID].name,hostname);
				free(hostname);
				// Increase counter by one
				counters.clients++;
				if(strlen(clients[clientID].name) > 0)
					logg_str_str("Added new client: ", client, clients[clientID].name);
				else
					logg_str("Added new client: ", client);
			}

			// Save everything
			queries[counters.queries].timestamp = querytimestamp;
			queries[counters.queries].type = type;
			queries[counters.queries].status = status;
			queries[counters.queries].domainID = domainID;
			queries[counters.queries].clientID = clientID;
			queries[counters.queries].timeidx = timeidx;
			queries[counters.queries].valid = true;

			// Increase DNS queries counter
			counters.queries++;

			// Update overTime data
			overTime[timeidx].total++;

			// Decide what to increment depending on status
			switch(status)
			{
				case 0: counters.unknown++; /*logg_str("Unknown: ",strtok(readbuffer, "\n"));*/ break;
				case 1: counters.blocked++; overTime[timeidx].blocked++; domains[domainID].blockedcount++; break;
				case 2: break;
				case 3: counters.cached++; break;
				case 4: counters.wildcardblocked++; overTime[timeidx].blocked++; domains[domainID].wildcard = true; break;
				default: /* That cannot happen */ break;
			}

			// Free allocated memory
			free(client);
			free(domain);

		}
		else if(strstr(readbuffer,": forwarded") != NULL)
		{
			// Get forward destination
			// forwardstart = pointer to | in "forwarded domain.name| to www.xxx.yyy.zzz\n"
			const char *forwardstart = strstr(readbuffer, " to ");
			// Check if buffer pointer is valid
			if(forwardstart == NULL)
			{
				logg_str("Notice: Skipping malformated log line (forward start missing): ",strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}
			// forwardend = pointer to | in "forwarded domain.name to www.xxx.yyy.zzz|\n"
			const char *forwardend = strstr(forwardstart+4, "\n");
			// Check if buffer pointer is valid
			if(forwardend == NULL)
			{
				logg_str("Notice: Skipping malformated log line (forward end missing): ",strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}
			size_t forwardlen = forwardend-(forwardstart+4);
			char *forward = calloc(forwardlen+1,sizeof(char));
			strncpy(forward,forwardstart+4,forwardlen);

			bool processed = false;
			// Go through already knows forward servers and see if we used one of those
			for(i=0; i < counters.forwarded; i++)
			{
				if(strcmp(forwarded[i].ip,forward) == 0)
				{
					forwarded[i].count++;
					processed = true;
					break;
				}
			}
			if(!processed)
			{
				// This forward server is not known
				// Check struct size
				memory_check(FORWARDED);
				// Store ID
				int forwardID = counters.forwarded;
				// Set its counter to 1
				forwarded[forwardID].count = 1;
				// Save IP
				forwarded[forwardID].ip = calloc(forwardlen+1,sizeof(char));
				memory.forwardedips += (forwardlen + 1) * sizeof(char);
				strcpy(forwarded[forwardID].ip,forward);
				//Get forward destination host name
				char *hostname = resolveHostname(forward);
				forwarded[forwardID].name = calloc(strlen(hostname)+1,sizeof(char));
				memory.forwardednames += (strlen(hostname) + 1) * sizeof(char);
				strcpy(forwarded[forwardID].name,hostname);
				free(hostname);
				// Increase counter by one
				counters.forwarded++;
				if(strlen(forwarded[forwardID].name) > 0)
					logg_str_str("Added new forward server: ", forwarded[forwardID].ip, forwarded[forwardID].name);
				else
					logg_str("Added new forward server: ", forwarded[forwardID].ip);
			}
		}
		else if((strstr(readbuffer,"IPv6") != NULL) &&
		        (strstr(readbuffer,"DBus") != NULL) &&
		        (strstr(readbuffer,"i18n") != NULL) &&
		        (strstr(readbuffer,"DHCP") != NULL) &&
		         !initialscan)
		{
			// dnsmasq restartet
			logg("dnsmasq process restarted");
			read_gravity_files();
		}
		else if(strstr(readbuffer,"query[PTR]"))
		{
			counters.PTR++;
		}
		else if(strstr(readbuffer,"query[SRV]"))
		{
			counters.SRV++;
		}

		// Save file pointer position, because we might have to repeat
		// reading the next line if dnsmasq hasn't finished writing it
		// (see beginning of this loop)
		fposbck = ftell(fp);
	}

	// Update file pointer position
	if(file == 0)
		dnsmasqlogpos = ftell(dnsmasqlog);
	// Close file if we are not reading the main log
	else
		fclose(fp);
}

char *resolveHostname(char *addr)
{
	// Get host name
	struct hostent *he;
	char *hostname;
	if(strstr(addr,":") != NULL)
	{
		struct in6_addr ipaddr;
		inet_pton(AF_INET6, addr, &ipaddr);
		he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET6);
	}
	else
	{
		struct in_addr ipaddr;
		inet_pton(AF_INET, addr, &ipaddr);
		he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET);
	}

	if(he == NULL)
	{
		hostname = calloc(1,sizeof(char));
	}
	else
	{
		hostname = calloc(strlen(he->h_name)+1,sizeof(char));
		strcpy(hostname, he->h_name);
	}

	return hostname;
}

int detectStatus(char *domain)
{
	// Try to find the domain in the array of wildcard blocked domains
	int i;
	char part[strlen(domain)],partbuffer[strlen(domain)];
	for(i=0; i < counters.wildcarddomains; i++)
	{
		if(strcmp(wildcarddomains[i], domain) == 0)
		{
			// Exact match with wildcard domain
			// if(debug)
			// 	printf("%s / %s (exact wildcard match)\n",wildcarddomains[i], domain);
			return 4;
		}
		// Create copy of domain under investigation
		strcpy(part,domain);
		while(sscanf(part,"%*[^.].%s",partbuffer) > 0)
		{
			if(strcmp(wildcarddomains[i], partbuffer) == 0)
			{
				// Return match with wildcard domain
				// if(debug)
				// 	printf("%s / %s (wildcard match)\n",wildcarddomains[i], partbuffer);
				return 4;
			}
			if(strlen(partbuffer) > 0)
				strcpy(part, partbuffer);
		}
	}

	// If not found -> this answer is not from
	// wildcard blocking, but from e.g. an
	// address=// configuration
	// Answer as "cached"
	return 3;
}
