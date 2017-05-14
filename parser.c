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
#define MAGICBYTE 0x57

char *resolveHostname(char *addr);
void extracttimestamp(char *readbuffer, int *querytimestamp, int *overTimetimestamp);
int getforwardID(char * str);
int findDomain(char *domain);
int findClient(char *client);

long int oldfilesize = 0;
long int lastpos = 0;
int lastqueryID = 0;
bool flush = false;
char timestamp[16] = "";

void initial_log_parsing(void)
{
	initialscan = true;
	if(config.include_yesterday)
		process_pihole_log(1);
	process_pihole_log(0);
	initialscan = false;
}

long int checkLogForChanges(void)
{
	// Get file details
	struct stat st;
	if(stat(files.log, &st) != 0)
	{
		// stat() failed (maybe the file does not exist?)
		return 0;
	}
	long int newfilesize = st.st_size;
	long int difference = newfilesize - oldfilesize;
	oldfilesize = newfilesize;

	return difference;
}

void open_pihole_log(void)
{
	FILE * fp;
	if((fp = fopen(files.log, "r")) == NULL) {
		logg("FATAL: Opening of %s failed!", files.log);
		logg("       Make sure it exists and is readable by user %s", username);
		syslog(LOG_ERR, "Opening of pihole.log failed!");
		// Return failure in exit status
		exit(EXIT_FAILURE);
	}
	fclose(fp);
}

void get_file_permissions(const char *path)
{
	char permissions[10];
	struct stat st;
	if(stat(path, &st) != 0)
	{
		// stat() failed (maybe the file does not exist?)
		logg("Warning: stat() failed for %s", files.log);
		return;
	}
	permissions[0] = (st.st_mode & S_IRUSR) ? 'r' : '-';
	permissions[1] = (st.st_mode & S_IWUSR) ? 'w' : '-';
	permissions[2] = (st.st_mode & S_IXUSR) ? 'x' : '-';
	permissions[3] = (st.st_mode & S_IRGRP) ? 'r' : '-';
	permissions[4] = (st.st_mode & S_IWGRP) ? 'w' : '-';
	permissions[5] = (st.st_mode & S_IXGRP) ? 'x' : '-';
	permissions[6] = (st.st_mode & S_IROTH) ? 'r' : '-';
	permissions[7] = (st.st_mode & S_IWOTH) ? 'w' : '-';
	permissions[8] = (st.st_mode & S_IXOTH) ? 'x' : '-';
	permissions[9] = '\0';

	logg("Reading from %s (%s)", path, permissions);
}

void *pihole_log_thread(void *val)
{
	prctl(PR_SET_NAME,"loganalyzer",0,0,0);
	while(!killed)
	{
		long int newdata = checkLogForChanges();

		if(newdata != 0 || flush)
		{
			// Lock FTL's data structure, since it is likely that it will be changed here
			// Requests should not be processed/answered when data is about to change
			enable_read_write_lock("pihole_log_thread");

			if(newdata > 0 && !flush)
			{
				// Process new data if found only in main log (file 0)
				process_pihole_log(0);
			}
			else
			{
				flush = false;
				// Process flushed log
				// Flush internal datastructure
				pihole_log_flushed(true);
				// Reset file size and position
				oldfilesize = 0;
				lastpos = 0;
				// Rescan files 0 (pihole.log) and 1 (pihole.log.1)
				initialscan = true;
				if(config.include_yesterday)
					process_pihole_log(1);
				process_pihole_log(0);
				needGC = true;
				initialscan = false;
			}

			// Release thread lock
			disable_thread_locks("pihole_log_thread");
		}

		// Wait some time before looking again at the log files
		sleepms(200);
	}
	return NULL;
}

void process_pihole_log(int file)
{
	int i;
	char *readbuffer = NULL;
	char *readbuffer2 = NULL;
	size_t size1 = 0, size2 = 0;
	FILE *fp;

	if(file == 0)
	{
		// Read from pihole.log
		if((fp = fopen(files.log, "r")) == NULL) {
			logg("Warning: Reading of log file %s failed", files.log);
			return;
		}
		// Skip to last read position
		fseek(fp, lastpos, SEEK_SET);
		if(initialscan)
			get_file_permissions(files.log);
	}
	else if(file == 1)
	{
		// Read from pihole.log.1
		if((fp = fopen(files.log1, "r")) == NULL) {
			logg("Warning: Reading of rotated log file %s failed", files.log1);
			return;
		}
		if(initialscan)
			get_file_permissions(files.log1);
	}
	else
	{
		logg("Error: Passed unknown file identifier (%i)", file);
		return;
	}

	long int fposbck = ftell(fp);

	// Read pihole log from current position until EOF line by line
	errno = 0;
	while(getline(&readbuffer, &size1, fp) != -1)
	{
		// Ensure that the line we read ended with a newline
		// It can happen that we read too fast and dnsmasq didn't had the time
		// to finish writing to the log. In this case, getline() will not stop
		// at a newline character, but at EOF. If we detect this scenario, we
		// have to wait a little longer and re-try reading
		if(feof(fp))
		{
			fseek(fp, fposbck, SEEK_SET);
			sleepms(10);
			if(getline(&readbuffer, &size1, fp) == -1)
				break;
		}

		// Test if the read line is a query line
		if(strstr(readbuffer,"]: query[A") != NULL)
		{
			// Check if this domain names contains only printable characters
			// if not: skip analysis of this log line
			if(strstr(readbuffer,"<name unprintable>") != NULL)
			{
				if(debug) logg("Ignoring <name unprintable> domain (query)");
				continue;
			}

			// Get timestamp
			int querytimestamp, overTimetimestamp;
			extracttimestamp(readbuffer, &querytimestamp, &overTimetimestamp);

			// Get minimum time stamp to analyze
			int differencetofullhour = time(NULL) % GCinterval;
			int mintime = (time(NULL) - GCdelay - differencetofullhour) - MAXLOGAGE;
			// Skip parsing of log entries that are too old altogether if 24h window is requested
			if(config.rolling_24h && querytimestamp < mintime) continue;

			// Ensure we have enough space in the queries struct
			memory_check(QUERIES);
			int queryID = counters.queries;

			int timeidx = -1;
			bool found = false;
			// Check struct size
			memory_check(OVERTIME);
			for(i=0; i < counters.overTime; i++)
			{
				validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
				if(overTime[i].timestamp == overTimetimestamp)
				{
					found = true;
					timeidx = i;
					break;
				}
			}
			if(!found)
			{
				timeidx = counters.overTime;
				validate_access("overTime", timeidx, false, __LINE__, __FUNCTION__, __FILE__);
				// Set magic byte
				overTime[timeidx].magic = MAGICBYTE;
				overTime[timeidx].timestamp = overTimetimestamp;
				overTime[timeidx].total = 0;
				overTime[timeidx].blocked = 0;
				overTime[timeidx].cached = 0;
				overTime[timeidx].forwardnum = 0;
				overTime[timeidx].forwarddata = NULL;
				overTime[timeidx].querytypedata = calloc(2, sizeof(int));
				memory.querytypedata += 2*sizeof(int);
				counters.overTime++;
			}

			// Get domain
			// domainstart = pointer to | in "query[AAAA] |host.name from ww.xx.yy.zz\n"
			const char *domainstart = strstr(readbuffer, "] ");
			// Check if buffer pointer is valid
			if(domainstart == NULL)
			{
				logg("Notice: Skipping malformated log line (domain start missing): %s", strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}
			// domainend = pointer to | in "query[AAAA] host.name| from ww.xx.yy.zz\n"
			const char *domainend = strstr(domainstart+2, " from");
			// Check if buffer pointer is valid
			if(domainend == NULL)
			{
				logg("Notice: Skipping malformated log line (domain end missing): %s", strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}

			size_t domainlen = domainend-(domainstart+2);
			if(domainlen < 1)
			{
				logg("Notice: Skipping malformated log line (domain length < 1): %s", strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}

			char *domain = calloc(domainlen+1,sizeof(char));
			char *domainwithspaces = calloc(domainlen+3,sizeof(char));
			strncpy(domain,domainstart+2,domainlen);
			sprintf(domainwithspaces," %s ",domain);

			// Get client
			// domainend+6 = pointer to | in "query[AAAA] host.name from |ww.xx.yy.zz\n"
			const char *clientend = strstr(domainend+6, "\n");
			// Check if buffer pointer is valid
			if(clientend == NULL)
			{
				logg("Notice: Skipping malformated log line (client end missing): %s", strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}

			size_t clientlen = (clientend-domainend)-6;
			if(clientlen < 1)
			{
				logg("Notice: Skipping malformated log line (client length < 1): %s", strtok(readbuffer,"\n"));
				// Skip this line
				continue;
			}

			char *client = calloc(clientlen+1,sizeof(char));
			strncpy(client,domainend+6,clientlen);

			// Get type
			unsigned char type = 0;
			if(strstr(readbuffer,"query[A]") != NULL)
			{
				type = 1;
				counters.IPv4++;
				validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				overTime[timeidx].querytypedata[0]++;
			}
			else if(strstr(readbuffer,"query[AAAA]") != NULL)
			{
				type = 2;
				counters.IPv6++;
				validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				overTime[timeidx].querytypedata[1]++;
			}

			// Save current file pointer position
			long int fpos = ftell(fp);
			unsigned char status = 0;

			// Try to find either a matching
			// - "gravity.list" + domain
			// - "forwarded" + domain
			// - "cached" + domain
			// in the following up to 200 lines
			bool firsttime = true;
			int forwardID = -1;
			for(i=0; i<200; i++)
			{
				if(getline(&readbuffer2, &size2, fp) != -1)
				{
					// Process only matching lines
					if(strstr(readbuffer2, domainwithspaces) != NULL)
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
							// Get ID of forward destination, create new forward destination record
							// if not found in current data structure
							forwardID = getforwardID(readbuffer2);
							if(forwardID == -2)
								continue;
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

			// Free memory allocated by readline
			if(readbuffer2 != NULL)
			{
				free(readbuffer2);
				readbuffer2 = NULL;
			}

			// Go through already knows domains and see if it is one of them
			// Check struct size
			memory_check(DOMAINS);
			int domainID = findDomain(domain);
			if(domainID < 0)
			{
				// This domain is not known
				// Store ID
				domainID = counters.domains;
				// // Debug output
				if(debug)
					logg("New domain: %s (%i/%i)", domain, domainID, counters.domains_MAX);
				validate_access("domains", domainID, false, __LINE__, __FUNCTION__, __FILE__);
				// Set magic byte
				domains[domainID].magic = MAGICBYTE;
				// Set its counter to 1
				domains[domainID].count = 1;
				// Set blocked counter to zero
				domains[domainID].blockedcount = 0;
				// Initialize wildcard blocking flag with false
				domains[domainID].wildcard = false;
				// Store domain name
				domains[domainID].domain = strdup(domain);
				memory.domainnames += (strlen(domain) + 1) * sizeof(char);
				// Increase counter by one
				counters.domains++;
			}

			// Go through already knows clients and see if it is one of them
			// Check struct size
			memory_check(CLIENTS);
			int clientID = findClient(client);
			if(clientID < 0)
			{
				// This client is not known
				// Store ID
				clientID = counters.clients;
				//Get client host name
				char *hostname = resolveHostname(client);
				// Debug output
				if(strlen(hostname) > 0)
					logg("New client: %s %s (%i/%i)", client, hostname, clientID, counters.clients_MAX);
				else
					logg("New client: %s (%i/%i)", client, clientID, counters.clients_MAX);

				validate_access("clients", clientID, false, __LINE__, __FUNCTION__, __FILE__);
				// Set magic byte
				clients[clientID].magic = MAGICBYTE;
				// Set its counter to 1
				clients[clientID].count = 1;
				// Store client IP
				clients[clientID].ip = strdup(client)
				memory.clientips += (strlen(client) + 1) * sizeof(char);
				// Store client hostname
				clients[clientID].name = strdup(hostname);
				memory.clientnames += (strlen(hostname) + 1) * sizeof(char);
				free(hostname);
				// Increase counter by one
				counters.clients++;
			}

			// Save everything
			validate_access("queries", queryID, false, __LINE__, __FUNCTION__, __FILE__);
			queries[queryID].magic = MAGICBYTE;
			queries[queryID].timestamp = querytimestamp;
			queries[queryID].type = type;
			queries[queryID].status = status;
			queries[queryID].domainID = domainID;
			queries[queryID].clientID = clientID;
			queries[queryID].timeidx = timeidx;
			queries[queryID].forwardID = forwardID;
			queries[queryID].valid = true;

			// Increase DNS queries counter
			counters.queries++;

			// Update overTime data
			validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
			overTime[timeidx].total++;

			// Decide what to increment depending on status
			switch(status)
			{
				case 0:
					// Unknown (?)
					counters.unknown++;
					break;
				case 1:
					// Blocked by Pi-hole's blocking lists
					counters.blocked++;
					validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[timeidx].blocked++;
					validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
					domains[domainID].blockedcount++;
					break;
				case 2:
					// Forwarded to an upstream DNS server
					counters.forwardedqueries++;
					break;
				case 3:
					// Answered from local cache _or_ local config
					counters.cached++;
					validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[timeidx].cached++;
					break;
				case 4:
					// Blocked due to a matching wildcard rule
					counters.wildcardblocked++;
					validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[timeidx].blocked++;
					validate_access("domains", domainID, true, __LINE__, __FUNCTION__, __FILE__);
					domains[domainID].blockedcount++;
					domains[domainID].wildcard = true;
					break;
				default:
					/* That cannot happen */
					break;
			}

			// Free allocated memory
			free(client);
			free(domain);
			free(domainwithspaces);
		}
		else if(strstr(readbuffer,": forwarded") != NULL)
		{
			// Check if this domain names contains only printable characters
			// if not: skip analysis of this log line
			if(strstr(readbuffer,"<name unprintable>") != NULL)
			{
				if(debug) logg("Ignoring <name unprintable> domain (forwarded)");
				continue;
			}

			// Get ID of forward destination, create new forward destination record
			// if not found in current data structure
			int forwardID = getforwardID(readbuffer);
			if(forwardID == -2)
				continue;

			// Get timestamp
			int querytimestamp, overTimetimestamp, timeidx = -1, i;
			extracttimestamp(readbuffer, &querytimestamp, &overTimetimestamp);

			bool found = false;
			// Check struct size
			memory_check(OVERTIME);
			for(i=0; i < counters.overTime; i++)
			{
				validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
				if(overTime[i].timestamp == overTimetimestamp)
				{
					found = true;
					timeidx = i;
					break;
				}
			}
			if(!found)
			{
				timeidx = counters.overTime;
				validate_access("overTime", timeidx, false, __LINE__, __FUNCTION__, __FILE__);
				overTime[timeidx].magic = MAGICBYTE;
				overTime[timeidx].timestamp = overTimetimestamp;
				overTime[timeidx].total = 0;
				overTime[timeidx].blocked = 0;
				overTime[timeidx].cached = 0;
				overTime[timeidx].forwardnum = 0;
				overTime[timeidx].forwarddata = NULL;
				overTime[timeidx].querytypedata = calloc(2, sizeof(int));
				memory.querytypedata += 2*sizeof(int);
				counters.overTime++;
			}
			// Determine if there is enough space for saving the current
			// forwardID in the overTime data structure -allocate space otherwise
			validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
			if(overTime[timeidx].forwardnum <= forwardID)
			{
				// Reallocate more space for forwarddata
				overTime[timeidx].forwarddata = realloc(overTime[timeidx].forwarddata, (forwardID+1)*sizeof(*overTime[timeidx].forwarddata));
				// Initialize new data fields with zeroes
				for(i = overTime[timeidx].forwardnum; i <= forwardID; i++)
				{
					overTime[timeidx].forwarddata[i] = 0;
					memory.forwarddata++;
				}
				// Update counter
				overTime[timeidx].forwardnum = forwardID + 1;
			}

			// Update overTime data structure with the new forwarder
			validate_access_oTfd(timeidx, forwardID, __LINE__, __FUNCTION__, __FILE__);
			overTime[timeidx].forwarddata[forwardID]++;
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

		// Save file pointer position, because we might have to repeat
		// reading the next line if dnsmasq hasn't finished writing it
		// (see beginning of this loop)
		fposbck = ftell(fp);

		// Return early if data structure is flushed
		if(file == 0)
		{
			if(checkLogForChanges() < 0)
			{
				logg("Notice: Returning early from log parsing for flushing");
				fclose(fp);
				flush = true;
				return;
			}
		}
	}

	if(errno == ENOMEM)
		logg("WARN: process_pihole_log failed: could not allocate memory for getline");

	// Free memory allocated by readline
	if(readbuffer != NULL)
		free(readbuffer);

	// IF we are reading the main log, we want to store the last read
	// position so that we can jump to this position in the next round
	if(file == 0)
	{
		lastpos = ftell(fp);
	}

	// Close file when parsing is finished
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
		hostname[0] = '\0';
	}
	else
	{
		hostname = strdup(he->h_name);
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
		validate_access("wildcarddomains", i, false, __LINE__, __FUNCTION__, __FILE__);
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

void extracttimestamp(char *readbuffer, int *querytimestamp, int *overTimetimestamp)
{
	// Get timestamp
	// char timestamp[16]; <- declared in FTL.h
	memset(&timestamp, 0, sizeof(timestamp));
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

	// DST - according to ISO/IEC 9899:TC3
	// > A negative value causes mktime to attempt to determine whether
	// > Daylight Saving Time is in effect for the specified time
	// We have to dynamically do this here, since we might be reading in
	// data that extends into a different DST region
	querytime.tm_isdst = -1;

	*querytimestamp = (int)mktime(&querytime);

	// Floor timestamp to the beginning of 10 minutes interval
	// and add 5 minutes to center it in the interval
	*overTimetimestamp = *querytimestamp-(*querytimestamp%600)+300;
}

int getforwardID(char * str)
{
	// Get forward destination
	// forwardstart = pointer to | in "forwarded domain.name| to www.xxx.yyy.zzz\n"
	const char *forwardstart = strstr(str, " to ");
	// Check if buffer pointer is valid
	if(forwardstart == NULL)
	{
		logg("Notice: Skipping malformated log line (forward start missing): %s", strtok(str,"\n"));
		// Skip this line
		return -2;
	}
	// forwardend = pointer to | in "forwarded domain.name to www.xxx.yyy.zzz|\n"
	const char *forwardend = strstr(forwardstart+4, "\n");
	// Check if buffer pointer is valid
	if(forwardend == NULL)
	{
		logg("Notice: Skipping malformated log line (forward end missing): %s", strtok(str,"\n"));
		// Skip this line
		return -2;
	}

	size_t forwardlen = forwardend-(forwardstart+4);
	if(forwardlen < 1)
	{
		logg("Notice: Skipping malformated log line (forward length < 1): %s", strtok(readbuffer,"\n"));
		// Skip this line
		continue;
	}

	char *forward = calloc(forwardlen+1,sizeof(char));
	strncpy(forward,forwardstart+4,forwardlen);

	bool processed = false;
	int i, forwardID = -1;
	// Go through already knows forward servers and see if we used one of those
	// Check struct size
	memory_check(FORWARDED);
	for(i=0; i < counters.forwarded; i++)
	{
		validate_access("forwarded", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(strcmp(forwarded[i].ip, forward) == 0)
		{
			forwardID = i;
			forwarded[forwardID].count++;
			processed = true;
			break;
		}
	}
	if(!processed)
	{
		// This forward server is not known
		// Store ID
		forwardID = counters.forwarded;
		// Get forward destination host name
		char *hostname = resolveHostname(forward);
		if(strlen(hostname) > 0)
			logg("New forward server: %s %s (%i/%i)", forward, hostname, forwardID, counters.forwarded_MAX);
		else
			logg("New forward server: %s (%i/%u)", forward, forwardID, counters.forwarded_MAX);

		validate_access("forwarded", forwardID, false, __LINE__, __FUNCTION__, __FILE__);
		// Set magic byte
		forwarded[forwardID].magic = MAGICBYTE;
		// Set its counter to 1
		forwarded[forwardID].count = 1;
		// Save IP
		forwarded[forwardID].ip = strdup(forward);
		memory.forwardedips += (forwardlen + 1) * sizeof(char);
		// Save forward destination host name
		forwarded[forwardID].name = strdup(hostname);
		memory.forwardednames += (strlen(hostname) + 1) * sizeof(char);
		free(hostname);
		// Increase counter by one
		counters.forwarded++;
	}

	// Release allocated memory
	free(forward);

	return forwardID;
}

int findDomain(char *domain)
{
	int i;
	for(i=0; i < counters.domains; i++)
	{
		validate_access("domains", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Quick test: Does the domain start with the same character?
		if(domains[i].domain[0] != domain[0])
			continue;

		// If so, compare the full domain using strcmp
		if(strcmp(domains[i].domain, domain) == 0)
		{
			domains[i].count++;
			return i;
		}
	}
	// Return -1 if not found
	return -1;
}

int findClient(char *client)
{
	int i;
	for(i=0; i < counters.clients; i++)
	{
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Quick test: Does the clients IP start with the same character?
		if(clients[i].ip[0] != client[0])
			continue;

		// If so, compare the full domain using strcmp
		if(strcmp(clients[i].ip, client) == 0)
		{
			clients[i].count++;
			return i;
		}
	}
	// Return -1 if not found
	return -1;
}

void validate_access(const char * name, int pos, bool testmagic, int line, const char * function, const char * file)
{
	int limit = 0;
	if(name[0] == 'c') limit = counters.clients_MAX;
	else if(name[0] == 'd') limit = counters.domains_MAX;
	else if(name[0] == 'q') limit = counters.queries_MAX;
	else if(name[0] == 'o') limit = counters.overTime_MAX;
	else if(name[0] == 'f') limit = counters.forwarded_MAX;
	else if(name[0] == 'w') limit = counters.wildcarddomains;
	else { logg("Validator error (range)"); killed = 1; }

	if(pos >= limit || pos < 0)
	{
		logg("FATAL ERROR: Trying to access %s[%i], but maximum is %i", name, pos, limit);
		logg("             found in %s() (line %i) in %s", function, line, file);
	}
	// Don't test magic byte if detected potential out-of-bounds error
	else if(testmagic)
	{
		unsigned char magic = 0x00;
		if(name[0] == 'c') magic = clients[pos].magic;
		else if(name[0] == 'd') magic = domains[pos].magic;
		else if(name[0] == 'q') magic = queries[pos].magic;
		else if(name[0] == 'o') magic = overTime[pos].magic;
		else if(name[0] == 'f') magic = forwarded[pos].magic;
		else { logg("Validator error (magic byte)"); killed = 1; }
		if(magic != MAGICBYTE)
		{
			logg("FATAL ERROR: Trying to access %s[%i], but magic byte is %x", name, pos, magic);
			logg("             found in %s() (line %i) in %s", function, line, file);
		}
	}
}

void validate_access_oTfd(int timeidx, int pos, int line, const char * function, const char * file)
{
	int limit = overTime[timeidx].forwardnum;
	if(pos >= limit || pos < 0)
	{
		logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		logg("FATAL ERROR: Trying to access overTime.forwardata[%i], but maximum is %i", pos, limit);
		logg("             found in %s() (line %i) in %s", function, line, file);
	}
}
