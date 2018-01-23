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

char *resolveHostname(const char *addr);
void extracttimestamp(const char *readbuffer, int *querytimestamp, int *overTimetimestamp);
int findForwardID(const char *forward, bool count);
int findDomainID(const char *domain);
int findClientID(const char *client);
int findOverTimeID(int overTimetimestamp);
int detectStatus(const char *domain);

long int oldfilesize = 0;
long int lastpos = 0;
int lastqueryID = 0;
bool flush = false;
char timestamp[16] = "";
int loggeneration = 0;

void initial_log_parsing(void)
{
	initialscan = true;
	process_pihole_log();
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

int getTimeIndex(char * readbuffer)
{
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
		overTime[timeidx].clientnum = 0;
		overTime[timeidx].clientdata = NULL;
		memory.querytypedata += 2*sizeof(int);
		counters.overTime++;
	}

	return timeidx;
}

void open_pihole_log(void)
{
	FILE * fp;
	if((fp = fopen(files.log, "r")) == NULL) {
		logg("WARN:  Opening of %s failed!", files.log);
		logg("       Make sure it exists and is readable by user %s\n       Will try again in 15 seconds.", username);

		sleepms(15000);
		if((fp = fopen(files.log, "r")) == NULL) {
			logg("FATAL: Opening of %s failed permanently!", files.log);
			syslog(LOG_ERR, "Opening of pihole.log failed!");
			// Return failure in exit status
			exit(EXIT_FAILURE);
		}
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

// converts upper to lower case, and leaves other characters unchanged
void strtolower(char *str)
{
	int i = 0;
	while(str[i]){ str[i] = tolower(str[i]); i++; }
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
			enable_thread_lock("pihole_log_thread");

			if(newdata > 0 && !flush)
			{
				// Process new data if found only in main log (file 0)
				process_pihole_log();
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
				// Rescan pihole.log
				initialscan = true;
				process_pihole_log();
				needGC = true;
				initialscan = false;
			}

			// Release thread lock
			disable_thread_lock("pihole_log_thread");
		}

		// Wait some time before looking again at the log files
		sleepms(200);
	}
	return NULL;
}

int getdnsmasqID(char * readbuffer)
{
	// Get query ID from a string like
	// "Dec 20 21:16:22 dnsmasq[19372]: 4 10.8.0.2/34596 query[A] pi.hole from 10.8.0.2"
	int dnsmasqID = -1;
	if(!sscanf(readbuffer, "%*[^]]]: %i", &dnsmasqID))
	{
		if(debug) logg("Error getting ID for query \"%s\" %u", readbuffer, dnsmasqID);
	}
	return dnsmasqID;
}

bool checkQuery(char * readbuffer, const char * type)
{
	// Check if this domain names contains only printable characters
	// if not: skip analysis of this log line
	if(strstr(readbuffer,"<name unprintable>") != NULL)
	{
		if(debug) logg("Ignoring <name unprintable> domain (%s)", type);
		return false;
	}

	// Check if this domain name contains quotes
	if(strstr(readbuffer, "\"") != NULL)
	{
		if(debug) logg("Ignoring \" domain (%s)", type);
		return false;
	}

	// Check if this is a PTR query (we don't analyze them)
	if(strstr(readbuffer,"in-addr.arpa") != NULL)
		return false;

	return true;
}

void process_pihole_log(void)
{
	int i;
	char *readbuffer = NULL;
	size_t size1 = 0;
	FILE *fp;

	// Read from pihole.log
	if((fp = fopen(files.log, "r")) == NULL) {
		logg("Warning: Reading of log file %s failed", files.log);
		return;
	}
	// Skip to last read position
	fseek(fp, lastpos, SEEK_SET);
	if(initialscan)
		get_file_permissions(files.log);

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

		// Get timestamp
		int querytimestamp, overTimetimestamp;
		extracttimestamp(readbuffer, &querytimestamp, &overTimetimestamp);

		// Check if this query has already been imported from the database
		if(querytimestamp < lastDBimportedtimestamp) continue;

		// Skip parsing of log entries that are too old
		// Get minimum time stamp to analyze
		int differencetofullhour = time(NULL) % GCinterval;
		int mintime = (time(NULL) - GCdelay - differencetofullhour) - config.maxlogage;
		if(querytimestamp < mintime) continue;

		// Test if the read line is a query line
		if(strstr(readbuffer," query[A") != NULL)
		{
			if(!checkQuery(readbuffer, "query"))
				continue;

			if(!config.analyze_AAAA && strstr(readbuffer," query[AAAA]") != NULL)
			{
				if(debug) logg("Not analyzing AAAA query");
				continue;
			}

			// Ensure we have enough space in the queries struct
			memory_check(QUERIES);
			int queryID = counters.queries;
			int timeidx = findOverTimeID(overTimetimestamp);

			// Detect time travel events
			if(timeidx < 0)
			{
				// This query is older than the first one in the log, hence the clock
				// on this machine was at least slightly off for a while. We will skip
				// this query as we cannot attribute it correctly to anything.
				validate_access("overTime", 0, false, __LINE__, __FUNCTION__, __FILE__);
				logg("Warning: Skipping log entry with incorrect timestamp (%i/%i)", overTimetimestamp, overTime[0].timestamp);
				continue;
			}

			// Get dnsmasq's ID for this transaction
			int dnsmasqID = getdnsmasqID(readbuffer);
			// Skip invalid lines
			if(dnsmasqID < 0)
				continue;

			// Get domain
			// domainstart = pointer to | in "query[AAAA] |host.name from ww.xx.yy.zz\n"
			const char *domainstart = strstr(readbuffer, "] ");
			// Check if buffer pointer is valid
			if(domainstart == NULL)
			{
				logg("Notice: Skipping malformated log line (domain start missing): %s", readbuffer);
				// Skip this line
				continue;
			}
			// domainend = pointer to | in "query[AAAA] host.name| from ww.xx.yy.zz\n"
			const char *domainend = strstr(domainstart+2, " from");
			// Check if buffer pointer is valid
			if(domainend == NULL)
			{
				logg("Notice: Skipping malformated log line (domain end missing): %s", readbuffer);
				// Skip this line
				continue;
			}

			size_t domainlen = domainend-(domainstart+2);
			if(domainlen < 1)
			{
				logg("Notice: Skipping malformated log line (domain length < 1): %s", readbuffer);
				// Skip this line
				continue;
			}

			char *domain = calloc(domainlen+1,sizeof(char));
			// strncat() NULL-terminates the copied string (strncpy() doesn't!)
			strncat(domain,domainstart+2,domainlen);
			// Convert domain to lower case
			strtolower(domain);

			if(strcmp(domain, "pi.hole") == 0)
			{
				// domain is "pi.hole", skip this query
				// free memory already allocated here
				free(domain);
				continue;
			}

			// Get client
			// domainend+6 = pointer to | in "query[AAAA] host.name from |ww.xx.yy.zz\n"
			const char *clientend = strstr(domainend+6, "\n");
			// Check if buffer pointer is valid
			if(clientend == NULL)
			{
				logg("Notice: Skipping malformated log line (client end missing): %s", readbuffer);
				// Skip this line, free memory already allocated here
				free(domain);
				continue;
			}

			size_t clientlen = (clientend-domainend)-6;
			if(clientlen < 1)
			{
				logg("Notice: Skipping malformated log line (client length < 1): %s", readbuffer);
				// Skip this line, free memory already allocated here
				free(domain);
				continue;
			}

			char *client = calloc(clientlen+1,sizeof(char));
			// strncat() NULL-terminates the copied string (strncpy() doesn't!)
			strncat(client,domainend+6,clientlen);
			// Convert client to lower case
			strtolower(client);

			// Get type (A / AAAA)
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
			else
			{
				// Might be ANY
				if(debug) logg("Notice: Skipping possible ANY log line, ID: %i", dnsmasqID);
				free(domain);
				free(client);
				continue;
			}

			// Go through already knows domains and see if it is one of them
			// Check struct size
			memory_check(DOMAINS);
			int domainID = findDomainID(domain);

			// Go through already knows clients and see if it is one of them
			// Check struct size
			memory_check(CLIENTS);
			int clientID = findClientID(client);

			// Save everything
			validate_access("queries", queryID, false, __LINE__, __FUNCTION__, __FILE__);
			queries[queryID].magic = MAGICBYTE;
			queries[queryID].timestamp = querytimestamp;
			queries[queryID].type = type;
			queries[queryID].status = 0;
			queries[queryID].domainID = domainID;
			queries[queryID].clientID = clientID;
			queries[queryID].timeidx = timeidx;
			queries[queryID].valid = true;
			queries[queryID].db = false;
			queries[queryID].id = dnsmasqID;
			queries[queryID].complete = false;
			queries[queryID].reply = 0;
			queries[queryID].generation = loggeneration;

			// Increase DNS queries counter
			counters.queries++;
			// Count this query as unknown as long as no reply has
			// been found and analyzed
			counters.unknown++;

			// Update overTime data
			validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
			overTime[timeidx].total++;

			// Update overTime data structure with the new client
			validate_access_oTcl(timeidx, clientID, __LINE__, __FUNCTION__, __FILE__);
			overTime[timeidx].clientdata[clientID]++;

			// Free allocated memory
			free(client);
			free(domain);
		}
		// is this a "gravity.list" line?
		else if(strstr(readbuffer,"/gravity.list ") != NULL && strstr(readbuffer," is ") != NULL)
		{
			// Check query for invalid characters
			if(!checkQuery(readbuffer, "gravity.list"))
				continue;

			// Get dnsmasq's ID for this transaction
			int dnsmasqID = getdnsmasqID(readbuffer);
			// Skip invalid lines
			if(dnsmasqID < 0)
				continue;

			// Save status in corresponding query indentified by dnsmasq's ID
			bool found = false;
			for(i=0; i<counters.queries; i++)
			{
				// Check both UUID and generation of this query
				if(queries[i].id == dnsmasqID && queries[i].generation == loggeneration)
				{
					queries[i].status = 1;
					found = true;
					break;
				}
			}
			if(!found)
			{
				// This may happen e.g. if the original query was a PTR query or "pi.hole"
				// as we ignore them altogether
				continue;
			}

			if(!queries[i].complete)
			{
				// This query is no longer unknown
				counters.unknown--;
				// ... but got blocked
				counters.blocked++;
				// Hereby, this query is now fully determined
				queries[i].complete = true;

				// Get time index
				int timeidx = getTimeIndex(readbuffer);
				validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				overTime[timeidx].blocked++;
				validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
				domains[queries[i].domainID].blockedcount++;
			}
		}
		// is this a "forwarded" line?
		else if(strstr(readbuffer," forwarded ") != NULL && strstr(readbuffer," to ") != NULL)
		{
			// Check query for invalid characters
			if(!checkQuery(readbuffer, "forwarded"))
				continue;

			// Get dnsmasq's ID for this transaction
			int dnsmasqID = getdnsmasqID(readbuffer);
			// Skip invalid lines
			if(dnsmasqID < 0)
				continue;

			// Get forward destination
			// forwardstart = pointer to | in "forwarded domain.name| to www.xxx.yyy.zzz\n"
			const char *forwardstart = strstr(readbuffer, " to ");
			// Check if buffer pointer is valid
			if(forwardstart == NULL)
			{
				logg("Notice: Skipping malformated log line (forward start missing): %s", readbuffer);
				continue;
			}
			// forwardend = pointer to | in "forwarded domain.name to www.xxx.yyy.zzz|\n"
			const char *forwardend = strstr(forwardstart+4, "\n");
			// Check if buffer pointer is valid
			if(forwardend == NULL)
			{
				logg("Notice: Skipping malformated log line (forward end missing): %s", readbuffer);
				continue;
			}

			size_t forwardlen = forwardend-(forwardstart+4);
			if(forwardlen < 1)
			{
				logg("Notice: Skipping malformated log line (forward length < 1): %s", readbuffer);
				continue;
			}

			char *forward = calloc(forwardlen+1,sizeof(char));
			// strncat() NULL-terminates the copied string (strncpy() doesn't!)
			strncat(forward,forwardstart+4,forwardlen);
			// Convert forward to lower case
			strtolower(forward);

			// Save status and forwardID in corresponding query indentified by dnsmasq's ID
			bool found = false;
			for(i=0; i<counters.queries; i++)
			{
				// Check both UUID and generation of this query
				if(queries[i].id == dnsmasqID && queries[i].generation == loggeneration)
				{
					// Detect if we cached the <CNAME> but need to ask the upstream
					// servers for the actual IPs now
					if(queries[i].status == 3)
					{
						// Fix counters
						counters.cached--;
						validate_access("overTime", queries[i].timeidx, true, __LINE__, __FUNCTION__, __FILE__);
						overTime[queries[i].timeidx].cached--;

						// Mark this query again as (temporarily) unknown
						counters.unknown++;
						queries[i].complete = false;
					}
					queries[i].status = 2;
					found = true;
					break;
				}
			}
			if(!found)
			{
				// This may happen e.g. if the original query was a PTR query or "pi.hole"
				// as we ignore them altogether
				free(forward);
				continue;
			}

			// Count only if current query has not been counted so far
			if(queries[i].complete)
			{
				free(forward);
				continue;
			}

			// Get ID of forward destination, create new forward destination record
			// if not found in current data structure
			int forwardID = findForwardID(forward, true);
			queries[i].forwardID = forwardID;

			// Release allocated memory
			free(forward);

			// Get time index
			int timeidx = getTimeIndex(readbuffer);

			// Update overTime data structure with the new forwarder
			validate_access_oTfd(timeidx, forwardID, __LINE__, __FUNCTION__, __FILE__);
			overTime[timeidx].forwarddata[forwardID]++;

			if(!queries[i].complete)
			{
				// This query is no longer unknown ...
				counters.unknown--;
				// ... but got forwarded
				counters.forwardedqueries++;
				// Hereby, this query is now fully determined
				queries[i].complete = true;
			}
		}
		// is this a "cached" line?
		else if((strstr(readbuffer," cached ") != NULL || \
			     strstr(readbuffer,"/local.list ") != NULL || \
			     strstr(readbuffer,"/hostname.list ") != NULL || \
			     strstr(readbuffer," DHCP ") != NULL || \
			     strstr(readbuffer," /etc/hosts ") != NULL) \
			  && strstr(readbuffer," is ") != NULL)
		{
			// Check query for invalid characters
			if(!checkQuery(readbuffer, "cached"))
				continue;

			// Get dnsmasq's ID for this transaction
			int dnsmasqID = getdnsmasqID(readbuffer);
			// Skip invalid lines
			if(dnsmasqID < 0)
				continue;

			// Save status in corresponding query indentified by dnsmasq's ID
			bool found = false;
			for(i=0; i<counters.queries; i++)
			{
				// Check both UUID and generation of this query
				if(queries[i].id == dnsmasqID && queries[i].generation == loggeneration)
				{
					queries[i].status = 3;
					found = true;
					break;
				}
			}
			if(!found)
			{
				// This may happen e.g. if the original query was a PTR query or "pi.hole"
				// as we ignore them altogether
				continue;
			}

			if(!queries[i].complete)
			{
				// This query is no longer unknown ...
				counters.unknown--;
				// ... but answered from local cache _or_ local config
				counters.cached++;
				// Hereby, this query is now fully determined
				queries[i].complete = true;

				// Get time index
				int timeidx = getTimeIndex(readbuffer);
				validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				overTime[timeidx].cached++;
			}
		}
		// is this a "wildcard" line?
		else if(strstr(readbuffer," config ") != NULL && strstr(readbuffer," is ") != NULL)
		{
			// Check query for invalid characters
			if(!checkQuery(readbuffer, "config"))
				continue;

			// Get dnsmasq's ID for this transaction
			int dnsmasqID = getdnsmasqID(readbuffer);
			// Skip invalid lines
			if(dnsmasqID < 0)
				continue;

			// Save status in corresponding query indentified by dnsmasq's ID
			bool found = false;
			for(i=0; i<counters.queries; i++)
			{
				// Check both UUID and generation of this query
				if(queries[i].id == dnsmasqID && queries[i].generation == loggeneration)
				{
					queries[i].status = detectStatus(domains[queries[i].domainID].domain);
					found = true;
					break;
				}
			}
			if(!found)
			{
				// This may happen e.g. if the original query was a PTR query or "pi.hole"
				// as we ignore them altogether
				continue;
			}

			if(!queries[i].complete)
			{
				// This query is no longer unknown
				counters.unknown--;
				// Hereby, this query is now fully determined
				queries[i].complete = true;

				// Get time index
				int timeidx = getTimeIndex(readbuffer);

				// Decide what to do depening on the result of detectStatus()
				if(queries[i].status == 4)
				{
					// Blocked due to a matching wildcard rule
					counters.wildcardblocked++;

					validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[timeidx].blocked++;
					validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
					domains[queries[i].domainID].blockedcount++;
					domains[queries[i].domainID].wildcard = true;
				}
				else if(queries[i].status == 3)
				{
					// Answered from a custom (user provided) cache file
					counters.cached++;

					validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
					overTime[timeidx].cached++;
				}
			}
		}

		// is this a "black.list" line?
		else if(strstr(readbuffer,"/black.list ") != NULL && strstr(readbuffer," is ") != NULL)
		{
			// Check query for invalid characters
			if(!checkQuery(readbuffer, "black.list"))
				continue;

			// Get dnsmasq's ID for this transaction
			int dnsmasqID = getdnsmasqID(readbuffer);
			// Skip invalid lines
			if(dnsmasqID < 0)
				continue;

			// Save status in corresponding query indentified by dnsmasq's ID
			bool found = false;
			for(i=0; i<counters.queries; i++)
			{
				// Check both UUID and generation of this query
				if(queries[i].id == dnsmasqID && queries[i].generation == loggeneration)
				{
					queries[i].status = 5;
					found = true;
					break;
				}
			}
			if(!found)
			{
				// This may happen e.g. if the original query was a PTR query or "pi.hole"
				// as we ignore them altogether
				continue;
			}

			if(!queries[i].complete)
			{
				// This query is no longer unknown
				counters.unknown--;
				// ... but got blocked by user's black list
				counters.blocked++;
				// Hereby, this query is now fully determined
				queries[i].complete = true;

				// Get time index
				int timeidx = getTimeIndex(readbuffer);
				validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
				overTime[timeidx].blocked++;
				validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
				domains[queries[i].domainID].blockedcount++;
			}
		}
		// Is dnsmasq restarted? If yes, then we have to increment the log generation
		// as the following UUIDs will again start at zero...
		else if(strstr(readbuffer,"IPv6") != NULL &&
		        strstr(readbuffer,"DBus") != NULL &&
		        strstr(readbuffer,"i18n") != NULL &&
		        strstr(readbuffer,"DHCP") != NULL)
		{
			loggeneration++;
			if(debug) logg("Detected restart of dnsmasq, increasing loggeneration to %i", loggeneration);
		}

		// is this a "reply" line?
		else if(strstr(readbuffer," reply ") != NULL && strstr(readbuffer," is ") != NULL)
		{
			// Check query for invalid characters
			if(!checkQuery(readbuffer, "reply"))
				continue;

			// Get dnsmasq's ID for this transaction
			int dnsmasqID = getdnsmasqID(readbuffer);
			// Skip invalid lines
			if(dnsmasqID < 0)
				continue;

			// Search for corresponding query indentified by dnsmasq's ID
			bool found = false;
			for(i=0; i<counters.queries; i++)
			{
				// Check both UUID and generation of this query
				if(queries[i].id == dnsmasqID && queries[i].generation == loggeneration)
				{
					found = true;
					break;
				}
			}

			if(!found)
			{
				// This may happen e.g. if the original query was a PTR query or "pi.hole"
				// as we ignore them altogether
				continue;
			}

			if(queries[i].reply != 0)
			{
				// Skip this entry if we already found the first result for this query before
				continue;
			}

			// Iterate through possible values
			if(strstr(readbuffer," is NODATA") != NULL)
			{
				// NODATA(-IPv6)
				queries[i].reply = 1;
				counters.reply_NODATA++;
			}
			else if(strstr(readbuffer," is NXDOMAIN") != NULL)
			{
				// NXDOMAIN
				queries[i].reply = 2;
				counters.reply_NXDOMAIN++;
			}
			else if(strstr(readbuffer," is <CNAME>") != NULL)
			{
				// <CNAME>
				queries[i].reply = 3;
				counters.reply_CNAME++;
			}
			else
			{
				// Valid IP
				queries[i].reply = 4;
				counters.reply_IP++;
				// const char * dest = strstr(readbuffer," is ");
				// char * result;
				// sscanf(dest, " is %ms", &result);
				// printf("reply is IP: %s\n",result);
				// free(result);
			}
		}
		// is this a "validaton" line? -- DNSSEC
		else if(strstr(readbuffer," validation ") != NULL && strstr(readbuffer," is ") != NULL)
		{
			// Check query for invalid characters
			if(!checkQuery(readbuffer, "DNSSEC"))
				continue;

			// Get dnsmasq's ID for this transaction
			int dnsmasqID = getdnsmasqID(readbuffer);
			// Skip invalid lines
			if(dnsmasqID < 0)
				continue;

			// Search for corresponding query indentified by dnsmasq's ID
			bool found = false;
			for(i=0; i<counters.queries; i++)
			{
				// Check both UUID and generation of this query
				if(queries[i].id == dnsmasqID && queries[i].generation == loggeneration)
				{
					found = true;
					break;
				}
			}

			if(!found)
			{
				// This may happen e.g. if the original query was a PTR query or "pi.hole"
				// as we ignore them altogether
				continue;
			}

			validate_access("domains", queries[i].domainID, true, __LINE__, __FUNCTION__, __FILE__);
			// Iterate through possible values
			if(strstr(readbuffer,"is SECURE") != NULL)
			{
				domains[queries[i].domainID].dnssec = DNSSEC_SECURE;
			}
			else if(strstr(readbuffer,"is INSECURE") != NULL)
			{
				domains[queries[i].domainID].dnssec = DNSSEC_INSECURE;
			}
			else if(strstr(readbuffer,"is BOGUS") != NULL)
			{
				domains[queries[i].domainID].dnssec = DNSSEC_BOGUS;
			}
			else if(strstr(readbuffer,"is ABANDONED") != NULL)
			{
				domains[queries[i].domainID].dnssec = DNSSEC_ABANDONED;
			}
			else
			{
				// Unknown
				domains[queries[i].domainID].dnssec = DNSSEC_UNKNOWN;
				if(debug) logg("Unknown DNSSEC reply: %i\n\"%s\"",dnsmasqID,readbuffer);
			}
		}


		// Save file pointer position, because we might have to repeat
		// reading the next line if dnsmasq hasn't finished writing it
		// (see beginning of this loop)
		fposbck = ftell(fp);

		// Return early if data structure is flushed
		if(checkLogForChanges() < 0)
		{
			logg("Notice: Returning early from log parsing for flushing");
			fclose(fp);
			flush = true;
			return;
		}
	}

	if(errno == ENOMEM)
		logg("WARN: process_pihole_log failed: could not allocate memory for getline");

	// Free memory allocated by readline
	if(readbuffer != NULL)
		free(readbuffer);

	// We want to store the last read position so that we can jump to this position in the next round
	lastpos = ftell(fp);

	// Close file when parsing is finished
	fclose(fp);
}

bool isValidIPv4(const char *addr)
{
	struct sockaddr_in sa;
	return inet_pton(AF_INET, addr, &(sa.sin_addr)) != 0;
}

bool isValidIPv6(const char *addr)
{
	struct sockaddr_in6 sa;
	return inet_pton(AF_INET6, addr, &(sa.sin6_addr)) != 0;
}

char *resolveHostname(const char *addr)
{
	// Get host name
	struct hostent *he = NULL;
	char *hostname;
	bool IPv6 = false;

	// Test if we want to resolve an IPv6 address
	if(strstr(addr,":") != NULL)
	{
		IPv6 = true;
	}

	if(IPv6 && config.resolveIPv6) // Resolve IPv6 address only if requested
	{
		struct in6_addr ipaddr;
		inet_pton(AF_INET6, addr, &ipaddr);
		he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET6);
	}
	else if(!IPv6 && config.resolveIPv4) // Resolve IPv4 address only if requested
	{
		struct in_addr ipaddr;
		inet_pton(AF_INET, addr, &ipaddr);
		he = gethostbyaddr(&ipaddr, sizeof ipaddr, AF_INET);
	}

	if(he == NULL)
	{
		// No hostname found
		hostname = calloc(1,sizeof(char));
		hostname[0] = '\0';
	}
	else
	{
		// Return hostname copied to new memory location
		hostname = strdup(he->h_name);
		// Convert hostname to lower case
		strtolower(hostname);
	}

	return hostname;
}

int detectStatus(const char *domain)
{
	// Try to find the domain in the array of wildcard blocked domains
	int i;
	for(i=0; i < counters.wildcarddomains; i++)
	{
		validate_access("wildcarddomains", i, false, __LINE__, __FUNCTION__, __FILE__);
		if(strcasecmp(wildcarddomains[i], domain) == 0)
		{
			// Exact match with wildcard domain
			// if(debug)
			// 	printf("%s / %s (exact wildcard match)\n",wildcarddomains[i], domain);
			return 4;
		}
		// Create copy of domain under investigation
		char * part = strdup(domain);
		if(part == NULL)
		{
			// String duplication / memory allocation failed
			logg("Notice: Memory allocation for part in detectStatus failed, domain: \"%s\"", domain);
			continue;
		}
		char * partbuffer = calloc(strlen(part)+1, sizeof(char));
		if(partbuffer == NULL)
		{
			// Memory allocation failed
			logg("Notice: Memory allocation for partbuffer in detectStatus failed, domain: \"%s\"", domain);
			continue;
		}

		// Strip subdomains one after another and
		// compare to existing wildcard entries
		while(sscanf(part,"%*[^.].%s", partbuffer) > 0)
		{
			// Test for a match
			if(strcasecmp(wildcarddomains[i], partbuffer) == 0)
			{
				// Free allocated memory before return'ing
				free(part);
				free(partbuffer);
				// Return match with wildcard domain
				// if(debug)
				// 	printf("%s / %s (wildcard match)\n",wildcarddomains[i], partbuffer);
				return 4;
			}
			if(strlen(partbuffer) > 0)
			{
				// Empty part
				*part = '\0';
				// Replace with partbuffer
				strcat(part, partbuffer);
			}
		}
		// Free allocated memory
		free(part);
		free(partbuffer);
	}

	// If not found -> this answer is not from
	// wildcard blocking, but from e.g. an
	// address=// configuration
	// Answer as "cached"
	return 3;
}

void extracttimestamp(const char *readbuffer, int *querytimestamp, int *overTimetimestamp)
{
	// Get timestamp
	// char timestamp[16]; <- declared in FTL.h
	memset(&timestamp, 0, sizeof(timestamp));
	// strncat() NULL-terminates the copied string (strncpy() doesn't!)
	strncat(timestamp,readbuffer,(size_t)15);

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

	// Year is missing in dnsmasq's output so we have to take care of it
	if(querytime.tm_mon == 11 && (*timeinfo).tm_mon == 0)
	{
		// Special case: read timestamp in December (e.g. 2017), but current
		// month is already January (e.g. 2018) -> use (year-1) for this timestamp
		// Note that months are counted from January on, i.e.
		// January == 0, December == 11
		querytime.tm_year = (*timeinfo).tm_year - 1;
	}
	else
	{
		// In all other cases: Use current year
		querytime.tm_year = (*timeinfo).tm_year;
	}

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

int findForwardID(const char * forward, bool count)
{
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
			if(count) forwarded[forwardID].count++;
			return forwardID;
		}
	}
	// This forward server is not known
	// Store ID
	forwardID = counters.forwarded;
	// Get forward destination host name
	char *hostname = resolveHostname(forward);
	if(strlen(hostname) > 0)
	{
		// Convert hostname to lower case
		strtolower(hostname);
		logg("New forward server: %s %s (%i/%i)", forward, hostname, forwardID, counters.forwarded_MAX);
	}
	else
		logg("New forward server: %s (%i/%u)", forward, forwardID, counters.forwarded_MAX);

	validate_access("forwarded", forwardID, false, __LINE__, __FUNCTION__, __FILE__);
	// Set magic byte
	forwarded[forwardID].magic = MAGICBYTE;
	// Initialize its counter
	if(count)
		forwarded[forwardID].count = 1;
	else
		forwarded[forwardID].count = 0;
	// Save IP
	forwarded[forwardID].ip = strdup(forward);
	memory.forwardedips += (strlen(forward) + 1) * sizeof(char);
	// Save forward destination host name
	forwarded[forwardID].name = strdup(hostname);
	memory.forwardednames += (strlen(hostname) + 1) * sizeof(char);
	free(hostname);
	// Increase counter by one
	counters.forwarded++;

	return forwardID;
}

int findDomainID(const char *domain)
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

	// If we did not return until here, then this domain is not known
	// Store ID
	int domainID = counters.domains;
	// // Debug output
	if(debug) logg("New domain: %s (%i/%i)", domain, domainID, counters.domains_MAX);
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
	// Store DNSSEC result for this domain
	domains[domainID].dnssec = DNSSEC_UNSPECIFIED;
	// Increase counter by one
	counters.domains++;

	return domainID;
}

int findClientID(const char *client)
{
	int i;
	// Compare content of client against known client IP addresses
	for(i=0; i < counters.clients; i++)
	{
		validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
		// Quick test: Does the clients IP start with the same character?
		if(clients[i].ip[0] != client[0])
			continue;

		// If so, compare the full IP using strcmp
		if(strcmp(clients[i].ip, client) == 0)
		{
			clients[i].count++;
			return i;
		}
	}
	// If we did not return until here, then this client is either
	// a) new or
	// b) only known by its hostname (after importing from the database)

	// First try to resolve the IP to a hostname to compare again
	char *hostname = NULL;
	if(isValidIPv4(client) || isValidIPv6(client))
	{
		hostname = resolveHostname(client);

		// Compare again with resolved host name if resoltuino succeeded
		if(hostname[0] != '\0')
		{
			for(i=0; i < counters.clients; i++)
			{
				validate_access("clients", i, true, __LINE__, __FUNCTION__, __FILE__);
				// Quick test: Does the clients host name start with the same character?
				if(clients[i].name[0] != hostname[0])
					continue;

				// If so, compare the full host name using strcmp
				if(strcmp(clients[i].name, hostname) == 0)
				{
					// Store IP address
					free(clients[i].ip);
					clients[i].ip = strdup(client);

					clients[i].count++;
					return i;
				}
			}
		}
	}
	else
	{
		hostname = strdup(client);
	}

	// If we did not return until here, then this client is definitely new
	// Store ID
	int clientID = counters.clients;

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
	clients[clientID].ip = strdup(client);
	memory.clientips += (strlen(client) + 1) * sizeof(char);
	// Store client hostname
	clients[clientID].name = strdup(hostname);
	memory.clientnames += (strlen(hostname) + 1) * sizeof(char);
	free(hostname);
	// Increase counter by one
	counters.clients++;

	return clientID;
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

void validate_access_oTfd(int timeidx, int forwardID, int line, const char * function, const char * file)
{
	// Determine if there is enough space for saving the current
	// forwardID in the overTime data structure, allocate space otherwise
	validate_access("overTime", timeidx, true, __LINE__, __FUNCTION__, __FILE__);
	if(overTime[timeidx].forwardnum <= forwardID)
	{
		// Reallocate more space for forwarddata
		overTime[timeidx].forwarddata = realloc(overTime[timeidx].forwarddata, (forwardID+1)*sizeof(*overTime[timeidx].forwarddata));
		// Initialize new data fields with zeroes
		int j;
		for(j = overTime[timeidx].forwardnum; j <= forwardID; j++)
		{
			overTime[timeidx].forwarddata[j] = 0;
			memory.forwarddata++;
		}
		// Update counter
		overTime[timeidx].forwardnum = forwardID + 1;
	}

	int limit = overTime[timeidx].forwardnum;
	if(forwardID >= limit || forwardID < 0)
	{
		logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		logg("FATAL ERROR: Trying to access overTime.forwarddata[%i], but maximum is %i", forwardID, limit);
		logg("             found in %s() (line %i) in %s", function, line, file);
	}
}

void validate_access_oTcl(int timeidx, int clientID, int line, const char * function, const char * file)
{
	// Determine if there is enough space for saving the current
	// clientID in the overTime data structure, allocate space otherwise
	if(overTime[timeidx].clientnum <= clientID)
	{
		// Reallocate more space for clientdata
		overTime[timeidx].clientdata = realloc(overTime[timeidx].clientdata, (clientID+1)*sizeof(*overTime[timeidx].clientdata));
		// Initialize new data fields with zeroes
		int i;
		for(i = overTime[timeidx].clientnum; i <= clientID; i++)
		{
			overTime[timeidx].clientdata[i] = 0;
			memory.clientdata++;
		}
		// Update counter
		overTime[timeidx].clientnum = clientID + 1;
	}
	int limit = overTime[timeidx].clientnum;
	if(clientID >= limit || clientID < 0)
	{
		logg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		logg("FATAL ERROR: Trying to access overTime.clientdata[%i], but maximum is %i", clientID, limit);
		logg("             found in %s() (line %i) in %s", function, line, file);
	}
}

void reresolveHostnames(void)
{
	int clientID;
	for(clientID = 0; clientID < counters.clients; clientID++)
	{
		// Memory validation
		validate_access("clients", clientID, true, __LINE__, __FUNCTION__, __FILE__);

		// Process this client only if it has at least one active query in the log
		if(clients[clientID].count < 1)
			continue;

		// Get client hostname
		char *hostname = resolveHostname(clients[clientID].ip);
		if(strlen(hostname) > 0)
		{
			// Delete possibly already existing hostname pointer before storing new data
			if(clients[clientID].name != NULL)
			{
				memory.clientnames -= (strlen(clients[clientID].name) + 1) * sizeof(char);
				free(clients[clientID].name);
				clients[clientID].name = NULL;
			}

			// Store client hostname
			clients[clientID].name = strdup(hostname);
			memory.clientnames += (strlen(hostname) + 1) * sizeof(char);
		}
		free(hostname);
	}
}

int findOverTimeID(int overTimetimestamp)
{
	int timeidx = -1, i;
	// Check struct size
	memory_check(OVERTIME);
	for(i=0; i < counters.overTime; i++)
	{
		validate_access("overTime", i, true, __LINE__, __FUNCTION__, __FILE__);
		if(overTime[i].timestamp == overTimetimestamp)
			return i;
	}
	// We loop over this to fill potential data holes with zeros
	int nexttimestamp = 0;
	if(counters.overTime != 0)
	{
		validate_access("overTime", counters.overTime-1, false, __LINE__, __FUNCTION__, __FILE__);
		nexttimestamp = overTime[counters.overTime-1].timestamp + 600;
	}
	else
	{
		nexttimestamp = overTimetimestamp;
	}

	while(overTimetimestamp >= nexttimestamp)
	{
		// Check struct size
		memory_check(OVERTIME);
		timeidx = counters.overTime;
		validate_access("overTime", timeidx, false, __LINE__, __FUNCTION__, __FILE__);
		// Set magic byte
		overTime[timeidx].magic = MAGICBYTE;
		overTime[timeidx].timestamp = nexttimestamp;
		overTime[timeidx].total = 0;
		overTime[timeidx].blocked = 0;
		overTime[timeidx].cached = 0;
		overTime[timeidx].forwardnum = 0;
		overTime[timeidx].forwarddata = NULL;
		overTime[timeidx].querytypedata = calloc(2, sizeof(int));
		overTime[timeidx].clientnum = 0;
		overTime[timeidx].clientdata = NULL;
		memory.querytypedata += 2*sizeof(int);
		counters.overTime++;

		// Update time stamp for next loop interation
		if(counters.overTime != 0)
		{
			validate_access("overTime", counters.overTime-1, false, __LINE__, __FUNCTION__, __FILE__);
			nexttimestamp = overTime[counters.overTime-1].timestamp + 600;
		}
	}
	return timeidx;
}
