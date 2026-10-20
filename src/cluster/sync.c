/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster configuration synchronization
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "config/config.h"
#include "config/dnsmasq_config.h"
#include "config/toml_writer.h"
#include "cluster/cluster.h"
// cluster_vip_shutdown()
#include "cluster/dhcp.h"
// cluster_plain_id()
#include "cluster/auth.h"
#include "cluster/http.h"
// git_version()
#include "version.h"
#include "cluster/sync.h"
// vip_note_placed()
#include "cluster/vip.h"
#include <pthread.h>
// addJSONConfValue(), getJSONvalue()
#include "api/api.h"
// restart_ftl()
#include "signals.h"
// ERRBUF_SIZE
#include "config/dnsmasq_config.h"

// read_teleporter_zip()
#include "zip/teleporter.h"
// log_cluster_message()
#include "database/message-table.h"
// sqlite3
#include "database/sqlite3.h"
// gravity_running
#include "daemon.h"
// generate_password()
#include "config/password.h"
// chown_pihole()
#include "files.h"
#include <fcntl.h>
// isalnum()
#include <ctype.h>
#include <math.h>
#include <stdint.h>
// lock_shm()
#include "shmem.h"
#include <sys/wait.h>
// SYS_close_range
#include <sys/syscall.h>
// PATH_MAX
#include <limits.h>
// sleepms()
#include "timers.h"
#include <fcntl.h>
#include <sys/stat.h>

// The gravity script, which lives outside FTL
#define PIHOLE_BINARY "/usr/local/bin/pihole"

// Columns holding the outcome of the last gravity run rather than something a
// user entered. They differ between nodes by design - each one builds its own
// blocking database - so counting them as a change would have every gravity run
// look like an edit worth synchronizing
static const char *run_columns[] = {
	"date_updated",
	"number",
	"invalid_domains",
	"status",
	"abp_entries"
};

// The list tables a Teleporter archive carries. Identical to the tables the
// Teleporter itself exports, so a pull is a complete replacement of what the
// other node has
static const char *gravity_tables[] = {
	"group",
	"adlist",
	"adlist_by_group",
	"domainlist",
	"domainlist_by_group",
	"client",
	"client_by_group"
};

// FNV-1a. We are only comparing two nodes' fingerprints for equality, so a
// non-cryptographic hash is enough - a collision delays a synchronization, it
// cannot forge one
static void hash_add(uint64_t *hash, const char *str)
{
	if(str == NULL)
		return;

	for(const char *p = str; *p != '\0'; p++)
	{
		*hash ^= (uint64_t)(unsigned char)*p;
		*hash *= 0x00000100000001B3ULL;
	}
}

static void hash_str(const uint64_t hash, char out[CLUSTER_HASHLEN])
{
	snprintf(out, CLUSTER_HASHLEN, "%016llx", (unsigned long long)hash);
}

// Fingerprint of the synchronized configuration items
// Which of the three fingerprints an item belongs in
// The credentials are hashed on their own rather than folded into the
// comparable fingerprint. Whether they travel between two particular nodes
// depends on what each of them accepts, which is a decision each makes for
// itself - so a single fingerprint covering them would have two nodes compare
// values that can never converge, and report a difference that never resolves
enum hash_scope { SCOPE_SETTINGS, SCOPE_CREDENTIALS };

// Items forced through the environment are part of it: the two nodes have to
// hash the same set of items or they never agree, and neither can know what the
// other pins
static void config_hash_scope(const enum hash_scope scope, char out[CLUSTER_HASHLEN])
{
	uint64_t hash = 0xcbf29ce484222325ULL;

	// The values are read straight out of the live configuration, which
	// another thread replaces - and frees the old strings and cJSON trees of
	// - while we walk it
	lock_shm();
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		struct conf_item *item = get_conf_item(&config, i);
		const bool credential = item->f & FLAG_CREDENTIAL;

		switch(scope)
		{
			case SCOPE_SETTINGS:
				// Everything that may travel except the
				// credentials, whatever the transport is
				if(credential || !cluster_hashable_ignoring_transport(item))
					continue;
				break;

			case SCOPE_CREDENTIALS:
				// ...and the credentials on their own
				if(!credential || !cluster_hashable_ignoring_transport(item))
					continue;
				break;
		}

		cJSON *val = addJSONConfValue(item->t, &item->v);
		char *str = cJSON_PrintUnformatted(val);
		hash_add(&hash, item->k);
		hash_add(&hash, "=");
		hash_add(&hash, str);
		free(str);
		cJSON_Delete(val);
	}
	unlock_shm();

	hash_str(hash, out);
}

void cluster_config_hash(char out[CLUSTER_HASHLEN])
{
	config_hash_scope(SCOPE_SETTINGS, out);
}

void cluster_credentials_hash(char out[CLUSTER_HASHLEN])
{
	config_hash_scope(SCOPE_CREDENTIALS, out);
}

// What each item hashes to, for comparing this node against its own past. Zero
// for an item that never takes part and for one pinned through the environment:
// nothing here can change those, and `webserver.api.pwhash` derived from
// FTLCONF_webserver_api_password gets a fresh salt at every start
static void item_hashes(uint64_t out[CONFIG_ELEMENTS])
{
	lock_shm();
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		struct conf_item *item = get_conf_item(&config, i);
		out[i] = 0;
		if(!cluster_hashable_ignoring_transport(item) || config_env_pinned(item))
			continue;

		uint64_t hash = 0xcbf29ce484222325ULL;
		cJSON *val = addJSONConfValue(item->t, &item->v);
		char *str = cJSON_PrintUnformatted(val);
		hash_add(&hash, item->k);
		hash_add(&hash, "=");
		hash_add(&hash, str);
		free(str);
		cJSON_Delete(val);
		out[i] = hash;
	}
	unlock_shm();
}

// When each item was last changed, here or on the peer it was taken from. Zero
// for an item nobody changed and for every item that never leaves a node
static double item_changed[CONFIG_ELEMENTS] = { 0.0 };
static pthread_mutex_t item_changed_lock = PTHREAD_MUTEX_INITIALIZER;

// The index of the item with this key, -1 for a key this build does not know
int cluster_item_index(const char *key)
{
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
		if(strcmp(get_conf_item(&config, i)->k, key) == 0)
			return (int)i;

	return -1;
}

double cluster_item_changed(const unsigned int i)
{
	pthread_mutex_lock(&item_changed_lock);
	const double changed = i < CONFIG_ELEMENTS ? item_changed[i] : 0.0;
	pthread_mutex_unlock(&item_changed_lock);

	return changed;
}

void cluster_item_stamps(double out[CONFIG_ELEMENTS])
{
	pthread_mutex_lock(&item_changed_lock);
	memcpy(out, item_changed, sizeof(item_changed));
	pthread_mutex_unlock(&item_changed_lock);
}

// Never later than now: a stamp from the future outranks every change anybody
// makes until wall time catches up with it. Written to disk straight away, as
// a setting that asks FTL to restart takes the daemon down within the second
void cluster_stamp_items(const bool which[CONFIG_ELEMENTS], const double when[CONFIG_ELEMENTS])
{
	const double now = double_time();
	pthread_mutex_lock(&item_changed_lock);
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
		if(which[i])
			item_changed[i] = when[i] > now ? now : when[i];
	pthread_mutex_unlock(&item_changed_lock);

	cluster_state_save(NULL);
}

// What this node kept its own value of in the last push that dated anything,
// as "key (why), ...", for the status
static char refused_items[512] = "";
static pthread_mutex_t refused_lock = PTHREAD_MUTEX_INITIALIZER;

void cluster_note_refused(const char *items)
{
	pthread_mutex_lock(&refused_lock);
	strncpy(refused_items, items, sizeof(refused_items) - 1);
	refused_items[sizeof(refused_items) - 1] = '\0';
	pthread_mutex_unlock(&refused_lock);
}

void cluster_refused_items(char *out, const size_t outlen)
{
	pthread_mutex_lock(&refused_lock);
	strncpy(out, refused_items, outlen - 1);
	out[outlen - 1] = '\0';
	pthread_mutex_unlock(&refused_lock);
}

// The newest of them, repaired where kept: a clock that stepped backwards
// leaves stamps from the future behind, which no peer accepts
double cluster_newest_change(void)
{
	const double now = double_time();
	double newest = 0.0;
	pthread_mutex_lock(&item_changed_lock);
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		if(item_changed[i] > now)
			item_changed[i] = now;
		if(item_changed[i] > newest)
			newest = item_changed[i];
	}
	pthread_mutex_unlock(&item_changed_lock);

	return newest;
}

static bool is_run_column(const char *name)
{
	if(name == NULL)
		return false;

	for(size_t i = 0; i < ArraySize(run_columns); i++)
		if(strcmp(name, run_columns[i]) == 0)
			return true;

	return false;
}

// Fingerprint of the given list tables. A Teleporter import replaces them row
// by row (ids and timestamps included), so two synchronized nodes really do
// arrive at the same value here
// False when the database could not be read all the way through. A partial
// fingerprint is indistinguishable from a real one, and the caller would take it
// for a change made here - stamping this node as holding the newest lists and
// then replacing a peer's genuine edit with what is in fact a read error
static bool tables_hash(const char **tables, const size_t num_tables, char out[CLUSTER_HASHLEN])
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	sqlite3 *db = NULL;

	// The path is a configuration item another thread may replace while
	// sqlite is holding on to it
	char dbfile[PATH_MAX] = "";
	lock_shm();
	strncpy(dbfile, config.files.gravity.v.s, sizeof(dbfile) - 1);
	unlock_shm();

	if(sqlite3_open_v2(dbfile, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK)
	{
		log_debug(DEBUG_CLUSTER, "cluster: cannot open %s: %s",
		          dbfile, sqlite3_errmsg(db));
		sqlite3_close(db);
		// A fingerprint we cannot compute must not look like a match with
		// a node that has one
		hash_str(0, out);
		return false;
	}

	// A gravity run holds the database for a while, and a read that gives up
	// half way through would look like a change
	sqlite3_busy_timeout(db, 2000);

	for(size_t i = 0; i < num_tables; i++)
	{
		char querystr[128] = "";
		snprintf(querystr, sizeof(querystr), "SELECT * FROM \"%s\"", tables[i]);

		sqlite3_stmt *stmt = NULL;
		if(sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL) != SQLITE_OK)
		{
			log_debug(DEBUG_CLUSTER, "cluster: cannot hash table %s: %s",
			          tables[i], sqlite3_errmsg(db));
			sqlite3_close(db);
			hash_str(0, out);
			return false;
		}

		// The rows are hashed individually and combined by addition: the
		// group mapping tables have no rowid to sort by, so the order two
		// nodes see them in is not guaranteed to be the same
		uint64_t table = 0;
		int rc = 0;
		while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
		{
			uint64_t row = 0xcbf29ce484222325ULL;
			const int columns = sqlite3_column_count(stmt);
			for(int c = 0; c < columns; c++)
			{
				if(is_run_column(sqlite3_column_name(stmt, c)))
					continue;

				hash_add(&row, (const char *)sqlite3_column_text(stmt, c));
				hash_add(&row, "\x1f");
			}
			table += row;
		}
		sqlite3_finalize(stmt);

		// Busy, locked, an I/O error or a corrupt page all end the loop
		// the same way a finished table does
		if(rc != SQLITE_DONE)
		{
			log_debug(DEBUG_CLUSTER, "cluster: cannot read table %s: %s",
			          tables[i], sqlite3_errstr(rc));
			sqlite3_close(db);
			hash_str(0, out);
			return false;
		}

		char tablehash[64] = "";
		snprintf(tablehash, sizeof(tablehash), "%s=%016llx",
		         tables[i], (unsigned long long)table);
		hash_add(&hash, tablehash);
	}

	sqlite3_close(db);
	hash_str(hash, out);

	return true;
}

// What each item hashed to when this node last recorded it, and the lock around
// it: two webserver threads can install a configuration at once. Taken over a
// fixed set of items, so it stays comparable with the last time even when the
// member list turns https:// and changes what may actually travel
static uint64_t stamped_items[CONFIG_ELEMENTS] = { 0 };
static pthread_mutex_t stamped_lock = PTHREAD_MUTEX_INITIALIZER;

// Which items did this change touch that the cluster synchronizes? A debug
// flag, a path or this node's own name are not among them, and dating those
// would make a node nobody configured outrank the nodes somebody did
bool cluster_config_moved(bool moved[CONFIG_ELEMENTS])
{
	uint64_t now[CONFIG_ELEMENTS];
	item_hashes(now);

	bool any = false;
	pthread_mutex_lock(&stamped_lock);
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		moved[i] = now[i] != 0 && now[i] != stamped_items[i];
		any |= moved[i];
		stamped_items[i] = now[i];
	}
	pthread_mutex_unlock(&stamped_lock);

	return any;
}

// The DHCP leases, which are neither configuration nor a list: they are what
// the node handing out addresses knows about the clients it handed them to.
// Exactly one node serves DHCP at a time, so there is exactly one writer, and
// the file is only ever opened by dnsmasq when this node is that one - which is
// what makes it safe for the cluster to keep the file current on the others
//
// A node taking DHCP over restarts FTL, and dnsmasq reads the lease file when
// it starts. So a standby whose copy is current takes over knowing every lease,
// and the clients it inherits keep the addresses they already have

// The fingerprint of a lease file this node holds in memory, so what arrives
// from a peer can be checked against what that peer said it was sending
void cluster_leases_hash_bytes(const uint8_t *data, const size_t size, char out[CLUSTER_HASHLEN])
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	for(size_t i = 0; i < size; i++)
	{
		hash ^= (uint64_t)data[i];
		hash *= 0x00000100000001B3ULL;
	}

	hash_str(hash, out);
}

// One attempt at reading the file whole. Returns false without touching *data
// when the file moved while we were reading it, which the caller answers by
// trying again rather than by handing out half a lease database
static bool leases_read_once(uint8_t **data, size_t *size)
{
	struct stat before = { 0 };
	if(stat(DHCPLEASESFILE, &before) != 0)
		return false;

	FILE *fp = fopen(DHCPLEASESFILE, "rb");
	if(fp == NULL)
		return false;

	if(fseek(fp, 0, SEEK_END) != 0)
	{
		fclose(fp);
		return false;
	}

	const long len = ftell(fp);
	if(len < 0 || (unsigned long)len > CLUSTER_MAX_LEASES_SIZE || fseek(fp, 0, SEEK_SET) != 0)
	{
		fclose(fp);
		return false;
	}

	// An empty lease file is a fact worth carrying: a node that handed out
	// nothing, or whose leases all expired, is not a node we failed to read
	uint8_t *buf = calloc((size_t)len + 1, sizeof(uint8_t));
	if(buf == NULL)
	{
		fclose(fp);
		return false;
	}

	const size_t got = len > 0 ? fread(buf, 1, (size_t)len, fp) : 0;
	if(got != (size_t)len)
	{
		free(buf);
		fclose(fp);
		return false;
	}

	// dnsmasq rewrites this file in place - rewind, truncate to nothing, write
	// it out again - so a read that lands inside that window returns a file
	// that is genuinely shorter than the leases it describes, and every byte
	// of it reads as valid.
	//
	// What says so is the size the file has once the read is done: a rewrite
	// that was in flight while we read has moved on from the length we saw,
	// while a file nobody touched still has exactly it. Timestamps do not say
	// so - Linux stamps them from a coarse clock, and a whole rewrite lands
	// inside one tick - so they are checked but never relied on
	struct stat after = { 0 };
	if(fstat(fileno(fp), &after) != 0 || after.st_size != (off_t)got ||
	   after.st_ino != before.st_ino ||
	   after.st_mtim.tv_sec != before.st_mtim.tv_sec ||
	   after.st_mtim.tv_nsec != before.st_mtim.tv_nsec)
	{
		free(buf);
		fclose(fp);
		return false;
	}

	// ...and a lease file is whole lines. A rewrite caught between two of
	// dnsmasq's buffered writes ends mid-record, which no complete file does
	if(got > 0 && buf[got - 1] != '\n')
	{
		free(buf);
		fclose(fp);
		return false;
	}

	fclose(fp);

	*data = buf;
	*size = got;

	return true;
}

bool cluster_leases_read(uint8_t **data, size_t *size)
{
	*data = NULL;
	*size = 0;

	// A busy DHCP server rewrites this often, but never for long. Trying a
	// few times costs microseconds and is the difference between handing a
	// standby every lease and handing it two thirds of them
	for(unsigned int attempt = 0; attempt < 4; attempt++)
	{
		if(leases_read_once(data, size))
			return true;

		// Long enough for a rewrite of any realistic lease file to finish.
		// Not thread_sleepms(): this also runs on a webserver thread
		// answering a peer, and that call would mark the cluster thread
		// cancellable on its behalf
		sleepms(20);
	}

	return false;
}

// What the peers compare. A file we cannot read is not "no leases": it is a
// node with nothing to say about them, which is what the empty string means
//
// Read again only when the file changed. Every peer polling this node asks for
// its status, and the node handing out addresses is the one with the largest
// lease file - hashing it once per poll would read that file N times per round
// on the one machine that is also running the DHCP server
bool cluster_leases_hash(char out[CLUSTER_HASHLEN])
{
	static char cached[CLUSTER_HASHLEN] = "";
	static ino_t inode = 0;
	static off_t size_seen = 0;
	static struct timespec modified = { 0 };
	static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

	out[0] = '\0';

	struct stat st = { 0 };
	if(stat(DHCPLEASESFILE, &st) != 0)
		return false;

	pthread_mutex_lock(&lock);

	// Down to the nanosecond: dnsmasq rewrites this file in place, so a
	// renewal that only moves an expiry timestamp leaves the inode and the
	// size exactly as they were, and whole seconds would miss it
	if(strlen(cached) > 0 && st.st_ino == inode && st.st_size == size_seen &&
	   st.st_mtim.tv_sec == modified.tv_sec && st.st_mtim.tv_nsec == modified.tv_nsec)
	{
		memcpy(out, cached, CLUSTER_HASHLEN);
		pthread_mutex_unlock(&lock);
		return true;
	}

	pthread_mutex_unlock(&lock);

	uint8_t *data = NULL;
	size_t size = 0;
	if(!cluster_leases_read(&data, &size))
		return false;

	cluster_leases_hash_bytes(data, size, out);
	free(data);

	// Stamped with what was on disk before the read rather than after it: a
	// write that lands while we are reading leaves us holding a hash of
	// neither version, and this way the next call reads it again
	pthread_mutex_lock(&lock);
	memcpy(cached, out, CLUSTER_HASHLEN);
	inode = st.st_ino;
	size_seen = st.st_size;
	modified = st.st_mtim;
	pthread_mutex_unlock(&lock);

	return true;
}

// Replace this node's copy with the serving node's. Written through a temporary
// file and renamed: a node that takes DHCP over reads this file at startup, and
// half of it is worse than none of it
bool cluster_leases_write(const uint8_t *data, const size_t size)
{
	char tmp[PATH_MAX] = "";
	snprintf(tmp, sizeof(tmp), "%s.cluster", DHCPLEASESFILE);

	// The mode dnsmasq's own lease file has, set as the file is created
	// rather than afterwards: the leases name every client on the network
	// and there must be no window where anybody may read them
	unlink(tmp);
	const int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
	                    S_IRUSR | S_IWUSR | S_IRGRP);
	FILE *fp = fd < 0 ? NULL : fdopen(fd, "wb");
	if(fp == NULL)
	{
		log_warn("cluster: cannot write %s: %s", tmp, strerror(errno));
		if(fd >= 0)
			close(fd);
		return false;
	}

	// ...and the owner it has, so the DHCP server can still write it once
	// this node is the one handing out addresses
	chown_pihole(tmp, NULL);

	const bool written = size == 0 || fwrite(data, 1, size, fp) == size;
	// Flushed and on the disk before the rename: the point of writing it
	// here is that it survives to the restart that reads it
	const bool flushed = written && fflush(fp) == 0 && fsync(fileno(fp)) == 0;
	fclose(fp);

	if(!flushed)
	{
		log_warn("cluster: cannot write %s", tmp);
		unlink(tmp);
		return false;
	}

	if(rename(tmp, DHCPLEASESFILE) != 0)
	{
		log_warn("cluster: cannot replace %s: %s", DHCPLEASESFILE, strerror(errno));
		unlink(tmp);
		return false;
	}

	return true;
}

// More leases than a failover between two Pi-holes ever produces. Past it the
// merge below is not run - the serving node's file is taken whole, as before
#define CLUSTER_LEASE_MERGE_MAX 8192u

// A lease line sliced out of a file being merged. In a dnsmasq lease file the
// expiry is the first field and the address the third, for IPv4 and IPv6 lines
// alike; an expiry of zero is dnsmasq's infinite lease
struct lease_line {
	const char *line;
	size_t len;
	const char *addr;
	size_t addrlen;
	unsigned long expiry;
	bool infinite;
};

// The vendorclass/agent-info continuation lines, kept with the lease they
// extend - keyed, like the lease, by the address in their second field
struct lease_extra {
	const char *line;
	size_t len;
	const char *addr;
	size_t addrlen;
};

struct lease_merge_set {
	struct lease_line *leases;
	unsigned int num;
	struct lease_extra *extras;
	unsigned int numextras;
	const char *duid;
	size_t duidlen;
};

// The nth whitespace-separated token of a line, without copying it
static bool lease_token(const char *line, const size_t len, const unsigned int n,
                        const char **tok, size_t *toklen)
{
	size_t i = 0;
	for(unsigned int field = 0; ; field++)
	{
		while(i < len && line[i] == ' ')
			i++;
		if(i >= len)
			return false;
		const size_t start = i;
		while(i < len && line[i] != ' ')
			i++;
		if(field == n)
		{
			*tok = line + start;
			*toklen = i - start;
			return true;
		}
	}
}

// Slice a lease file into its lease lines, its extra lines and its DUID line.
// False when it carries more than the merge handles, so the caller writes the
// serving node's file whole rather than walking an O(n*m) merge
static bool lease_parse(const uint8_t *data, const size_t size, struct lease_merge_set *set)
{
	set->num = 0;
	set->numextras = 0;
	set->duid = NULL;
	set->duidlen = 0;
	if(data == NULL)
		return true;

	const char *base = (const char *)data;
	size_t off = 0;
	while(off < size)
	{
		const char *line = base + off;
		const char *nl = memchr(line, '\n', size - off);
		const size_t len = nl != NULL ? (size_t)(nl - line) : size - off;
		off += len + 1;
		if(len == 0)
			continue;

		const char *first = NULL;
		size_t firstlen = 0;
		if(!lease_token(line, len, 0, &first, &firstlen))
			continue;

		if(firstlen == 4 && strncmp(first, "duid", 4) == 0)
		{
			set->duid = line;
			set->duidlen = len;
			continue;
		}

		if((firstlen == 11 && strncmp(first, "vendorclass", 11) == 0) ||
		   (firstlen == 10 && strncmp(first, "agent-info", 10) == 0))
		{
			const char *addr = NULL;
			size_t addrlen = 0;
			if(!lease_token(line, len, 1, &addr, &addrlen))
				continue;
			if(set->numextras >= CLUSTER_LEASE_MERGE_MAX)
				return false;
			struct lease_extra *x = &set->extras[set->numextras++];
			x->line = line;
			x->len = len;
			x->addr = addr;
			x->addrlen = addrlen;
			continue;
		}

		const unsigned long expiry = strtoul(first, NULL, 10);
		const char *addr = NULL;
		size_t addrlen = 0;
		if(!lease_token(line, len, 2, &addr, &addrlen))
			continue;
		if(set->num >= CLUSTER_LEASE_MERGE_MAX)
			return false;
		struct lease_line *l = &set->leases[set->num++];
		l->line = line;
		l->len = len;
		l->addr = addr;
		l->addrlen = addrlen;
		l->expiry = expiry;
		l->infinite = expiry == 0;
	}

	return true;
}

// Which of two leases for one address is kept: the later expiry, with an
// infinite lease (expiry zero) beating any dated one. A reassignment always
// carries a later expiry than the lease it replaces, so this is the client
// that actually holds the address now
static bool lease_newer(const struct lease_line *cand, const struct lease_line *have)
{
	if(cand->infinite != have->infinite)
		return cand->infinite;
	return cand->expiry > have->expiry;
}

static void lease_append(uint8_t *buf, size_t *used, const char *line, const size_t len)
{
	memcpy(buf + *used, line, len);
	*used += len;
	buf[(*used)++] = '\n';
}

static void lease_append_extras(uint8_t *buf, size_t *used, const struct lease_merge_set *set,
                                const char *addr, const size_t addrlen)
{
	for(unsigned int j = 0; j < set->numextras; j++)
		if(set->extras[j].addrlen == addrlen &&
		   memcmp(set->extras[j].addr, addr, addrlen) == 0)
			lease_append(buf, used, set->extras[j].line, set->extras[j].len);
}

bool cluster_leases_merge(const uint8_t *incoming, const size_t insize,
                          uint8_t **out, size_t *outsize)
{
	*out = NULL;
	*outsize = 0;

	// Our own copy, if any. Its absence is the first pull, which leaves the
	// incoming file to stand on its own
	uint8_t *ours = NULL;
	size_t oursize = 0;
	if(!cluster_leases_read(&ours, &oursize))
	{
		ours = NULL;
		oursize = 0;
	}

	struct lease_merge_set theirs = { 0 }, mine = { 0 };
	struct chosen { const struct lease_line *lease; bool from_theirs; bool in_theirs; } *chosen = NULL;
	uint8_t *buf = NULL;
	bool ok = false;

	theirs.leases = calloc(CLUSTER_LEASE_MERGE_MAX, sizeof(*theirs.leases));
	theirs.extras = calloc(CLUSTER_LEASE_MERGE_MAX, sizeof(*theirs.extras));
	mine.leases = calloc(CLUSTER_LEASE_MERGE_MAX, sizeof(*mine.leases));
	mine.extras = calloc(CLUSTER_LEASE_MERGE_MAX, sizeof(*mine.extras));
	chosen = calloc(2u * CLUSTER_LEASE_MERGE_MAX, sizeof(*chosen));
	if(theirs.leases == NULL || theirs.extras == NULL || mine.leases == NULL ||
	   mine.extras == NULL || chosen == NULL)
		goto done;

	if(!lease_parse(incoming, insize, &theirs) || !lease_parse(ours, oursize, &mine))
		goto done;

	// The serving node's leases first, so its is the address's default home;
	// one of ours only displaces it when it is the newer lease
	unsigned int nchosen = 0;
	for(unsigned int pass = 0; pass < 2; pass++)
	{
		const struct lease_merge_set *set = pass == 0 ? &theirs : &mine;
		for(unsigned int i = 0; i < set->num; i++)
		{
			const struct lease_line *l = &set->leases[i];
			unsigned int k = 0;
			for(; k < nchosen; k++)
				if(chosen[k].lease->addrlen == l->addrlen &&
				   memcmp(chosen[k].lease->addr, l->addr, l->addrlen) == 0)
					break;
			if(k == nchosen)
			{
				chosen[nchosen].lease = l;
				chosen[nchosen].from_theirs = pass == 0;
				chosen[nchosen].in_theirs = pass == 0;
				nchosen++;
			}
			else if(lease_newer(l, chosen[k].lease))
			{
				chosen[k].lease = l;
				chosen[k].from_theirs = pass == 0;
				if(pass == 0)
					chosen[k].in_theirs = true;
			}
		}
	}

	buf = malloc(oursize + insize + 2);
	if(buf == NULL)
		goto done;

	size_t used = 0;
	// The serving node's DUID where it has one, so its DHCPv6 identity carries
	// over the same way the whole-file copy used to pass it on
	const char *duid = theirs.duid != NULL ? theirs.duid : mine.duid;
	const size_t duidlen = theirs.duid != NULL ? theirs.duidlen : mine.duidlen;
	if(duid != NULL)
		lease_append(buf, &used, duid, duidlen);

	const unsigned long now = (unsigned long)time(NULL);
	for(unsigned int i = 0; i < nchosen; i++)
	{
		const struct lease_line *l = chosen[i].lease;
		// A lease only this node still carries and already expired is dropped
		// rather than kept forever: the serving node pruned its own, and our
		// copy is never pruned by a dnsmasq that is not running here
		if(!chosen[i].in_theirs && !l->infinite && l->expiry <= now)
			continue;
		lease_append(buf, &used, l->line, l->len);
		lease_append_extras(buf, &used, chosen[i].from_theirs ? &theirs : &mine,
		                    l->addr, l->addrlen);
	}

	*out = buf;
	*outsize = used;
	buf = NULL;
	ok = true;

done:
	free(ours);
	free(theirs.leases);
	free(theirs.extras);
	free(mine.leases);
	free(mine.extras);
	free(chosen);
	free(buf);
	return ok;
}

bool cluster_sync_hashes(char confhash[CLUSTER_HASHLEN], char gravityhash[CLUSTER_HASHLEN])
{
	cluster_config_hash(confhash);

	return tables_hash(gravity_tables, ArraySize(gravity_tables), gravityhash);
}

bool cluster_adlist_hash(char hash[CLUSTER_HASHLEN])
{
	static const char *adlist[] = { "adlist", "adlist_by_group" };

	return tables_hash(adlist, ArraySize(adlist), hash);
}

// Reading the configuration, deciding what to change and installing the result
// is a read-modify-write, and clustering turns what used to be two people
// hitting Save at once into machine-paced traffic: a node that takes a push
// hands it on within 100 ms, so two documents reach a third node moments apart.
// Without this the later writer installs a copy taken before the earlier one
// and the earlier change is gone behind a 200. Held across the whole sequence,
// which lock_shm() could not be - it is taken and released inside it. It is
// lock_config(), the lock every other writer of the configuration takes.

// Cancellation is switched off while the lock is held. terminate_threads()
// cancels the cluster thread where it sleeps, and the writes below reach
// cancellation points of their own (open, fsync, close) - being cancelled in
// one of those would leave the lock held forever, with every peer pushing to
// this node parked behind it and FTL unable to finish stopping. The lock is
// recursive, so only the outermost hold switches it back on
static _Thread_local unsigned int sync_lock_depth = 0;
static _Thread_local int sync_lock_cancelstate = PTHREAD_CANCEL_ENABLE;

// Not switched back on once FTL is stopping: a cancel that arrived meanwhile
// would fire at the next cancellation point, wherever that is. The thread
// finishes on its own instead
static void restore_cancelstate(const int state)
{
	if(!killed)
		pthread_setcancelstate(state, NULL);
}

void cluster_sync_lock(void)
{
	int state = PTHREAD_CANCEL_ENABLE;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	lock_config();
	if(sync_lock_depth++ == 0)
		sync_lock_cancelstate = state;
}

void cluster_sync_unlock(void)
{
	const int state = sync_lock_cancelstate;
	const bool outermost = --sync_lock_depth == 0;
	unlock_config();
	if(outermost)
		restore_cancelstate(state);
}

// What this node hands to a peer. It is byte for byte what GET /api/config
// answers, minus the items that never leave a node and the ones not asked for,
// so there is no second notion anywhere of what a configuration document looks
// like. Each item goes with the time it was changed at, under "changed"
cJSON *cluster_config_document(const bool include[CONFIG_ELEMENTS], const bool encrypted)
{
	cJSON *document = cJSON_CreateObject();
	cJSON *stamps = cJSON_CreateObject();

	// The values and their stamps are read together. A stamp is only ever
	// written after its value, so a save made in between reaches a peer as
	// its new value under the old stamp, which that peer judges as old
	lock_shm();
	get_json_config(NULL, document, false, true, encrypted);
	cJSON *conf = cJSON_GetObjectItem(document, "config");
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		struct conf_item *item = get_conf_item(&config, i);
		cJSON *parent = conf;
		const unsigned int level = config_path_depth(item->p);
		for(unsigned int j = 0; j + 1 < level && parent != NULL; j++)
			parent = cJSON_GetObjectItem(parent, item->p[j]);
		if(parent == NULL || level == 0 || !cJSON_HasObjectItem(parent, item->p[level - 1]))
			continue;

		if(include[i])
			cJSON_AddNumberToObject(stamps, item->k, cluster_item_changed(i));
		else
			cJSON_DeleteItemFromObject(parent, item->p[level - 1]);
	}
	unlock_shm();
	cJSON_AddItemToObject(document, "changed", stamps);

	return document;
}

// The peer reads a request body into a bounded buffer, so a document at or above
// that size would arrive truncated. Asked before sending and asked again by the
// caller, which stops sending rather than repeating the attempt every round
bool cluster_push_possible(const char *body)
{
	return strlen(body) < CLUSTER_MAX_PUSH_BYTES - 1;
}

// ...and this is how it gets there: a PATCH of the peer's configuration, the
// request the web interface makes when somebody hits Save. The peer decides
// item by item whether it already holds what we sent, so a node that is up to
// date changes nothing, writes nothing and restarts nothing
bool cluster_push_config(struct cluster_peer *peer, const char *body, bool *taken)
{
	const char *path = "/api/config";

	if(!cluster_push_possible(body))
	{
		log_warn("cluster: configuration is too large to synchronize (%zu bytes)",
		         strlen(body));
		log_cluster_message("the configuration is too large to synchronize");
		return false;
	}

	cJSON *answer = NULL;
	char err[CLUSTER_STRLEN] = "";
	if(!cluster_http_patch(peer, path, body, &answer, err, sizeof(err)))
	{
		log_debug(DEBUG_CLUSTER, "cluster: cannot hand config to %s: %s", peer->url, err);
		return false;
	}

	// Missing in the answer of a node too old to say, which took it
	if(taken != NULL)
		*taken = !cJSON_IsFalse(cJSON_GetObjectItem(answer, "taken"));
	cJSON_Delete(answer);

	return true;
}

// What the process watching the run writes back through the pipe when it could
// not start the run at all. Anything else is the wait status of `pihole -g`
#define GRAVITY_NOT_STARTED -1

// Rebuild the blocking database from the adlists we just received. This is the
// one part of Pi-hole that lives outside FTL, so we run it the way a user would
// The gravity run this node started, watched from the tick. The outcome comes
// back through a pipe rather than through wait(): dnsmasq reaps whatever child
// it finds, so the exit status of a child of FTL is not ours to count on
static pid_t gravity_pid = 0;
static int gravity_fd = -1;

// Set while a rebuild started by the cluster is running, and cleared to the
// outcome when it ends. A version is only adopted once the lists were actually
// built from it: the blocking database is not part of the fingerprint, so a
// node whose rebuild never ran would otherwise tell the cluster it holds the
// newest lists while blocking nothing
static bool gravity_ok = false;

// Set once the run was ended for FTL to stop
static bool gravity_stopping = false;

// Close every descriptor from lowfd up. Only called in a child of fork()
static void close_from(const int lowfd)
{
#ifdef SYS_close_range
	if(syscall(SYS_close_range, (unsigned int)lowfd, ~0U, 0) == 0)
		return;
#endif
	// Kernels before 5.9 have no close_range()
	const long max = sysconf(_SC_OPEN_MAX);
	for(long fd = lowfd; fd < (max > 0 ? max : 1024); fd++)
		close((int)fd);
}

// How long a gravity.db_temp nobody writes to still means a run is building
// it. gravity.sh leaves the file behind when it fails or is killed
#define GRAVITY_TEMP_MAX_AGE 600

// A gravity run this node's cluster did not start: one through the API sets
// gravity_running, one from the shell or cron only leaves gravity.db_temp. Such
// a run swaps a copy of the list tables taken at its start in when it ends
bool cluster_gravity_elsewhere(void)
{
	if(gravity_running && gravity_fd < 0)
		return true;

	char temp[PATH_MAX] = "";
	lock_shm();
	snprintf(temp, sizeof(temp), "%s_temp", config.files.gravity.v.s);
	unlock_shm();

	struct stat st = { 0 };
	if(stat(temp, &st) != 0)
		return false;

	const time_t age = time(NULL) - st.st_mtime;
	return age >= 0 && age < GRAVITY_TEMP_MAX_AGE;
}

bool cluster_run_gravity(void)
{
	if(gravity_fd >= 0)
		return false; // our own run, still going

	// A run started now would outlive FTL
	if(killed || want_terminate)
		return false;

	// gravity.sh has no lock against a second run, and two of them leave a
	// gravity.db without tables
	if(cluster_gravity_elsewhere())
	{
		log_debug(DEBUG_CLUSTER, "cluster: gravity is running elsewhere, waiting");
		return false;
	}

	// Claimed in one step, so the web interface and this thread cannot both
	// think they got it - and so neither clears what the other took
	if(atomic_exchange(&gravity_running, true))
	{
		// Somebody is rebuilding already - through the web interface.
		// Theirs would replace the database we just imported into
		// anyway, so this waits for it rather than racing it
		log_debug(DEBUG_CLUSTER, "cluster: gravity is already running, waiting");
		return false;
	}

	log_info("cluster: adlists changed, running gravity");

	int fds[2] = { -1, -1 };
	if(pipe2(fds, O_CLOEXEC) != 0)
	{
		log_err("cluster: cannot open a pipe for gravity: %s", strerror(errno));
		atomic_store(&gravity_running, false);
		return false;
	}

	const pid_t pid = fork();
	if(pid < 0)
	{
		log_err("cluster: cannot fork for gravity: %s", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		atomic_store(&gravity_running, false);
		return false;
	}

	if(pid == 0)
	{
		// A process group of its own, so a stop can end the whole run
		setpgid(0, 0);

		// Only the pipe's write end stays open: anything else of FTL's,
		// its listening sockets above all, would outlive FTL in the run
		const int out = dup2(fds[1], 3) == 3 ? 3 : -1;
		close_from(4);

		// This process does nothing but wait for the run below, and
		// nothing else in it reaps: a child of a single-threaded process
		// that waits for it is one whose exit status arrives
		const pid_t child = fork();
		if(child == 0)
		{
			// Gravity writes a lot, and none of it belongs in the
			// answer of whoever triggered this
			const int fd = open("/dev/null", O_WRONLY);
			if(fd >= 0)
			{
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
			close_from(3);
			// Not shielded from SIGTERM, unlike the API's run: a stop
			// ends it through cluster_gravity_stop(), and the rebuild
			// is owed and redone after the restart
			execl(PIHOLE_BINARY, "pihole", "-g", (char *)NULL);
			// Only reached if exec failed, the code a shell uses for it
			_exit(127);
		}

		int status = 0;
		pid_t waited = -1;
		// A signal to this process is not the end of the run
		do
			waited = child > 0 ? waitpid(child, &status, 0) : -1;
		while(waited < 0 && errno == EINTR);
		const int outcome = waited == child ? status : GRAVITY_NOT_STARTED;
		if(out < 0 || write(out, &outcome, sizeof(outcome)) != sizeof(outcome))
			_exit(EXIT_FAILURE);
		_exit(EXIT_SUCCESS);
	}

	close(fds[1]);
	// ...also from here, whichever of the two runs first
	setpgid(pid, pid);

	// Not waited for here: gravity takes minutes, and the cluster thread has
	// peers to watch and a DHCP hand-over to decide in that time
	if(fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0)
		log_warn("cluster: cannot watch the gravity run: %s", strerror(errno));
	gravity_fd = fds[0];
	gravity_pid = pid;
	gravity_ok = false;
	gravity_stopping = false;

	return true;
}

// A stop is pending. gravity_running holds it back until the run is over, which
// is minutes, so the cluster's own run is ended instead. The pending record on
// disk has the rebuild redone after the restart
void cluster_gravity_stop(void)
{
	if(gravity_fd < 0 || gravity_pid <= 0 || gravity_stopping)
		return;

	gravity_stopping = true;
	log_info("cluster: ending the gravity run for FTL to stop, it is run again after the restart");
	if(kill(-gravity_pid, SIGTERM) != 0)
		log_warn("cluster: cannot end the gravity run: %s", strerror(errno));
}

// Looked at once per tick. Blocking here would leave the cluster blind for the
// whole run, and a node failing over during it would go unnoticed
// True when a run ended that is to be settled. gravity_running is then left to
// cluster_gravity_release(), so a stop parked behind the run waits for that
bool cluster_gravity_check(void)
{
	if(gravity_fd < 0)
		return false;

	// Written in one piece, well below PIPE_BUF, so it arrives whole or not
	int outcome = 0;
	const ssize_t len = read(gravity_fd, &outcome, sizeof(outcome));
	if(len < 0 && (errno == EAGAIN || errno == EINTR))
		return false; // still running, looked at again next tick

	close(gravity_fd);
	gravity_fd = -1;

	// Whoever gets there first: this leaves no zombie behind if dnsmasq has
	// not already taken it
	if(gravity_pid > 0)
		waitpid(gravity_pid, NULL, WNOHANG);
	gravity_pid = 0;

	if(len != sizeof(outcome))
	{
		// The run died before it could say how it went, so whether the
		// lists were built is unknown - and unknown is not success
		log_warn("cluster: gravity outcome unknown");
		return true;
	}

	// Nothing to settle: the pending record has the rebuild redone after
	// the restart
	if(gravity_stopping)
	{
		log_info("cluster: gravity run ended");
		cluster_gravity_release();
		return false;
	}

	if(WIFEXITED(outcome) && WEXITSTATUS(outcome) == EXIT_SUCCESS)
	{
		log_info("cluster: gravity finished");
		gravity_ok = true;
		return true;
	}

	char failed[CLUSTER_STRLEN] = "";
	if(outcome == GRAVITY_NOT_STARTED)
		snprintf(failed, sizeof(failed), "cannot start gravity");
	else if(WIFEXITED(outcome) && WEXITSTATUS(outcome) == 127)
		snprintf(failed, sizeof(failed), "cannot run %s", PIHOLE_BINARY);
	else if(WIFEXITED(outcome))
		snprintf(failed, sizeof(failed), "gravity exited with status %d", WEXITSTATUS(outcome));
	else if(WIFSIGNALED(outcome))
		snprintf(failed, sizeof(failed), "gravity was ended by signal %d (%s)",
		         WTERMSIG(outcome), strsignal(WTERMSIG(outcome)));
	else
		snprintf(failed, sizeof(failed), "gravity outcome unknown");

	log_warn("cluster: %s", failed);
	log_cluster_message(failed);

	return true;
}

void cluster_gravity_release(void)
{
	atomic_store(&gravity_running, false);
}

bool cluster_pull_gravity(struct cluster_peer *peer, const char *held, bool *rebuilding,
                          char imported[CLUSTER_HASHLEN])
{
	*rebuilding = false;
	imported[0] = '\0';

	if(killed || want_terminate)
		return false;

	// Remembered across the import: only a changed adlist makes the blocking
	// database stale
	char before[CLUSTER_HASHLEN] = "";
	const bool before_known = cluster_adlist_hash(before);

	uint8_t *data = NULL;
	size_t size = 0;
	char err[CLUSTER_STRLEN] = "";
	// The lists are a whole database rather than an answer to a question, so
	// they get a transfer budget of their own - the round timeout is how long
	// a peer may take to reply, not how long a download may take
	if(!cluster_http_raw(peer, "/api/cluster/lists", &data, &size, err, sizeof(err)))
	{
		log_warn("cluster: cannot read lists of %s: %s", peer->url, err);
		return false;
	}

	// ...and asked again after the download, which takes seconds
	if(killed || want_terminate)
	{
		free(data);
		return false;
	}

	// Import the list tables only: the archive also carries the publisher's
	// pihole.toml and DHCP leases, neither of which we want here
	cJSON *import = cJSON_CreateObject();
	cJSON *gravity = cJSON_CreateObject();
	char hint[ERRBUF_SIZE] = { 0 };
	cJSON *files = cJSON_CreateArray();

	// This object is the whole of what keeps a peer's configuration and its
	// DHCP leases out of this node: read_teleporter_zip() takes no filter to
	// mean no restriction. An allocation that failed would hand it none, and
	// this node would take the peer's pihole.toml along with its lists
	//
	// Judged before the two are joined: adding to a parent that does not exist
	// does not hand the child over either, and cleaning up after the fact would
	// have to know which of the two happened
	if(import == NULL || gravity == NULL || files == NULL)
	{
		log_err("cluster: cannot build the import filter, not taking the lists of %s", peer->url);
		cJSON_Delete(import);
		cJSON_Delete(gravity);
		cJSON_Delete(files);
		free(data);
		return false;
	}

	for(size_t i = 0; i < ArraySize(gravity_tables); i++)
		cJSON_AddTrueToObject(gravity, gravity_tables[i]);
	cJSON_AddItemToObject(import, "gravity", gravity);
	// A peer's archive holds the one table dump generate_cluster_zip() puts in
	// it, so anything beyond a handful is not an archive but a way to make
	// this node walk a hundred thousand entries.
	//
	// Under the same lock a Teleporter restore takes (api/teleporter.c). It was
	// the one writer of these tables that took none, so the restore's lock
	// excluded nothing: an administrator's restore could be answered 200 and
	// have a peer's lists written over it seconds later, with the pihole.toml
	// half of the same archive left in place
	cluster_sync_lock();

	// The round decided to pull on the tables as they were when it began, and
	// the download above took seconds. An entry added or removed here in
	// between was answered 2xx and would go with the rest of the table: kept
	// instead, and the next round dates it as the edit it is
	char now[CLUSTER_HASHLEN] = "";
	if(held != NULL && strlen(held) > 0 &&
	   tables_hash(gravity_tables, ArraySize(gravity_tables), now) && strcmp(now, held) != 0)
	{
		cluster_sync_unlock();
		cJSON_Delete(import);
		cJSON_Delete(files);
		free(data);
		log_info("cluster: lists changed here while those of %s were on their way, keeping them", peer->url);
		return false;
	}

	const char *error = read_teleporter_zip(data, size, 4, hint, import, files);
	// What arrived, which is newer than the fingerprint the round elected
	// when the peer edited a list since
	if(error == NULL && !tables_hash(gravity_tables, ArraySize(gravity_tables), imported))
		imported[0] = '\0';
	cluster_sync_unlock();
	// An archive without the list tables reads as a success and imports nothing
	const bool had_tables = cJSON_GetArraySize(files) > 0;
	cJSON_Delete(import);
	cJSON_Delete(files);
	free(data);

	if(error != NULL)
	{
		log_err("cluster: cannot import lists of %s: %s (%s)", peer->url, error, hint);
		return false;
	}
	if(!had_tables)
	{
		log_err("cluster: the lists of %s contain no list tables", peer->url);
		return false;
	}

	log_info("cluster: imported lists of %s", peer->url);

	// Allow and deny lists, groups and clients take effect immediately - the
	// import triggers a reload. New or removed adlists do not: the domains
	// they hold have to be downloaded and written to the blocking database
	// first, which is what a gravity run does
	char after[CLUSTER_HASHLEN] = "";
	const bool after_known = cluster_adlist_hash(after);

	// Either fingerprint unreadable means we cannot tell whether the adlists
	// moved. Rebuilding is the answer that cannot be wrong
	// Whether a rebuild is owed, not whether one could be started: starting
	// it is the caller's business, and it keeps trying until one runs
	*rebuilding = !before_known || !after_known || strcmp(before, after) != 0;

	return true;
}

bool cluster_gravity_pending(void)
{
	return gravity_fd >= 0;
}

bool cluster_gravity_succeeded(void)
{
	return gravity_ok;
}


// Where the versions survive a restart. Not a configuration item: this is
// bookkeeping FTL maintains, not something a user sets
#define CLUSTER_STATE_FILE CLUSTER_STATE_FILE_NAME

// This node's identity, generated once and kept in the state file. Names are
// what an administrator reads; this is what the nodes compare
static char node_id[17] = "";

// The last state written, so saving the item versions does not lose the list
// version and the other way around
static struct cluster_sync_state saved_state = { 0 };

const char *cluster_node_id(void)
{
	return node_id;
}

// Set once the versions and the identity have been read from disk
static bool state_loaded = false;

// Whether the state file was written by the build that is now reading it. The
// fingerprints cover the shape of the data as well as its content, so across an
// upgrade a difference says nothing about whether anybody changed anything
static bool same_build_state = false;

bool cluster_state_same_build(void)
{
	return same_build_state;
}

// Said once the comparison it exists for has been made and this node's own
// fingerprint has been recorded under the build now running. Read at start-up
// and never cleared, it stayed false for the whole first session after an
// upgrade - so a list edited on this node during that session was read as "the
// schema moved underneath us" rather than as an edit, and the peers handed the
// old lists back over it
void cluster_state_build_settled(void)
{
	same_build_state = true;
}

// Set when this node joined a cluster and has to arrive as a new member
static bool state_forgotten = false;

bool cluster_state_known(void)
{
	return state_loaded;
}

// The last edit of the list tables made through FTL, and the last one the
// cluster thread has accounted for. Kept in the state file: a Teleporter import
// restarts FTL before the next round can look
static double lists_written = 0.0;
static double lists_accounted = 0.0;
// ...and which file gravity.db was when last looked at. gravity.sh swaps in a
// new one at the end of every run
static unsigned long long lists_inode = 0;
// ...and what the tables hashed to right after that edit. Tables found that way
// are explained by it whichever file holds them
static char lists_written_hash[CLUSTER_HASHLEN] = "";
static pthread_mutex_t lists_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long long gravity_inode(void)
{
	char dbfile[PATH_MAX] = "";
	lock_shm();
	strncpy(dbfile, config.files.gravity.v.s, sizeof(dbfile) - 1);
	unlock_shm();

	struct stat st = { 0 };
	return stat(dbfile, &st) == 0 ? (unsigned long long)st.st_ino : 0;
}

// Called by the API's list writers, under cluster_sync_lock()
void cluster_note_list_write(void)
{
	if(!state_loaded)
		return;

	char hash[CLUSTER_HASHLEN] = "";
	if(!tables_hash(gravity_tables, ArraySize(gravity_tables), hash))
		hash[0] = '\0';

	pthread_mutex_lock(&lists_lock);
	lists_written = fmax(double_time(), lists_written);
	memcpy(lists_written_hash, hash, sizeof(lists_written_hash));
	pthread_mutex_unlock(&lists_lock);

	cluster_state_save(NULL);
}

void cluster_lists_explain(const char *hash, double *written, bool *replaced)
{
	const unsigned long long inode = gravity_inode();

	pthread_mutex_lock(&lists_lock);
	*written = lists_written > lists_accounted ? lists_written : 0.0;
	*replaced = lists_inode != 0 && inode != 0 && inode != lists_inode &&
	            (strlen(lists_written_hash) == 0 || strcmp(hash, lists_written_hash) != 0);
	pthread_mutex_unlock(&lists_lock);
}

double cluster_lists_write_lost(const char *hash, const double since)
{
	pthread_mutex_lock(&lists_lock);
	const double lost = lists_written >= since && strlen(lists_written_hash) > 0 &&
	                    strcmp(hash, lists_written_hash) != 0 ? lists_written : 0.0;
	pthread_mutex_unlock(&lists_lock);

	return lost;
}

void cluster_lists_accounted(const double written)
{
	const unsigned long long inode = gravity_inode();

	pthread_mutex_lock(&lists_lock);
	const bool moved = written > lists_accounted || (inode != 0 && inode != lists_inode);
	if(written > lists_accounted)
		lists_accounted = written;
	if(inode != 0)
		lists_inode = inode;
	pthread_mutex_unlock(&lists_lock);

	if(moved)
		cluster_state_save(NULL);
}

void cluster_state_load(struct cluster_sync_state *state)
{
	bool generated_id = false;
	// Zero unless the file carries them in the form written below. A file
	// that does not is one this node cannot compare against, and what it
	// holds now becomes the baseline instead
	uint64_t stored_items[CONFIG_ELEMENTS] = { 0 };
	bool stored_any = false;
	char stored_version[64] = "";
	memset(state, 0, sizeof(*state));
	node_id[0] = '\0';

	FILE *file = fopen(CLUSTER_STATE_FILE, "r");
	if(file != NULL)
	{
		char line[256] = "";
		while(fgets(line, sizeof(line), file) != NULL)
		{
			double when = 0.0, written = 0.0;
			unsigned long long inode = 0;
			unsigned int failures = 0;
			char hash[CLUSTER_HASHLEN] = "";
			char phash[CLUSTER_HASHLEN] = "";
			char key[64] = "";
			char vip[64] = "";
			char built[64] = "";

			// Checked like every other field read from this file: a
			// value the peers cannot accept would have this node
			// refused by all of them while it still counts itself a
			// member - and it is written back at every save, so it
			// would never heal. An unusable one is dropped and a
			// fresh identity minted below
			if(sscanf(line, "node %16s", key) == 1 && cluster_plain_id(key))
				strncpy(node_id, key, sizeof(node_id) - 1);
			else if(sscanf(line, "gravity %lf %16s", &when, hash) == 2)
			{
				// Bounded the way the config line below is: a stamp
				// from the future would pin the lists to whatever
				// this node holds, across restarts
				if(!isfinite(when) || when < 0.0)
					when = 0.0;
				state->gravity_changed = fmin(when, double_time());
				strncpy(state->gravity_hash, hash, sizeof(state->gravity_hash) - 1);
			}
			else if(sscanf(line, "prepull %64s", phash) == 1)
			{
				strncpy(state->pre_pull_hash, phash,
				        sizeof(state->pre_pull_hash) - 1);
				state->pre_pull_hash[sizeof(state->pre_pull_hash) - 1] = '\0';
			}
			else if(sscanf(line, "pending %lf %16s %64s", &when, hash, phash) >= 2)
			{
				if(isfinite(when) && when >= 0.0)
				{
					state->pending_changed = fmin(when, double_time());
					if(strcmp(hash, "-") != 0)
						strncpy(state->pending_id, hash,
						        sizeof(state->pending_id) - 1);
					if(strcmp(phash, "-") != 0)
						strncpy(state->pending_hash, phash,
						        sizeof(state->pending_hash) - 1);
				}
			}
			else if(sscanf(line, "item %63s %lf %16s", key, &when, hash) == 3)
			{
				// When an item was last changed and what it hashed
				// to. Hardware without a real-time clock comes back
				// behind the time it shut down at, so a stamp from
				// the future is clamped to now rather than dropped
				const int i = cluster_item_index(key);
				if(i < 0)
					continue;
				pthread_mutex_lock(&item_changed_lock);
				item_changed[i] = isfinite(when) && when > 0.0 ? fmin(when, double_time()) : 0.0;
				pthread_mutex_unlock(&item_changed_lock);
				stored_items[i] = strtoull(hash, NULL, 16);
				stored_any = true;
			}
			else if(sscanf(line, "version %63s", built) == 1)
			{
				strncpy(stored_version, built, sizeof(stored_version) - 1);
				stored_version[sizeof(stored_version) - 1] = '\0';
			}
			else if(sscanf(line, "vip %63s", vip) == 1)
				vip_note_placed(vip, "");
			else if(sscanf(line, "lists %lf %lf %llu %16s", &when, &written, &inode, hash) == 4)
			{
				pthread_mutex_lock(&lists_lock);
				lists_written = isfinite(when) && when > 0.0 ? fmin(when, double_time()) : 0.0;
				lists_accounted = isfinite(written) && written > 0.0 ? fmin(written, double_time()) : 0.0;
				lists_inode = inode;
				strncpy(lists_written_hash, strcmp(hash, "-") != 0 ? hash : "",
				        sizeof(lists_written_hash) - 1);
				pthread_mutex_unlock(&lists_lock);
			}
			else if(sscanf(line, "takeover %lf %u", &when, &failures) == 2)
			{
				if(isfinite(when) && when > double_time())
					cluster_dhcp_restore_takeover(when, failures);
			}
		}

		fclose(file);
	}

	// Remembering what was read means a later save cannot wipe it
	saved_state = *state;

	if(strlen(node_id) == 0)
	{
		// No identity yet, so this node is new to the cluster. Random
		// rather than derived from anything: two Pi-holes imaged from
		// the same card share their name, their MAC prefix and their
		// machine ID, and two nodes with one identity cannot elect
		char *generated = NULL;
		if(generate_password(&generated, NULL) && generated != NULL)
		{
			for(unsigned int i = 0; i < sizeof(node_id) - 1 && generated[i] != '\0'; i++)
				node_id[i] = isalnum((unsigned char)generated[i]) ? generated[i] : 'x';
			node_id[sizeof(node_id) - 1] = '\0';
		}
		if(generated != NULL)
			free(generated);

		if(strlen(node_id) == 0)
			strncpy(node_id, "unidentified", sizeof(node_id) - 1);

		log_info("cluster: this node is %s", node_id);

		// Written out at once. A cluster that only fails DHCP over never
		// stamps a configuration and never runs gravity, so nothing else
		// would ever save it - and the node would mint a new identity at
		// every restart, which its peers have pinned the old one for
		generated_id = true;
	}


	// What this node holds right now is its starting point, not a change:
	// FTL writes pihole.toml at every start, and counting that as somebody
	// configuring this node would have a node that just rebooted outrank the
	// node the configuration actually came from
	// A file that carries no fingerprint - a first start, or a node that
	// just joined - starts from what this node holds. An empty baseline
	// would make the next write of any kind, even one that touched nothing
	// the cluster synchronizes, look like somebody configuring this node,
	// and that node then outranks the cluster it was about to take from
	uint64_t now_items[CONFIG_ELEMENTS];
	item_hashes(now_items);

	// A release can change how an item's value is written out, which moves
	// its fingerprint without anybody having configured anything. Comparing
	// across an upgrade would read that as an edit, stamp this node as the
	// most recently configured one in the cluster, and hand its months-old
	// values to every peer
	same_build_state = strcmp(stored_version, git_version()) == 0;
	const bool same_build = same_build_state;
	const bool comparable = stored_any && same_build;

	// The baseline an interrupted pull is measured against is a fingerprint of
	// the build that wrote it, and it outlives the guard: once a fingerprint is
	// recorded under this build the comparison it feeds is no longer refused.
	// Without one the pull is settled as "nothing here is newer", which is the
	// only answer that is right whichever tables the interruption left behind
	if(!same_build)
	{
		state->pre_pull_hash[0] = '\0';
		saved_state.pre_pull_hash[0] = '\0';
	}

	if(strlen(stored_version) > 0 && !same_build)
		log_info("cluster: FTL was upgraded from %s, keeping this node's configuration timestamps",
		         stored_version);

	// ...and the same fingerprints say whether somebody configured this node
	// while it was down. An item the file does not name has nothing to be
	// compared against
	bool changed_while_down = false;
	pthread_mutex_lock(&stamped_lock);
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
	{
		stamped_items[i] = comparable && stored_items[i] != 0 ? stored_items[i] : now_items[i];
		if(now_items[i] != 0 && now_items[i] != stamped_items[i])
			changed_while_down = true;
	}
	pthread_mutex_unlock(&stamped_lock);

	// Written only now, so the identity and a fingerprint pair that can be
	// compared against go into the file together. Saved from here rather
	// than left to the first round: a cluster that only fails DHCP over
	// never stamps a configuration and never runs gravity, so nothing else
	// would ever write the identity out, and the node would mint a new one
	// at every restart - which its peers have pinned the old one for
	//
	// ...and written after an upgrade for the same reason: the build that
	// wrote the fingerprints is what says whether they can be compared, so
	// leaving the old one in the file would refuse the comparison at every
	// start from now on, and an edit made while this node was down would
	// never be noticed again
	if(generated_id || !same_build)
		cluster_state_save(state);

	state_loaded = true;

	// Somebody edited pihole.toml while FTL was not running. That is a change
	// made on this node like any other, and leaving it unstamped would have
	// the cluster hand this node its own old values back
	if(changed_while_down)
	{
		log_info("cluster: config was changed while this node was down");
		config_stamp_local_change();
	}
}

// Its own lock: this is reached from the cluster thread and from a webserver
// thread handling a push, and two writers sharing one temporary file would
// truncate each other's and rename the mixture into place
static pthread_mutex_t state_file_lock = PTHREAD_MUTEX_INITIALIZER;

// state == NULL keeps what is already known, for the callers that only moved
// the configuration timestamp
static void write_state_file(const struct cluster_sync_state *state)
{
	// open(), fsync() and close() are cancellation points, and the cluster
	// thread is cancelled where it sleeps when FTL stops. Being cancelled in
	// the middle of this would leave the lock held for good, with every peer
	// pushing to this node parked behind it
	int cancelstate = PTHREAD_CANCEL_ENABLE;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);

	pthread_mutex_lock(&state_file_lock);

	// Under the same lock as the write: a webserver thread stamping a
	// configuration change and the cluster thread publishing a gravity run
	// reach this from two directions
	if(state != NULL)
		saved_state = *state;
	// Written and renamed so a reader never sees half of it, and created
	// with its final permissions rather than whatever umask(0) would give
	// it - the file steers what this node believes the cluster holds
	char tmpfile[sizeof(CLUSTER_STATE_FILE) + 32] = "";
	snprintf(tmpfile, sizeof(tmpfile), "%s.%u.tmp", CLUSTER_STATE_FILE, (unsigned int)getpid());
	const int fd = open(tmpfile, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
	                    S_IRUSR | S_IWUSR | S_IRGRP);
	if(fd < 0)
	{
		log_err("cluster: cannot write %s: %s", tmpfile, strerror(errno));
		pthread_mutex_unlock(&state_file_lock);
		restore_cancelstate(cancelstate);
		return;
	}

	FILE *file = fdopen(fd, "w");
	if(file == NULL)
	{
		log_err("cluster: cannot write %s: %s", tmpfile, strerror(errno));
		close(fd);
		pthread_mutex_unlock(&state_file_lock);
		restore_cancelstate(cancelstate);
		return;
	}

	fprintf(file, "node %s\n", node_id);
	fprintf(file, "gravity %.17g %s\n", saved_state.gravity_changed, saved_state.gravity_hash);
	if(saved_state.pending_changed > 0.0)
		fprintf(file, "pending %.17g %s %s\n", saved_state.pending_changed,
		        strlen(saved_state.pending_id) > 0 ? saved_state.pending_id : "-",
		        strlen(saved_state.pending_hash) > 0 ? saved_state.pending_hash : "-");
	// What this node's lists hashed to before it asked a peer for theirs. Kept
	// beside the pull it belongs to: the fingerprint it would otherwise be
	// compared against is republished every time a rebuild fails, so a pull
	// resumed after a restart had no baseline left and a list edited during
	// the retry was published under the pre-pull timestamp
	if(saved_state.pending_changed > 0.0 && strlen(saved_state.pre_pull_hash) > 0)
		fprintf(file, "prepull %s\n", saved_state.pre_pull_hash);
	pthread_mutex_lock(&lists_lock);
	fprintf(file, "lists %.17g %.17g %llu %s\n", lists_written, lists_accounted, lists_inode,
	        strlen(lists_written_hash) > 0 ? lists_written_hash : "-");
	pthread_mutex_unlock(&lists_lock);
	double takeover_until = 0.0;
	unsigned int takeover_failures = 0;
	cluster_dhcp_takeover_state(&takeover_until, &takeover_failures);
	if(takeover_until > double_time())
		fprintf(file, "takeover %.6f %u\n", takeover_until, takeover_failures);
	// The virtual address this node placed, if it holds one. Read back at
	// start-up so an FTL that was killed can tell the address it left behind
	// from one the administrator configured on the machine
	char placed[CLUSTER_STRLEN] = "";
	if(vip_placed_address(placed, sizeof(placed)))
		fprintf(file, "vip %s\n", placed);
	// Every item with a fingerprint or a stamp, so a restart neither forgets
	// when an item was changed nor misses an edit made while FTL was down
	double stamps[CONFIG_ELEMENTS];
	cluster_item_stamps(stamps);
	pthread_mutex_lock(&stamped_lock);
	for(unsigned int i = 0; i < CONFIG_ELEMENTS; i++)
		if(stamped_items[i] != 0 || stamps[i] > 0.0)
			fprintf(file, "item %s %.17g %016llx\n", get_conf_item(&config, i)->k,
			        stamps[i], (unsigned long long)stamped_items[i]);
	fprintf(file, "version %s\n", git_version());
	pthread_mutex_unlock(&stamped_lock);

	// This file decides what this node believes the cluster holds, so it is
	// on disk before the rename makes it the current one - a node coming
	// back from a power cut with an empty state file would take its peers'
	// lists over its own
	const bool flushed = fflush(file) == 0 && fsync(fileno(file)) == 0;
	if(fclose(file) != 0 || !flushed)
	{
		log_err("cluster: cannot write %s: %s", tmpfile, strerror(errno));
		unlink(tmpfile);
		pthread_mutex_unlock(&state_file_lock);
		restore_cancelstate(cancelstate);
		return;
	}

	if(rename(tmpfile, CLUSTER_STATE_FILE) != 0)
	{
		log_err("cluster: cannot rename %s: %s", tmpfile, strerror(errno));
		unlink(tmpfile);
		pthread_mutex_unlock(&state_file_lock);
		restore_cancelstate(cancelstate);
		return;
	}

	const int dirfd = open("/etc/pihole", O_RDONLY | O_DIRECTORY);
	if(dirfd >= 0)
	{
		fsync(dirfd);
		close(dirfd);
	}

	pthread_mutex_unlock(&state_file_lock);
	restore_cancelstate(cancelstate);
}

// state == NULL saves what is already known, for the callers that only changed
// an item version
void cluster_state_save(const struct cluster_sync_state *state)
{
	if(state_forgotten)
		return;

	write_state_file(state);
}

// A node joining a cluster takes what the cluster holds rather than handing its
// own settings to it, so what it remembered about being configured goes. A node
// that was in another cluster before would otherwise arrive with the newer
// timestamp and overwrite the cluster it just joined
void cluster_state_forget(void)
{
	// The address this machine placed is recorded in the file about to be
	// removed, and nothing else remembers it - so it would stay on the
	// interface with this node still answering DNS on it, for a cluster it
	// has just left. Given back first, while there is still a record of it.
	//
	// Read off the file rather than out of memory. A join refuses while
	// clustering is switched on, so the cluster thread - the only caller of
	// cluster_state_load() - has never run in this process, and both of
	// vip.c's records are empty however long the address has been sitting on
	// the interface. Asking cluster_vip_shutdown() got "nothing to do" every
	// time, which is a fix that never fired on the case it was written for
	cluster_vip_shutdown();

	FILE *state = fopen(CLUSTER_STATE_FILE, "r");
	if(state != NULL)
	{
		char line[512] = "";
		while(fgets(line, sizeof(line), state) != NULL)
		{
			char vip[CLUSTER_STRLEN] = "";
			if(sscanf(line, "vip %63s", vip) != 1 || strlen(vip) == 0)
				continue;

			// vip_release() removes it only where it is genuinely on an
			// interface and this machine recorded placing it; anything
			// else it leaves alone and says so
			vip_note_placed(vip, "");
			vip_release(vip);
			break;
		}
		fclose(state);
	}

	state_forgotten = true;
	pthread_mutex_lock(&item_changed_lock);
	memset(item_changed, 0, sizeof(item_changed));
	pthread_mutex_unlock(&item_changed_lock);
	pthread_mutex_lock(&lists_lock);
	lists_written = lists_accounted = 0.0;
	lists_written_hash[0] = '\0';
	pthread_mutex_unlock(&lists_lock);

	if(unlink(CLUSTER_STATE_FILE) != 0 && errno != ENOENT)
		log_warn("cluster: cannot remove %s: %s", CLUSTER_STATE_FILE, strerror(errno));
}
