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
// MAX_PAYLOAD_BYTES
#include "webserver/http-common.h"
#include <sys/wait.h>
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

// `pinned` says whether items forced through the environment are part of the
// fingerprint, and the answer depends on what the fingerprint is for.
//
// A fingerprint a peer compares against must include them: the two nodes have to
// hash the same set of items or they never agree, and neither can know what the
// other pins. A fingerprint this node compares against its own past must not:
// nothing here can change those items, so a difference in one is not evidence
// that somebody configured anything - and one of them moves on its own.
// `webserver.api.pwhash` is derived from FTLCONF_webserver_api_password with a
// fresh random salt at every start, so on the Docker image the credential half
// is a different string after every restart while the password is identical
static void config_hash_scope(const enum hash_scope scope, const bool pinned,
                              char out[CLUSTER_HASHLEN])
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

		if(!pinned && config_env_pinned(item))
			continue;

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
	config_hash_scope(SCOPE_SETTINGS, true, out);
}

void cluster_credentials_hash(char out[CLUSTER_HASHLEN])
{
	config_hash_scope(SCOPE_CREDENTIALS, true, out);
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

// The fingerprint the configuration timestamp was last taken at, and the lock
// around it: two webserver threads can install a configuration at once
// What this node last recorded itself as holding, in two halves: the settings
// and the credentials. Both are taken over a fixed set of items, so they stay
// comparable with the last time even when the member list turns https:// and
// changes what may actually travel
static char stamped_hash[CLUSTER_HASHLEN] = "";
static char stamped_credhash[CLUSTER_HASHLEN] = "";
static pthread_mutex_t stamped_lock = PTHREAD_MUTEX_INITIALIZER;

// Did this change touch anything the cluster synchronizes? A debug flag, a path
// or this node's own name did not, and dating those would make a node nobody
// configured outrank the nodes somebody did
bool cluster_config_moved(void)
{
	char hash[CLUSTER_HASHLEN] = "", credhash[CLUSTER_HASHLEN] = "";
	config_hash_scope(SCOPE_SETTINGS, false, hash);
	config_hash_scope(SCOPE_CREDENTIALS, false, credhash);

	pthread_mutex_lock(&stamped_lock);
	const bool moved = strcmp(hash, stamped_hash) != 0 ||
	                   strcmp(credhash, stamped_credhash) != 0;

	strncpy(stamped_hash, hash, sizeof(stamped_hash) - 1);
	stamped_hash[sizeof(stamped_hash) - 1] = '\0';
	strncpy(stamped_credhash, credhash, sizeof(stamped_credhash) - 1);
	stamped_credhash[sizeof(stamped_credhash) - 1] = '\0';
	pthread_mutex_unlock(&stamped_lock);

	return moved;
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
// which lock_shm() could not be - it is taken and released inside it
static pthread_mutex_t sync_lock = PTHREAD_MUTEX_INITIALIZER;

// Cancellation is switched off while the lock is held. terminate_threads()
// cancels the cluster thread where it sleeps, and the writes below reach
// cancellation points of their own (open, fsync, close) - being cancelled in
// one of those would leave the lock held forever, with every peer pushing to
// this node parked behind it and FTL unable to finish stopping
static int sync_lock_cancelstate = PTHREAD_CANCEL_ENABLE;

void cluster_sync_lock(void)
{
	int state = PTHREAD_CANCEL_ENABLE;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
	pthread_mutex_lock(&sync_lock);
	sync_lock_cancelstate = state;
}

void cluster_sync_unlock(void)
{
	const int state = sync_lock_cancelstate;
	pthread_mutex_unlock(&sync_lock);
	pthread_setcancelstate(state, NULL);
}

// What this node hands to a peer. It is byte for byte what GET /api/config
// answers, minus the items that never leave a node, so there is no second
// notion anywhere of what a configuration document looks like
cJSON *cluster_config_document(double *changed, const bool encrypted)
{
	cJSON *document = cJSON_CreateObject();

	// The document and the time it was last changed are read together: sent
	// apart, a save made between the two would reach a peer as the values
	// from before it under the timestamp from after it, and that peer would
	// then hold a configuration nobody can correct
	lock_shm();
	get_json_config(NULL, document, false, true, encrypted);
	*changed = config_changed;
	unlock_shm();

	return document;
}

// The peer reads a request body into a fixed buffer, so a document at or above
// that size would arrive truncated. Asked before sending and asked again by the
// caller, which stops sending rather than repeating the attempt every round
bool cluster_push_possible(const char *body)
{
	return strlen(body) < MAX_PAYLOAD_BYTES - 1;
}

// ...and this is how it gets there: a PATCH of the peer's configuration, the
// request the web interface makes when somebody hits Save. The peer decides
// item by item whether it already holds what we sent, so a node that is up to
// date changes nothing, writes nothing and restarts nothing
bool cluster_push_config(struct cluster_peer *peer, const char *body, const double changed)
{
	// The peer takes the configuration and the time it was changed at
	// together, so it can tell the next node the same thing we told it
	char path[64] = "";
	snprintf(path, sizeof(path), "/api/config?changed=%.6f", changed);

	if(!cluster_push_possible(body))
	{
		log_warn("cluster: configuration is too large to synchronize (%zu bytes)",
		         strlen(body));
		return false;
	}

	cJSON *answer = NULL;
	char err[CLUSTER_STRLEN] = "";
	if(!cluster_http_patch(peer, path, body, &answer, err, sizeof(err)))
	{
		log_debug(DEBUG_CLUSTER, "cluster: cannot hand config to %s: %s", peer->url, err);
		return false;
	}

	cJSON_Delete(answer);

	return true;
}

// What the process watching the run writes back through the pipe
#define GRAVITY_DONE '1'
#define GRAVITY_FAILED '0'

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

bool cluster_run_gravity(void)
{
	if(gravity_fd >= 0)
		return false; // our own run, still going

	// Claimed in one step, so the web interface and this thread cannot both
	// think they got it - and so neither clears what the other took
	if(__atomic_exchange_n(&gravity_running, 1, __ATOMIC_SEQ_CST) != 0)
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
		__atomic_store_n(&gravity_running, 0, __ATOMIC_SEQ_CST);
		return false;
	}

	const pid_t pid = fork();
	if(pid < 0)
	{
		log_err("cluster: cannot fork for gravity: %s", strerror(errno));
		close(fds[0]);
		close(fds[1]);
		__atomic_store_n(&gravity_running, 0, __ATOMIC_SEQ_CST);
		return false;
	}

	if(pid == 0)
	{
		close(fds[0]);

		// This process does nothing but wait for the run below, and
		// nothing else in it reaps: a child of a single-threaded process
		// that waits for it is one whose exit status arrives
		const pid_t child = fork();
		if(child == 0)
		{
			close(fds[1]);

			// Gravity writes a lot, and none of it belongs in the
			// answer of whoever triggered this
			const int fd = open("/dev/null", O_WRONLY);
			if(fd >= 0)
			{
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
			// Deliberately not shielded from SIGTERM, though the
			// API's own gravity path is (src/api/action.c). That
			// shield does not work under the KillMode its comment
			// names: setsid does not leave the cgroup, and systemd's
			// stop is not done until the cgroup is empty - so a stop
			// landing in a rebuild waits out TimeoutStopSec (60 s in
			// pihole-FTL.service, answering no DNS meanwhile) and
			// SIGKILLs the run at the end of it anyway. Taking the
			// SIGTERM promptly costs the rebuild, which is owed and
			// retried, rather than a minute of the whole node
			execl(PIHOLE_BINARY, "pihole", "-g", (char *)NULL);
			// Only reached if exec failed
			_exit(EXIT_FAILURE);
		}

		int status = 0;
		const char outcome = child > 0 && waitpid(child, &status, 0) == child &&
		                     WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS ?
		                     GRAVITY_DONE : GRAVITY_FAILED;
		if(write(fds[1], &outcome, 1) != 1)
			_exit(EXIT_FAILURE);
		_exit(EXIT_SUCCESS);
	}

	close(fds[1]);

	// Not waited for here: gravity takes minutes, and the cluster thread has
	// peers to watch and a DHCP hand-over to decide in that time
	if(fcntl(fds[0], F_SETFL, O_NONBLOCK) != 0)
		log_warn("cluster: cannot watch the gravity run: %s", strerror(errno));
	gravity_fd = fds[0];
	gravity_pid = pid;
	gravity_ok = false;

	return true;
}

// Looked at once per tick. Blocking here would leave the cluster blind for the
// whole run, and a node failing over during it would go unnoticed
void cluster_gravity_check(void)
{
	if(gravity_fd < 0)
		return;

	char outcome = 0;
	const ssize_t len = read(gravity_fd, &outcome, 1);
	if(len < 0 && (errno == EAGAIN || errno == EINTR))
		return; // still running, looked at again next tick

	close(gravity_fd);
	gravity_fd = -1;
	__atomic_store_n(&gravity_running, 0, __ATOMIC_SEQ_CST);

	// Whoever gets there first: this leaves no zombie behind if dnsmasq has
	// not already taken it
	if(gravity_pid > 0)
		waitpid(gravity_pid, NULL, WNOHANG);
	gravity_pid = 0;

	if(len == 1 && outcome == GRAVITY_DONE)
	{
		log_info("cluster: gravity finished");
		gravity_ok = true;
		return;
	}

	if(len == 1)
		log_warn("cluster: gravity failed, is %s installed?", PIHOLE_BINARY);
	else
		// The run died before it could say how it went, so whether the
		// lists were built is unknown - and unknown is not success
		log_warn("cluster: gravity outcome unknown");
}

bool cluster_pull_gravity(struct cluster_peer *peer, const char *held, bool *rebuilding)
{
	*rebuilding = false;

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
	// this node walk a hundred thousand entries
	// The round decided to pull on the tables as they were when it began, and
	// the download above took seconds. An entry added or removed here in
	// between was answered 2xx and would go with the rest of the table: kept
	// instead, and the next round dates it as the edit it is
	char now[CLUSTER_HASHLEN] = "";
	if(held != NULL && strlen(held) > 0 &&
	   tables_hash(gravity_tables, ArraySize(gravity_tables), now) && strcmp(now, held) != 0)
	{
		cJSON_Delete(import);
		cJSON_Delete(files);
		free(data);
		log_info("cluster: lists changed here while those of %s were on their way, keeping them", peer->url);
		return false;
	}

	const char *error = read_teleporter_zip(data, size, 4, hint, import, files);
	cJSON_Delete(import);
	cJSON_Delete(files);
	free(data);

	if(error != NULL)
	{
		log_err("cluster: cannot import lists of %s: %s (%s)", peer->url, error, hint);
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

// Set when this node joined a cluster and has to arrive as a new member
static bool state_forgotten = false;

bool cluster_state_known(void)
{
	return state_loaded;
}

void cluster_state_load(struct cluster_sync_state *state)
{
	bool generated_id = false;
	// Both empty unless the file carries them in the form written above. A
	// file that does not is one this node cannot compare against, and what
	// it holds now becomes the baseline instead
	char stored_hash[CLUSTER_HASHLEN] = "";
	char stored_credhash[CLUSTER_HASHLEN] = "";
	char stored_version[64] = "";
	memset(state, 0, sizeof(*state));
	node_id[0] = '\0';

	FILE *file = fopen(CLUSTER_STATE_FILE, "r");
	if(file != NULL)
	{
		char line[256] = "";
		while(fgets(line, sizeof(line), file) != NULL)
		{
			double when = 0.0;
			char hash[CLUSTER_HASHLEN] = "", credhash[CLUSTER_HASHLEN] = "";
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
			else if(sscanf(line, "hash %64s %64s", hash, credhash) == 2)
			{
				strncpy(stored_hash, hash, sizeof(stored_hash) - 1);
				strncpy(stored_credhash, credhash, sizeof(stored_credhash) - 1);
			}
			else if(sscanf(line, "version %63s", built) == 1)
			{
				strncpy(stored_version, built, sizeof(stored_version) - 1);
				stored_version[sizeof(stored_version) - 1] = '\0';
			}
			else if(sscanf(line, "vip %63s", vip) == 1)
				vip_note_placed(vip, "");
			else if(sscanf(line, "config %lf", &when) == 1)
			{
				// When this node was last configured by somebody
				// here. FTL restarts itself whenever a setting
				// asks for it, so keeping this in memory only
				// would reset it several times a day.
				// A stamp from the future - a node that booted
				// with a dead clock, or a hand-edited file -
				// would sit above every change anybody makes
				// until wall time caught up with it
				// Hardware without a real-time clock comes back with
				// a time behind the one it shut down at, so what was
				// written an hour ago reads as the future. Clamped
				// to now rather than discarded: this node really was
				// configured, and forgetting that hands the cluster
				// to whoever was not
				if(!isfinite(when) || when < 0.0)
					log_warn("cluster: %s holds an unusable timestamp, starting over",
					         CLUSTER_STATE_FILE);
				else
					config_changed = fmin(when, double_time());
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
	char now_settings[CLUSTER_HASHLEN] = "", now_credentials[CLUSTER_HASHLEN] = "";
	config_hash_scope(SCOPE_SETTINGS, false, now_settings);
	config_hash_scope(SCOPE_CREDENTIALS, false, now_credentials);

	// The fingerprint covers item keys as well as item values, so a release
	// that adds, removes or renames a synchronized item moves it without
	// anybody having configured anything. Comparing across an upgrade would
	// read that as an edit, stamp this node as the most recently configured
	// one in the cluster, and hand its months-old document to every peer
	same_build_state = strcmp(stored_version, git_version()) == 0;
	const bool same_build = same_build_state;
	const bool comparable = strlen(stored_hash) > 0 && strlen(stored_credhash) > 0 && same_build;

	if(strlen(stored_version) > 0 && !same_build)
		log_info("cluster: FTL was upgraded from %s, keeping this node's configuration timestamp",
		         stored_version);

	pthread_mutex_lock(&stamped_lock);
	strncpy(stamped_hash, comparable ? stored_hash : now_settings, sizeof(stamped_hash) - 1);
	strncpy(stamped_credhash, comparable ? stored_credhash : now_credentials,
	        sizeof(stamped_credhash) - 1);
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
	// ...and the same two halves say whether somebody configured this node
	// while it was down
	const bool changed_while_down = comparable &&
	                                (strcmp(now_settings, stored_hash) != 0 ||
	                                 strcmp(now_credentials, stored_credhash) != 0);

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
		pthread_setcancelstate(cancelstate, NULL);
		return;
	}

	FILE *file = fdopen(fd, "w");
	if(file == NULL)
	{
		log_err("cluster: cannot write %s: %s", tmpfile, strerror(errno));
		close(fd);
		pthread_mutex_unlock(&state_file_lock);
		pthread_setcancelstate(cancelstate, NULL);
		return;
	}

	fprintf(file, "node %s\n", node_id);
	fprintf(file, "gravity %.6f %s\n", saved_state.gravity_changed, saved_state.gravity_hash);
	if(saved_state.pending_changed > 0.0)
		fprintf(file, "pending %.6f %s %s\n", saved_state.pending_changed,
		        strlen(saved_state.pending_id) > 0 ? saved_state.pending_id : "-",
		        strlen(saved_state.pending_hash) > 0 ? saved_state.pending_hash : "-");
	fprintf(file, "config %.6f\n", config_changed);
	// The virtual address this node placed, if it holds one. Read back at
	// start-up so an FTL that was killed can tell the address it left behind
	// from one the administrator configured on the machine
	char placed[CLUSTER_STRLEN] = "";
	if(vip_placed_address(placed, sizeof(placed)))
		fprintf(file, "vip %s\n", placed);
	pthread_mutex_lock(&stamped_lock);
	// Both halves: what may travel depends on the member list, so a single
	// fingerprint would stop being comparable the moment somebody edits it
	fprintf(file, "hash %s %s\n", stamped_hash, stamped_credhash);
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
		pthread_setcancelstate(cancelstate, NULL);
		return;
	}

	if(rename(tmpfile, CLUSTER_STATE_FILE) != 0)
	{
		log_err("cluster: cannot rename %s: %s", tmpfile, strerror(errno));
		unlink(tmpfile);
		pthread_mutex_unlock(&state_file_lock);
		pthread_setcancelstate(cancelstate, NULL);
		return;
	}

	const int dirfd = open("/etc/pihole", O_RDONLY | O_DIRECTORY);
	if(dirfd >= 0)
	{
		fsync(dirfd);
		close(dirfd);
	}

	pthread_mutex_unlock(&state_file_lock);
	pthread_setcancelstate(cancelstate, NULL);
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
	state_forgotten = true;
	config_changed = 0.0;

	if(unlink(CLUSTER_STATE_FILE) != 0 && errno != ENOENT)
		log_warn("cluster: cannot remove %s: %s", CLUSTER_STATE_FILE, strerror(errno));
}
