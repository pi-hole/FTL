/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Outbound HTTP(S) downloader
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-client.h"
// get_FTL_version()
#include "log.h"
// chown_pihole()
#include "files.h"

#include <fcntl.h>
#include <limits.h>
#include <strings.h>
#include <sys/stat.h>

#ifdef HAVE_CURL
#include <curl/curl.h>
#endif

void http_result_free(struct http_result *res)
{
	// FTL's free() warns when handed NULL, and this is called on paths where
	// there is nothing left to release
	if(res == NULL || res->body == NULL)
		return;
	free(res->body);
}

#ifdef HAVE_CURL

// Schemes we accept, and which of them are TLS. A redirect may upgrade into
// TLS but never drop back out of it.
static const struct {
	const char *prefix;
	bool tls;
} schemes[] = {
	{ "http://",  false },
	{ "https://", true  },
	{ "ftp://",   false },
	{ "ftps://",  true  },
	{ "file://",  false },
};
#define HTTP_DL_SCHEME_LIST "http://, https://, ftp://, ftps:// and file://"

// Where the response body goes. Exactly one of buf (in-memory) and fd (file)
// is in use; fd is -1 in the in-memory case.
struct sink {
	size_t len;
	char *buf;
	size_t cap;
	int fd;
	bool oversize;
	bool io_error;
	int err;
};

static size_t sink_write(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct sink *s = userdata;
	const size_t n = size * nmemb;

	if(n == 0)
		return 0;

	// The cap is enforced here rather than left to CURLOPT_MAXFILESIZE_LARGE:
	// that one only acts on a declared Content-Length, so a chunked, a
	// close-delimited or simply a lying response would walk straight past it.
	// Returning short aborts the transfer with CURLE_WRITE_ERROR.
	if(n > HTTP_DL_MAX_BYTES - s->len)
	{
		s->oversize = true;
		return 0;
	}

	if(s->fd < 0)
	{
		// Keep one spare byte so the buffer can always be NUL-terminated:
		// lua_pushexternalstring() asserts s[len] == '\0'.
		if(s->len + n + 1 > s->cap)
		{
			size_t cap = s->cap > 0 ? s->cap : 8192;
			while(cap < s->len + n + 1)
				cap *= 2;
			if(cap > (size_t)HTTP_DL_MAX_BYTES + 1)
				cap = (size_t)HTTP_DL_MAX_BYTES + 1;
			char *tmp = realloc(s->buf, cap);
			if(tmp == NULL)
			{
				s->io_error = true;
				s->err = ENOMEM;
				return 0;
			}
			s->buf = tmp;
			s->cap = cap;
		}
		memcpy(s->buf + s->len, ptr, n);
		s->len += n;
		s->buf[s->len] = '\0';
		return n;
	}

	for(size_t off = 0; off < n;)
	{
		const ssize_t w = write(s->fd, ptr + off, n - off);
		if(w < 0)
		{
			if(errno == EINTR)
				continue;
			s->io_error = true;
			s->err = errno;
			return 0;
		}
		off += (size_t)w;
	}
	s->len += n;
	return n;
}

// A page may compose the destination from request data, so refuse anything that
// could walk out of the directory it was handed.
static bool dest_ok(const char *dest, char *err, size_t errsz)
{
	const size_t len = strlen(dest);

	if(dest[0] != '/')
	{
		snprintf(err, errsz, "destination path must be absolute");
		return false;
	}
	if(dest[len - 1] == '/')
	{
		snprintf(err, errsz, "destination path must name a file");
		return false;
	}
	if(len + sizeof(".XXXXXX") > PATH_MAX)
	{
		snprintf(err, errsz, "destination path is too long");
		return false;
	}
	for(const char *p = dest; p != NULL; p = strchr(p + 1, '/'))
	{
		if(strncmp(p, "/..", 3) == 0 && (p[3] == '/' || p[3] == '\0'))
		{
			snprintf(err, errsz, "destination path must not contain \"..\"");
			return false;
		}
	}
	return true;
}

// fsync the directory holding path, so the rename() itself is durable
static void fsync_parent(const char *path)
{
	char dir[PATH_MAX];
	if(snprintf(dir, sizeof(dir), "%s", path) >= (int)sizeof(dir))
		return;

	char *slash = strrchr(dir, '/');
	if(slash == NULL)
		return;
	*slash = '\0';

	const int fd = open(dir[0] != '\0' ? dir : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if(fd < 0)
		return;
	fsync(fd);
	close(fd);
}

// Move the completed temporary file into place. Consumes fd either way.
static bool tmp_commit(int fd, const char *tmp, const char *dest, char *err, size_t errsz)
{
	if(fsync(fd) != 0)
	{
		snprintf(err, errsz, "could not flush %s to disk: %s", tmp, strerror(errno));
		close(fd);
		return false;
	}
	if(close(fd) != 0)
	{
		snprintf(err, errsz, "could not finalize %s: %s", tmp, strerror(errno));
		return false;
	}

	// Hand the file to the pihole user before it becomes visible under its
	// final name, so it is never briefly owned by root under that name.
	chown_pihole(tmp, NULL);

	if(rename(tmp, dest) != 0)
	{
		snprintf(err, errsz, "could not rename %s to %s: %s", tmp, dest, strerror(errno));
		return false;
	}

	fsync_parent(dest);
	return true;
}

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static bool curl_ready = false;

static void curl_init_once(void)
{
	curl_ready = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK;
}

#endif // HAVE_CURL

bool http_get(const char *url, const char *dest, struct http_result *res)
{
	memset(res, 0, sizeof(*res));

#ifndef HAVE_CURL
	(void)url;
	(void)dest;
	snprintf(res->err, sizeof(res->err),
	         "this pihole-FTL was built without HTTP client support");
	return false;
#else
	pthread_once(&curl_once, curl_init_once);
	if(!curl_ready)
	{
		snprintf(res->err, sizeof(res->err), "could not initialize libcurl");
		return false;
	}

	// Matched here as well as through CURLOPT_PROTOCOLS_STR so the message names
	// the offending scheme instead of curl's generic "unsupported protocol".
	bool tls = false;
	bool known = false;
	for(size_t i = 0; !known && i < sizeof(schemes) / sizeof(*schemes); i++)
		if(strncasecmp(url, schemes[i].prefix, strlen(schemes[i].prefix)) == 0)
		{
			tls = schemes[i].tls;
			known = true;
		}
	if(!known)
	{
		snprintf(res->err, sizeof(res->err), "unsupported URL scheme (only %s are supported)",
		         HTTP_DL_SCHEME_LIST);
		return false;
	}

	struct sink sink = { .fd = -1 };
	char tmp[PATH_MAX] = "";

	if(dest != NULL)
	{
		if(!dest_ok(dest, res->err, sizeof(res->err)))
			return false;

		// mkostemp() rather than a fixed ".tmp" suffix: several CivetWeb workers
		// may download to the same destination at once, and an unpredictable
		// name leaves no window for a planted decoy either.
		snprintf(tmp, sizeof(tmp), "%s.XXXXXX", dest);
		sink.fd = mkostemp(tmp, O_CLOEXEC);
		if(sink.fd < 0)
		{
			snprintf(res->err, sizeof(res->err), "could not create a temporary file next to %s: %s",
			         dest, strerror(errno));
			return false;
		}
		if(fchmod(sink.fd, S_IRUSR | S_IWUSR | S_IRGRP) != 0)
			log_warn("Unable to set permissions on file \"%s\": %s", tmp, strerror(errno));
	}

	CURL *curl = curl_easy_init();
	if(curl == NULL)
	{
		snprintf(res->err, sizeof(res->err), "could not initialize a libcurl handle");
		if(sink.fd >= 0)
		{
			close(sink.fd);
			unlink(tmp);
		}
		return false;
	}

	char ebuf[CURL_ERROR_SIZE] = "";
	char agent[64] = "";
	snprintf(agent, sizeof(agent), "pihole-FTL/%s", get_FTL_version());

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, ebuf);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, agent);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sink_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);

	// The image builds curl with only these protocols, but say so anyway: this
	// is the gate that survives someone rebuilding it less restrictively.
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https,ftp,ftps,file");
	// file and ftp are deliberately absent here. A redirect must never be able
	// to reach them, or a remote server could answer a fetch with
	// "Location: file:///..." and have us read that back to the caller. For the
	// same reason an https fetch may not be redirected down to http, while the
	// upgrade is fine.
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, tls ? "https" : "http,https");
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, HTTP_DL_MAX_REDIRECTS);

	// A total timeout, not just a connect one: without it a peer trickling a
	// byte per idle window pins a CivetWeb worker indefinitely.
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, HTTP_DL_CONNECT_MS);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, HTTP_DL_TOTAL_MS);
	// Mandatory off the main thread: keeps curl away from alarm() and SIGPIPE.
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

	// Offer every encoding this libcurl can undo, and let it decompress before
	// the body reaches us. The cap in the write callback therefore counts
	// decompressed bytes, so a small response that inflates to gigabytes still
	// trips it - CURLOPT_MAXFILESIZE_LARGE only ever sees the compressed length.
	curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
	// Only used when the URL carries credentials, and CURLOPT_UNRESTRICTED_AUTH
	// stays off, so a redirect to another host never sees them.
	curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)(CURLAUTH_BASIC | CURLAUTH_DIGEST));
	curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)HTTP_DL_MAX_BYTES);
	// Ignore http_proxy and friends so a download does not quietly behave
	// differently depending on the environment FTL was started in.
	curl_easy_setopt(curl, CURLOPT_PROXY, "");

	// Honour OpenSSL's own environment variables, which is also what lets the
	// test suite point at its private CA without a config key.
	const char *ca_file = getenv("SSL_CERT_FILE");
	const char *ca_dir = getenv("SSL_CERT_DIR");
	if(ca_file != NULL && ca_file[0] != '\0')
		curl_easy_setopt(curl, CURLOPT_CAINFO, ca_file);
	if(ca_dir != NULL && ca_dir[0] != '\0')
		curl_easy_setopt(curl, CURLOPT_CAPATH, ca_dir);

	log_debug(DEBUG_WEBSERVER, "Downloading %s to %s", url, dest != NULL ? dest : "memory");

	const CURLcode rc = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &res->status);
	curl_easy_cleanup(curl);

	bool ok = true;
	if(rc != CURLE_OK)
	{
		ok = false;
		if(sink.oversize || rc == CURLE_FILESIZE_EXCEEDED)
			snprintf(res->err, sizeof(res->err), "response is larger than %u bytes",
			         HTTP_DL_MAX_BYTES);
		else if(sink.io_error)
			snprintf(res->err, sizeof(res->err), "could not store the downloaded data: %s",
			         strerror(sink.err));
		else
			snprintf(res->err, sizeof(res->err), "%s",
			         ebuf[0] != '\0' ? ebuf : curl_easy_strerror(rc));
	}
	else if(res->status >= 400)
	{
		ok = false;
		snprintf(res->err, sizeof(res->err), "server responded with HTTP %ld", res->status);
	}

	if(sink.fd >= 0)
	{
		if(ok)
			ok = tmp_commit(sink.fd, tmp, dest, res->err, sizeof(res->err));
		else
			close(sink.fd);
		// Nothing is left behind on failure, and dest keeps whatever it held
		if(!ok)
			unlink(tmp);
	}

	if(!ok)
	{
		if(sink.buf != NULL)
			free(sink.buf);
		return false;
	}

	res->len = sink.len;
	if(dest == NULL)
	{
		// An empty body is still a body: hand Lua a valid pointer, not NULL
		if(sink.buf == NULL)
		{
			sink.buf = calloc(1, 1);
			if(sink.buf == NULL)
			{
				snprintf(res->err, sizeof(res->err), "out of memory");
				return false;
			}
		}
		res->body = sink.buf;
	}

	return true;
#endif
}
