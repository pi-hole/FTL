/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Encrypted upstream URI parser
*
*  Parses one dns.upstreams entry; plaintext entries are only classified
*  (dnsmasq validates them), encrypted entries are strictly validated.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "upstream_uri.h"

#include <string.h>
#include <stddef.h>

// Bounded copy of src[len] into dst[cap] including the terminating NUL. Returns
 // false (no write past cap) if it would not fit.
static bool bcopy_str(char *dst, size_t cap, const char *src, size_t len)
{
	if(len >= cap)
		return false;
	memcpy(dst, src, len);
	dst[len] = '\0';
	return true;
}

// Only characters valid in hostnames and IP literals (IPv6 brackets are
 // stripped before this is called); rejecting the rest also blocks header/URI
 // injection via the SNI/Host value.
// allow_colon permits ':' for a bracketed IPv6 literal only; a plain hostname
// or a bare (unbracketed) host must not contain one - ':' is never a port
// separator here (we use '#'), so an unbracketed ':' is a malformed entry.
static bool __attribute__((pure)) valid_host(const char *h, bool allow_colon)
{
	if(h[0] == '\0')
		return false;
	for(const char *p = h; *p != '\0'; p++)
	{
		const unsigned char c = (unsigned char)*p;
		if(!(( c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		     ( c >= '0' && c <= '9') || c == '.' || c == '-' ||
		     (allow_colon && c == ':')))
			return false;
	}
	return true;
}

// Parse a decimal port in [1, 65535]; returns -1 on any error.
static int __attribute__((pure)) parse_port(const char *s)
{
	if(s[0] == '\0')
		return -1;
	long v = 0;
	for(const char *p = s; *p != '\0'; p++)
	{
		if(*p < '0' || *p > '9')
			return -1;
		v = v * 10 + (*p - '0');
		if(v > 65535)
			return -1;
	}
	return (v < 1) ? -1 : (int)v;
}

// Parse one dns.upstreams entry
//
// Returns true on success. For UST_PLAIN only .type and .connect_host are
// meaningful (plaintext entries are handled by dnsmasq, not the proxy).
//
// Encrypted forms (strictly validated):
// tls://<host>[#<port>]                 DoT, default port 853
// tls://<verify>@<ip>[#<port>]          DoT, pinned IP + SNI/verify name
// tls://[<ipv6>][#<port>]               DoT to a bracketed IPv6 literal
// https://<host>[#<port>][/<path>]      DoH, default port 443, path /dns-query
// https://<verify>@<ip>[#<port>][/<path>]
//
// Rejects control characters (incl. CR/LF), empty host, invalid/oversized
// fields, and unknown schemes.
bool parse_upstream_uri(const char *in, struct upstream_uri *out)
{
	if(in == NULL || out == NULL)
		return false;

	const size_t inlen = strlen(in);
	if(inlen == 0 || inlen >= 512)
		return false;

	// Reject any control character (incl. CR/LF/TAB and DEL) up front.
	for(size_t i = 0; i < inlen; i++)
	{
		const unsigned char c = (unsigned char)in[i];
		if(c < 0x20 || c == 0x7f)
			return false;
	}

	memset(out, 0, sizeof(*out));

	// Scheme detection. No "://" means a plaintext entry: only classify it,
	// dnsmasq validates the actual syntax.
	const char *sep = strstr(in, "://");
	if(sep == NULL)
	{
		out->type = UST_PLAIN;
		return bcopy_str(out->connect_host, sizeof(out->connect_host), in, inlen);
	}

	const size_t schemelen = (size_t)(sep - in);
	if(schemelen == 3 && strncmp(in, "tls", 3) == 0)
		out->type = UST_DOT;
	else if(schemelen == 5 && strncmp(in, "https", 5) == 0)
		out->type = UST_DOH;
	else
		return false; // unknown scheme

	const char *rest = sep + 3;
	// 853 is the DoT default port (RFC 7858 Sec. 3.1); 443 is HTTPS for
	// DoH.
	const int default_port = (out->type == UST_DOT) ? 853 : 443;

	// For DoH, split off the path at the first '/'.
	const char *authority_end = rest + strlen(rest);
	if(out->type == UST_DOH)
	{
		const char *slash = strchr(rest, '/');
		if(slash != NULL)
		{
			authority_end = slash;
			if(!bcopy_str(out->doh_path, sizeof(out->doh_path), slash, strlen(slash)))
				return false;
			// The path goes verbatim into the HTTP request-target, so it must
			// not contain whitespace or control characters. doh_build_request()
			// rejects those at runtime; reject them here so a bad path fails
			// config validation instead of silently disabling the upstream.
			for(const char *p = out->doh_path; *p != '\0'; p++)
				if((unsigned char)*p <= 0x20 || *p == 0x7f)
					return false;
		}
		else
			// RFC 8484 (Sec. 4.1.1) defines the path via a URI
			// Template rather than mandating one; "/dns-query" is
			// the widely used convention we default to.
			strcpy(out->doh_path, "/dns-query");
	}

	// authority = [<verify>@]<host>[#<port>], possibly [ipv6].
	const size_t authlen = (size_t)(authority_end - rest);
	char auth[UURI_HOST_MAX * 2];
	if(authlen >= sizeof(auth))
		return false;
	memcpy(auth, rest, authlen);
	auth[authlen] = '\0';

	char *host = auth;
	const char *verify = NULL;
	char *at = strchr(auth, '@');
	if(at != NULL)
	{
		*at = '\0';
		verify = auth; // left of '@' is the SNI/verify name
		host = at + 1; // right of '@' is the connect host
		if(verify[0] == '\0')
			return false;
	}

	char hostbuf[UURI_HOST_MAX];
	const char *portstr = NULL;
	const bool bracketed = (host[0] == '[');
	if(bracketed)
	{
		char *close = strchr(host, ']');
		if(close == NULL)
			return false;
		if(!bcopy_str(hostbuf, sizeof(hostbuf), host + 1, (size_t)(close - (host + 1))))
			return false;
		char *after = close + 1;
		if(*after == '#')
			portstr = after + 1;
		else if(*after != '\0')
			return false;
	}
	else
	{
		char *hash = strchr(host, '#');
		if(hash != NULL)
		{
			*hash = '\0';
			portstr = hash + 1;
		}
		if(!bcopy_str(hostbuf, sizeof(hostbuf), host, strlen(host)))
			return false;
	}

	// ':' is only legitimate inside the bracketed IPv6 form.
	if(!valid_host(hostbuf, bracketed))
		return false;

	int port = default_port;
	if(portstr != NULL)
	{
		port = parse_port(portstr);
		if(port < 0)
			return false;
	}

	// SNI/verify name: the explicit one from '@', else the host (already
	// validated above), so only the explicit name needs re-checking.
	const char *vn = hostbuf;
	if(verify != NULL)
	{
		if(!valid_host(verify, false))
			return false;
		vn = verify;
	}

	if(!bcopy_str(out->connect_host, sizeof(out->connect_host), hostbuf, strlen(hostbuf)))
		return false;
	if(!bcopy_str(out->verify_name, sizeof(out->verify_name), vn, strlen(vn)))
		return false;
	out->port = port;
	return true;
}
