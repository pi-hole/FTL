/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API authentication prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef AUTH_H
#define AUTH_H

// crypto library
#include <nettle/sha2.h>
#include <nettle/base64.h>
#include <nettle/version.h>

// On 2017-08-27 (after v3.3, before v3.4), nettle changed the type of
// destination from uint_8t* to char* in all base64 and base16 functions
// (armor-signedness branch). This is a breaking change as this is a change in
// signedness causing issues when compiling FTL against older versions of
// nettle. We create this constant here to have a conversion if necessary.
// See https://github.com/gnutls/nettle/commit/f2da403135e2b2f641cf0f8219ad5b72083b7dfd
#if NETTLE_VERSION_MAJOR == 3 && NETTLE_VERSION_MINOR < 4
#define NETTLE_SIGN (uint8_t*)
#else
#define NETTLE_SIGN
#endif

// How many bits should the SID and CSRF token use?
#define SID_BITSIZE 128
#define SID_SIZE BASE64_ENCODE_RAW_LENGTH(SID_BITSIZE/8)

// SameSite=Strict: Defense against some classes of cross-site request forgery
// (CSRF) attacks. This ensures the session cookie will only be sent in a
// first-party (i.e., Pi-hole) context and NOT be sent along with requests
// initiated by third party websites.
//
// HttpOnly: the cookie cannot be accessed through client side script (if the
// browser supports this flag). As a result, even if a cross-site scripting
// (XSS) flaw exists, and a user accidentally accesses a link that exploits this
// flaw, the browser (primarily Internet Explorer) will not reveal the cookie to
// a third party.
#define FTL_SET_COOKIE "Set-Cookie: sid=%s; SameSite=Strict; Path=/; Max-Age=%u; HttpOnly\r\n"
#define FTL_DELETE_COOKIE "Set-Cookie: sid=deleted; SameSite=Strict; Path=/; Max-Age=-1\r\n"

struct session {
	bool used;
	bool app;
	struct {
		bool login;
		bool mixed;
	} tls;
	time_t login_at;
	time_t valid_until;
	char remote_addr[48]; // Large enough for IPv4 and IPv6 addresses, hard-coded in civetweb.h as mg_request_info.remote_addr
	char user_agent[128];
	char sid[SID_SIZE];
	char csrf[SID_SIZE];
};

#endif // AUTH_H