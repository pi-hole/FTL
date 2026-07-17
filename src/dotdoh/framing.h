/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  DoT/DoH wire framing
*
*  Public interface of the framing helpers (frame/deframe bytes only, no DNS
*  parsing). Self-contained so the regression harness can use it directly.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_FRAMING_H
#define DOTDOH_FRAMING_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define DNS_MSG_MAX 65535

// Largest HTTP/1.1 response header block a DoH response may carry before we
 // give up (guards the accumulation buffer against an endless header stream).
#define DOH_HEADER_MAX 8192

// DoT: write a 2-byte big-endian length prefix followed by msg into out.
 // Returns len+2 on success, -1 on empty/oversized msg or insufficient out.
ssize_t dot_frame(const uint8_t *msg, size_t len, uint8_t *out, size_t out_sz);

// DoT: inspect an accumulated receive buffer. Returns the DNS message length
 // and sets *msg_off to the offset of the message body once a full length-
 // prefixed message is present, 0 if more bytes are needed, -1 on a zero-length
 // (protocol error) frame.
ssize_t dot_deframe(const uint8_t *buf, size_t buflen, size_t *msg_off);

// DoH: build an HTTP/1.1 POST request carrying the DNS message. host and path
 // must be free of control characters. Returns request length or -1.
ssize_t doh_build_request(const char *host, const char *path,
                          const uint8_t *msg, size_t len, uint8_t *out, size_t out_sz);

// DoH: parse an accumulated HTTP/1.1 response. On a complete 200 response sets
 // body_off and body_len to the DNS answer within buf and returns total bytes
 // consumed; 0 if more bytes are needed; -1 on a non-200 status, a missing or
 // oversized Content-Length, or a malformed/oversized header block.
ssize_t doh_parse_response(const uint8_t *buf, size_t buflen,
                           size_t *body_off, size_t *body_len);

#endif // DOTDOH_FRAMING_H
