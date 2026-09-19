/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  EDNS(0) query padding (RFC 7830 / RFC 8467)
*
*  Public interface of the query padding helper: rounds an outbound encrypted
*  query up to a block boundary by adding an EDNS(0) Padding option, so the size
*  of the ciphertext no longer leaks the query. Self-contained (no DNS library),
*  so the regression harness can use it directly.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_EDNS_PAD_H
#define DOTDOH_EDNS_PAD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Pad a DNS query in place to the next multiple of 128 octets (RFC 8467 client
// policy) by adding or extending an EDNS(0) Padding option (RFC 7830, option code
// 12). buf holds the len-byte message and has capacity bufsz.
//
// Returns the new message length, or len unchanged (fail-open) when padding is
// not safely possible: a truncated/malformed message, an OPT record that is not
// the last RR, a query that already carries a Padding option, or a result that
// would not fit in bufsz (or the 64 KiB DNS limit). Padding is best-effort
// privacy hardening, so a query we cannot pad is still sent as-is rather than
// dropped.
size_t edns_pad_query(uint8_t *buf, size_t len, size_t bufsz);

// Requestor's advertised EDNS UDP payload size from a query (OPT CLASS field), or
// 512 when absent/unparsable. See edns_pad.c for details.
uint16_t edns_query_udp_size(const uint8_t *buf, size_t len) __attribute__((pure));

// Pad a DNS response in place to the next multiple of 468 octets (RFC 8467 server
// policy). Unlike a query, a response is only padded when it already carries an
// EDNS(0) OPT record - a fresh OPT is never synthesised onto an answer. Same
// in-place semantics, idempotency and fail-open behaviour as edns_pad_query.
//
// The caller must gate this on the request having carried a Padding option
// (RFC 8467 Sec. 4): a server MUST NOT pad a response otherwise. See
// edns_has_padding_option().
size_t edns_pad_response(uint8_t *buf, size_t len, size_t bufsz);

// As above, but for a response we built ourselves and which therefore has no OPT
// yet; only valid when the query carried one.
size_t edns_pad_response_synth(uint8_t *buf, size_t len, size_t bufsz, bool set_do,
                               bool pad);

// Whether `buf` carries an OPT RR; *do_bit reports its DO flag when it does.
bool edns_query_opt(const uint8_t *buf, size_t len, bool *do_bit);

// Whether the DNS message msg carries the given EDNS(0) option code in its OPT
// RR. Fail-safe: returns false on any malformed input.
bool edns_has_option(const uint8_t *msg, size_t len, uint16_t code) __attribute__((pure));

// Remove the first EDNS(0) option with the given code from the OPT RR of buf,
// which holds a len-byte message, and return the new message length. When the
// message also carries a Padding option, the freed bytes are absorbed into it so
// the (RFC 8467) padded length is preserved; otherwise the message shrinks.
// Fail-open: a message without an OPT, without that option, or malformed is
// returned unchanged. The freed bytes are only absorbed when the OPT RR ends the
// message and the Padding option ends its RDATA; otherwise the message shrinks.
size_t edns_remove_option(uint8_t *buf, size_t len, uint16_t code);

// Whether the DNS message msg carries an EDNS(0) Padding option in its OPT RR.
// Fail-safe: returns false on any malformed input. Used to decide whether a
// response may be padded (per the request).
bool edns_has_padding_option(const uint8_t *msg, size_t len) __attribute__((pure));

#endif // DOTDOH_EDNS_PAD_H
