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

// Pad a DNS query in place to the next multiple of EDNS_PAD_BLOCK octets by
// adding (or extending) an EDNS(0) Padding option (RFC 7830, option code 12)
// following the recommended query policy of RFC 8467. buf holds the len-byte
// message and has capacity bufsz.
//
// Returns the new message length, or len unchanged (fail-open) when padding is
// not safely possible: a truncated/malformed message, an OPT record that is not
// the last RR, a query that already carries a Padding option, or a result that
// would not fit in bufsz (or the 64 KiB DNS limit). Padding is best-effort
// privacy hardening, so a query we cannot pad is still sent as-is rather than
// dropped.
size_t edns_pad_query(uint8_t *buf, size_t len, size_t bufsz);

#endif // DOTDOH_EDNS_PAD_H
