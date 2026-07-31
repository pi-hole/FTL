/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  EDNS(0) query padding (RFC 7830 / RFC 8467)
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "edns_pad.h"

#include <stdbool.h>
#include <string.h>

// RFC 8467 recommends clients pad queries to a multiple of this many octets.
#define EDNS_PAD_BLOCK 128
// EDNS(0) OPT resource record type (RFC 6891) and Padding option (RFC 7830).
#define DNS_TYPE_OPT   41
#define EDNS_OPT_PAD   12
// Requestor's UDP payload size advertised when we add an OPT ourselves. The
// transport to the upstream is a reliable stream (DoT/DoH), so this does not
// cap the answer; a conservative value keeps the record neutral.
#define EDNS_UDP_SIZE  1232
// The 2-byte DoT length prefix and DoH Content-Length bound the message to 64 KiB.
#define DNS_MSG_LIMIT  65535

// Advance *pos past a DNS name (RFC 1035 label sequence). Handles a trailing
// compression pointer as the terminator (2 octets). Returns false on any
// out-of-bounds or reserved label, leaving *pos undefined.
static bool skip_name(const uint8_t *buf, size_t len, size_t *pos)
{
	size_t p = *pos;
	for(;;)
	{
		if(p >= len)
			return false;
		const uint8_t c = buf[p];
		if(c == 0)               // root label: name ends here
		{
			p += 1;
			break;
		}
		if((c & 0xC0) == 0xC0)   // compression pointer: 2 octets, ends the name
		{
			if(p + 2 > len)
				return false;
			p += 2;
			break;
		}
		if((c & 0xC0) != 0)      // 0x40/0x80 are reserved label types
			return false;
		p += 1 + c;              // normal label
		if(p > len)
			return false;
	}
	*pos = p;
	return true;
}

// Requestor's advertised UDP payload size from the query's EDNS OPT record (the
// OPT CLASS field, RFC 6891), or 512 (the pre-EDNS default / RFC floor) when the
// query carries no OPT or cannot be parsed. Used to decide when a UDP answer must
// be TC-truncated so dnsmasq retries over TCP instead of receiving a byte-chopped
// datagram. Reads only up to the OPT RR; the padding appended later does not move
// the CLASS field, so this may be called before or after edns_pad_query().
uint16_t __attribute__((pure)) edns_query_udp_size(const uint8_t *buf, size_t len)
{
	if(len < 12)
		return 512;
	const uint16_t qdcount = (uint16_t)((buf[4] << 8) | buf[5]);
	const uint16_t ancount = (uint16_t)((buf[6] << 8) | buf[7]);
	const uint16_t nscount = (uint16_t)((buf[8] << 8) | buf[9]);
	const uint16_t arcount = (uint16_t)((buf[10] << 8) | buf[11]);
	size_t pos = 12;
	for(uint16_t i = 0; i < qdcount; i++)
	{
		if(!skip_name(buf, len, &pos) || pos + 4 > len)
			return 512;
		pos += 4;
	}
	const unsigned long total_rr = (unsigned long)ancount + nscount + arcount;
	for(unsigned long i = 0; i < total_rr; i++)
	{
		if(!skip_name(buf, len, &pos) || pos + 10 > len)
			return 512;
		const uint16_t type = (uint16_t)((buf[pos] << 8) | buf[pos + 1]);
		const uint16_t cls = (uint16_t)((buf[pos + 2] << 8) | buf[pos + 3]);
		const size_t rdlen = (size_t)((buf[pos + 8] << 8) | buf[pos + 9]);
		if(pos + 10 + rdlen > len)
			return 512;
		if(type == DNS_TYPE_OPT)
			return cls < 512 ? 512 : cls; // RFC 6891: values below 512 are 512
		pos += 10 + rdlen;
	}
	return 512;
}

size_t edns_pad_query(uint8_t *buf, size_t len, size_t bufsz)
{
	// Need at least a fixed 12-byte header to look at.
	if(len < 12)
		return len;

	const uint16_t qdcount = (uint16_t)((buf[4] << 8) | buf[5]);
	const uint16_t ancount = (uint16_t)((buf[6] << 8) | buf[7]);
	const uint16_t nscount = (uint16_t)((buf[8] << 8) | buf[9]);
	const uint16_t arcount = (uint16_t)((buf[10] << 8) | buf[11]);

	size_t pos = 12;

	// Question section: a name followed by QTYPE and QCLASS.
	for(uint16_t i = 0; i < qdcount; i++)
	{
		if(!skip_name(buf, len, &pos))
			return len;
		if(pos + 4 > len)
			return len;
		pos += 4;
	}

	// Walk every resource record, locating the OPT record if present. We need to
	// know it exists, where its RDLENGTH is, and that it is the last RR (so its
	// RDATA ends exactly at the message tail and we can append there).
	bool found_opt = false;
	size_t opt_rdlen_off = 0, opt_rdata_off = 0, opt_rdlen = 0;
	const unsigned long total_rr = (unsigned long)ancount + nscount + arcount;
	for(unsigned long i = 0; i < total_rr; i++)
	{
		if(!skip_name(buf, len, &pos))
			return len;
		if(pos + 10 > len) // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
			return len;
		const uint16_t type = (uint16_t)((buf[pos] << 8) | buf[pos + 1]);
		const size_t rdlen_off = pos + 8;
		const size_t rdlen = (size_t)((buf[rdlen_off] << 8) | buf[rdlen_off + 1]);
		const size_t rdata_off = pos + 10;
		if(rdata_off + rdlen > len)
			return len;

		if(type == DNS_TYPE_OPT)
		{
			if(found_opt) // a second OPT is malformed
				return len;
			found_opt = true;
			opt_rdlen_off = rdlen_off;
			opt_rdata_off = rdata_off;
			opt_rdlen = rdlen;

			// Scan existing options: if a Padding option is already present, leave
			// the message untouched (idempotent). A ragged option list that does
			// not tile the RDATA exactly is malformed -> fail open.
			size_t o = rdata_off;
			while(o + 4 <= rdata_off + rdlen)
			{
				const uint16_t oc = (uint16_t)((buf[o] << 8) | buf[o + 1]);
				const size_t ol = (size_t)((buf[o + 2] << 8) | buf[o + 3]);
				if(oc == EDNS_OPT_PAD)
					return len;
				o += 4 + ol;
			}
			if(o != rdata_off + rdlen)
				return len;
		}

		pos = rdata_off + rdlen;
	}

	// A clean parse consumes the whole message; trailing bytes mean malformed.
	if(pos != len)
		return len;

	// Fixed overhead added before the pad octets: the 4-byte Padding option
	// header, plus an 11-byte OPT RR (root name, TYPE, CLASS, TTL, RDLENGTH) when
	// the query has no OPT record yet.
	if(found_opt && opt_rdata_off + opt_rdlen != len)
		return len; // OPT is not the last RR -> cannot append at the tail
	const size_t overhead = found_opt ? 4 : (11 + 4);

	// Round the message up to the next EDNS_PAD_BLOCK boundary. The pad count is
	// always < EDNS_PAD_BLOCK, so it fits an option length comfortably.
	const size_t provisional = len + overhead;
	const size_t new_len = ((provisional + EDNS_PAD_BLOCK - 1) / EDNS_PAD_BLOCK) * EDNS_PAD_BLOCK;
	const size_t pad = new_len - provisional;
	if(new_len > bufsz || new_len > DNS_MSG_LIMIT)
		return len; // would not fit -> send unpadded

	if(found_opt)
	{
		// Append the Padding option to the existing OPT RDATA and grow RDLENGTH.
		size_t w = len;
		buf[w++] = 0x00;
		buf[w++] = EDNS_OPT_PAD;
		buf[w++] = (uint8_t)(pad >> 8);
		buf[w++] = (uint8_t)(pad & 0xff);
		memset(buf + w, 0, pad);
		const size_t new_rdlen = opt_rdlen + 4 + pad;
		buf[opt_rdlen_off]     = (uint8_t)(new_rdlen >> 8);
		buf[opt_rdlen_off + 1] = (uint8_t)(new_rdlen & 0xff);
	}
	else
	{
		// Append a fresh OPT RR carrying the Padding option, and bump ARCOUNT.
		size_t w = len;
		buf[w++] = 0x00;                              // root name
		buf[w++] = 0x00; buf[w++] = DNS_TYPE_OPT;     // TYPE = OPT (41)
		buf[w++] = (uint8_t)(EDNS_UDP_SIZE >> 8);     // CLASS = UDP payload size
		buf[w++] = (uint8_t)(EDNS_UDP_SIZE & 0xff);
		buf[w++] = 0x00; buf[w++] = 0x00;             // TTL: ext-rcode, version,
		buf[w++] = 0x00; buf[w++] = 0x00;             //      flags (DO=0) all zero
		const size_t rdlen = 4 + pad;
		buf[w++] = (uint8_t)(rdlen >> 8);             // RDLENGTH
		buf[w++] = (uint8_t)(rdlen & 0xff);
		buf[w++] = 0x00; buf[w++] = EDNS_OPT_PAD;     // Padding option code (12)
		buf[w++] = (uint8_t)(pad >> 8);               // Padding option length
		buf[w++] = (uint8_t)(pad & 0xff);
		memset(buf + w, 0, pad);
		const uint16_t new_ar = (uint16_t)(arcount + 1);
		buf[10] = (uint8_t)(new_ar >> 8);
		buf[11] = (uint8_t)(new_ar & 0xff);
	}

	return new_len;
}
