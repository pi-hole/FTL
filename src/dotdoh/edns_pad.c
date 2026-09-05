/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  EDNS(0) padding (RFC 7830 / RFC 8467)
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "edns_pad.h"

#include <stdbool.h>
#include <string.h>

// RFC 8467 Sec. 4.1: a client pads a query to a multiple of 128 octets; a server
// pads a response to a multiple of 468 octets.
#define EDNS_PAD_QUERY_BLOCK    128
#define EDNS_PAD_RESPONSE_BLOCK 468
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

// Locate the (single) OPT resource record in a DNS message. On success sets
// *rdlen_off / *rdata_off / *rdlen to the OPT's RDLENGTH offset, RDATA offset and
// RDLENGTH, and *is_last to whether the OPT's RDATA ends exactly at the message
// tail (so a caller may append to it). Returns:
//    1  an OPT RR was found and the message parsed cleanly to its end,
//    0  no OPT RR (message parsed cleanly),
//   -1  the message is malformed (fail-open for the caller).
// A second OPT, a ragged option list, or trailing bytes are all malformed.
static int find_opt(const uint8_t *buf, size_t len, size_t *rdlen_off,
                    size_t *rdata_off, size_t *rdlen, bool *is_last)
{
	if(len < 12)
		return -1;
	const uint16_t qdcount = (uint16_t)((buf[4] << 8) | buf[5]);
	const uint16_t ancount = (uint16_t)((buf[6] << 8) | buf[7]);
	const uint16_t nscount = (uint16_t)((buf[8] << 8) | buf[9]);
	const uint16_t arcount = (uint16_t)((buf[10] << 8) | buf[11]);

	size_t pos = 12;

	// Question section: a name followed by QTYPE and QCLASS.
	for(uint16_t i = 0; i < qdcount; i++)
	{
		if(!skip_name(buf, len, &pos))
			return -1;
		if(pos + 4 > len)
			return -1;
		pos += 4;
	}

	bool found = false;
	const unsigned long total_rr = (unsigned long)ancount + nscount + arcount;
	for(unsigned long i = 0; i < total_rr; i++)
	{
		if(!skip_name(buf, len, &pos))
			return -1;
		if(pos + 10 > len) // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
			return -1;
		const uint16_t type = (uint16_t)((buf[pos] << 8) | buf[pos + 1]);
		const size_t r_off = pos + 8;
		const size_t r_len = (size_t)((buf[r_off] << 8) | buf[r_off + 1]);
		const size_t d_off = pos + 10;
		if(d_off + r_len > len)
			return -1;

		if(type == DNS_TYPE_OPT)
		{
			if(found) // a second OPT is malformed
				return -1;
			found = true;
			*rdlen_off = r_off;
			*rdata_off = d_off;
			*rdlen = r_len;

			// The option list must tile the RDATA exactly.
			size_t o = d_off;
			while(o + 4 <= d_off + r_len)
				o += 4 + (size_t)((buf[o + 2] << 8) | buf[o + 3]);
			if(o != d_off + r_len)
				return -1;
		}

		pos = d_off + r_len;
	}

	// A clean parse consumes the whole message; trailing bytes mean malformed.
	if(pos != len)
		return -1;

	if(found)
		*is_last = (*rdata_off + *rdlen == len);
	return found ? 1 : 0;
}

// Does the OPT RR of msg carry an option with the given code? Fail-safe: returns
// false on any malformed input.
bool __attribute__((pure)) edns_has_option(const uint8_t *msg, size_t len, uint16_t code)
{
	size_t rdlen_off = 0, rdata_off = 0, rdlen = 0;
	bool is_last = false;
	if(find_opt(msg, len, &rdlen_off, &rdata_off, &rdlen, &is_last) != 1)
		return false;
	for(size_t o = rdata_off; o + 4 <= rdata_off + rdlen;
	    o += 4 + (size_t)((msg[o + 2] << 8) | msg[o + 3]))
		if(((msg[o] << 8) | msg[o + 1]) == code)
			return true;
	return false;
}

// Used to decide whether a response may be padded (RFC 8467 Sec. 4: a server pads
// only when the request did).
bool __attribute__((pure)) edns_has_padding_option(const uint8_t *msg, size_t len)
{
	return edns_has_option(msg, len, EDNS_OPT_PAD);
}

size_t edns_remove_option(uint8_t *buf, size_t len, uint16_t code)
{
	size_t rdlen_off = 0, rdata_off = 0, rdlen = 0;
	bool is_last = false;
	if(find_opt(buf, len, &rdlen_off, &rdata_off, &rdlen, &is_last) != 1)
		return len; // no OPT or malformed -> nothing to do (fail-open)

	// Locate the option to drop and, in the same pass, a Padding option that ends
	// the RDATA - only a trailing one can absorb the freed bytes in place.
	const size_t rdata_end = rdata_off + rdlen;
	size_t opt_off = 0, opt_total = 0, pad_len_off = 0;
	for(size_t o = rdata_off; o + 4 <= rdata_end;
	    o += 4 + (size_t)((buf[o + 2] << 8) | buf[o + 3]))
	{
		const uint16_t c = (uint16_t)((buf[o] << 8) | buf[o + 1]);
		const size_t total = 4 + (size_t)((buf[o + 2] << 8) | buf[o + 3]);
		if(c == code && opt_total == 0)
		{
			opt_off = o;
			opt_total = total;
		}
		else if(c == EDNS_OPT_PAD && o + total == rdata_end)
			pad_len_off = o + 2;
	}
	if(opt_total == 0)
		return len; // not present

	// Absorb the freed bytes into a trailing Padding option rather than shrinking
	// the message: the query was padded to a block boundary before it reached us
	// (RFC 8467) and should stay there. Both the OPT RR and the Padding option
	// must end the message for the freed bytes to land inside that padding.
	const size_t padlen = pad_len_off > 0
	                    ? (size_t)((buf[pad_len_off] << 8) | buf[pad_len_off + 1]) : 0;
	const bool absorb = pad_len_off > 0 && is_last && pad_len_off > opt_off &&
	                    padlen + opt_total <= 0xffff;

	// Drop the option's bytes from the RDATA.
	memmove(buf + opt_off, buf + opt_off + opt_total, len - (opt_off + opt_total));

	if(absorb)
	{
		// The padding option moved down by what we removed; its data now ends
		// opt_total bytes short of the message, so zero-fill that tail (RFC 7830
		// padding octets MUST be zero) and grow its length by the same amount.
		// RDLENGTH and the total message length are unchanged.
		const size_t moved = pad_len_off - opt_total;
		memset(buf + len - opt_total, 0, opt_total);
		buf[moved] = (uint8_t)((padlen + opt_total) >> 8);
		buf[moved + 1] = (uint8_t)((padlen + opt_total) & 0xff);
		return len;
	}

	// Nothing to absorb into: shrink the OPT RDLENGTH by what we removed.
	const size_t new_rdlen = rdlen - opt_total;
	buf[rdlen_off] = (uint8_t)(new_rdlen >> 8);
	buf[rdlen_off + 1] = (uint8_t)(new_rdlen & 0xff);
	return len - opt_total;
}

// Core padding: round the message up to the next `block` boundary by appending a
// Padding option. `create_opt` allows synthesising a fresh OPT RR when none is
// present (queries); a response must not fabricate one, so it passes false and is
// left unchanged when it has no OPT. Idempotent (a message that already carries a
// Padding option is returned unchanged) and fail-open (any malformed or
// would-not-fit case returns len unchanged).
static size_t edns_pad_msg(uint8_t *buf, size_t len, size_t bufsz, size_t block,
                           bool create_opt, bool set_do)
{
	size_t opt_rdlen_off = 0, opt_rdata_off = 0, opt_rdlen = 0;
	bool is_last = false;
	const int r = find_opt(buf, len, &opt_rdlen_off, &opt_rdata_off, &opt_rdlen, &is_last);
	if(r < 0)
		return len; // malformed -> send unchanged

	const bool found_opt = (r == 1);

	if(found_opt)
	{
		// Already padded? Leave untouched (idempotent).
		for(size_t o = opt_rdata_off; o + 4 <= opt_rdata_off + opt_rdlen;
		    o += 4 + (size_t)((buf[o + 2] << 8) | buf[o + 3]))
			if(((buf[o] << 8) | buf[o + 1]) == EDNS_OPT_PAD)
				return len;
		if(!is_last)
			return len; // OPT is not the last RR -> cannot append at the tail
	}
	else if(!create_opt)
	{
		// Response with no OPT: do not fabricate one (would carry a bogus DO=0 /
		// neutral UDP size onto an answer). Send unchanged.
		return len;
	}

	// Fixed overhead added before the pad octets: the 4-byte Padding option
	// header, plus an 11-byte OPT RR when the message has no OPT record yet.
	const size_t overhead = found_opt ? 4 : (11 + 4);

	// Round the message up to the next block boundary. The pad count is always
	// < block, so it fits an option length comfortably.
	const size_t provisional = len + overhead;
	const size_t new_len = ((provisional + block - 1) / block) * block;
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
		const uint16_t arcount = (uint16_t)((buf[10] << 8) | buf[11]);
		size_t w = len;
		buf[w++] = 0x00;                              // root name
		buf[w++] = 0x00; buf[w++] = DNS_TYPE_OPT;     // TYPE = OPT (41)
		buf[w++] = (uint8_t)(EDNS_UDP_SIZE >> 8);     // CLASS = UDP payload size
		buf[w++] = (uint8_t)(EDNS_UDP_SIZE & 0xff);
		// TTL: extended RCODE and version stay 0; the DO bit is copied from the
		// query, which RFC 3225 Sec. 3 requires of a response.
		buf[w++] = 0x00; buf[w++] = 0x00;
		buf[w++] = set_do ? 0x80 : 0x00; buf[w++] = 0x00;
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

// Whether the message carries an OPT RR, and if so whether its DO bit is set.
// Lets a synthesised reply mirror the query's EDNS-ness, which "does it pad"
// cannot answer.
bool edns_query_opt(const uint8_t *buf, size_t len, bool *do_bit)
{
	size_t rdlen_off = 0, rdata_off = 0, rdlen = 0;
	bool is_last = false;
	if(find_opt(buf, len, &rdlen_off, &rdata_off, &rdlen, &is_last) != 1)
		return false;
	// TTL sits 4 bytes ahead of RDLENGTH: ext-rcode, version, then the flags
	// whose top bit is DO.
	if(do_bit != NULL)
		*do_bit = rdlen_off >= 2 && (buf[rdlen_off - 2] & 0x80) != 0;
	return true;
}

size_t edns_pad_query(uint8_t *buf, size_t len, size_t bufsz)
{
	return edns_pad_msg(buf, len, bufsz, EDNS_PAD_QUERY_BLOCK, true, false);
}

// Pad a response we synthesised ourselves, which carries no OPT of its own.
// Fabricating one is right here and wrong for a forwarded answer: we only ever
// call this when the query carried an OPT, and RFC 6891
// Sec. 6.1.1 has an EDNS-aware responder answer such a query with an OPT.
size_t edns_pad_response_synth(uint8_t *buf, size_t len, size_t bufsz, bool set_do,
                               bool pad)
{
	if(pad)
		return edns_pad_msg(buf, len, bufsz, EDNS_PAD_RESPONSE_BLOCK, true, set_do);

	// The query was EDNS but did not pad: it still needs an OPT in the reply
	// (RFC 6891 Sec. 6.1.1), just an empty one.
	if(len + 11 > bufsz)
		return len;
	const uint16_t arcount = (uint16_t)((buf[10] << 8) | buf[11]);
	size_t w = len;
	buf[w++] = 0x00;                              // root name
	buf[w++] = 0x00; buf[w++] = DNS_TYPE_OPT;     // TYPE = OPT (41)
	buf[w++] = (uint8_t)(EDNS_UDP_SIZE >> 8);     // CLASS = payload size
	buf[w++] = (uint8_t)(EDNS_UDP_SIZE & 0xff);
	buf[w++] = 0x00; buf[w++] = 0x00;             // TTL: ext-rcode, version
	buf[w++] = set_do ? 0x80 : 0x00; buf[w++] = 0x00; // flags: DO from the query
	buf[w++] = 0x00; buf[w++] = 0x00;             // RDLENGTH = 0
	buf[10] = (uint8_t)((arcount + 1) >> 8);
	buf[11] = (uint8_t)((arcount + 1) & 0xff);
	return w;
}

size_t edns_pad_response(uint8_t *buf, size_t len, size_t bufsz)
{
	return edns_pad_msg(buf, len, bufsz, EDNS_PAD_RESPONSE_BLOCK, false, false);
}
