/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  DoT/DoH wire framing
*
*  Frames/deframes bytes only; DNS message contents are never parsed here. All
*  lengths are bounds-checked; no read or write ever crosses the caller-provided
*  buffer bounds.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "framing.h"

#include <string.h>
#include <stdio.h>

// DoT: write a 2-byte big-endian length prefix followed by msg into out.
// Returns len+2 on success, -1 on empty/oversized msg or insufficient out.
ssize_t dot_frame(const uint8_t *msg, size_t len, uint8_t *out, size_t out_sz)
{
	// DoT frames each message with a 2-octet big-endian length prefix - RFC
	// 7858 Sec. 3.3: messages "MUST use the two-octet length field
	// described in Section 4.2.2 of [RFC1035]". Refuse a length we cannot
	// represent or fit.
	if(len == 0 || len > DNS_MSG_MAX)
		return -1;
	if(out_sz < len + 2)
		return -1;
	out[0] = (uint8_t)((len >> 8) & 0xff);
	out[1] = (uint8_t)(len & 0xff);
	memcpy(out + 2, msg, len);
	return (ssize_t)(len + 2);
}

// DoT: inspect an accumulated receive buffer. Returns the DNS message length and
// sets *msg_off to the offset of the message body once a full length-prefixed
// message is present, 0 if more bytes are needed, -1 on a zero-length
// (protocol error) frame.
ssize_t dot_deframe(const uint8_t *buf, size_t buflen, size_t *msg_off)
{
	// We cannot know the message size until the 2-byte prefix has arrived.
	if(buflen < 2)
		return 0;
	const size_t l = ((size_t)buf[0] << 8) | (size_t)buf[1];
	if(l == 0)
		return -1; // a zero-length DNS message is a protocol error
	if(buflen < l + 2)
		return 0;  // the body has not fully arrived yet
	if(msg_off != NULL)
		*msg_off = 2;
	return (ssize_t)l;
}

// Reject control characters that could break out of an HTTP header.
static bool __attribute__((pure)) clean_header_value(const char *s)
{
	for(const char *p = s; *p != '\0'; p++)
	{
		const unsigned char c = (unsigned char)*p;
		// Reject controls, DEL and spaces: a space would also split the
		// HTTP request line ("POST /a b HTTP/1.1"), not just inject a
		// header.
		if(c < 0x20 || c == 0x7f || c == ' ')
			return false;
	}
	return true;
}

// DoH: build an HTTP/1.1 POST request carrying the DNS message. host and path
// must be free of control characters. Returns request length or -1.
ssize_t doh_build_request(const char *host, const char *path,
                          const uint8_t *msg, size_t len, uint8_t *out, size_t out_sz)
{
	if(host == NULL || path == NULL || msg == NULL)
		return -1;
	if(len == 0 || len > DNS_MSG_MAX)
		return -1;
	if(!clean_header_value(host) || !clean_header_value(path))
		return -1;

	// An IPv6 literal in the Host header must be bracketed (RFC 7230 Sec. 5.4);
	// a hostname never contains ':', so a colon reliably marks an IPv6 literal.
	char hostbuf[256];
	const char *hosthdr = host;
	if(strchr(host, ':') != NULL)
	{
		if((size_t)snprintf(hostbuf, sizeof(hostbuf), "[%s]", host) >= sizeof(hostbuf))
			return -1;
		hosthdr = hostbuf;
	}

	// RFC 8484: the DNS wire message is the POST body with media type
	// application/dns-message (Sec. 4.1 and Sec. 6).
	const int hlen = snprintf((char *)out, out_sz,
	                          "POST %s HTTP/1.1\r\n"
	                          "Host: %s\r\n"
	                          "Accept: application/dns-message\r\n"
	                          "Content-Type: application/dns-message\r\n"
	                          "Content-Length: %zu\r\n"
	                          "\r\n",
	                          path, hosthdr, len);
	if(hlen < 0 || (size_t)hlen >= out_sz)
		return -1;
	if((size_t)hlen + len > out_sz)
		return -1;
	memcpy(out + hlen, msg, len);
	return (ssize_t)((size_t)hlen + len);
}

// Case-insensitive search for needle (already lowercase) in hay[hn].
static const uint8_t *__attribute__((pure)) mem_findci(const uint8_t *hay, size_t hn, const char *needle)
{
	const size_t nn = strlen(needle);
	if(nn == 0 || nn > hn)
		return NULL;
	for(size_t i = 0; i + nn <= hn; i++)
	{
		size_t j = 0;
		for(; j < nn; j++)
		{
			unsigned char a = hay[i + j];
			if(a >= 'A' && a <= 'Z')
				a = (unsigned char)(a + 32);
			if(a != (unsigned char)needle[j])
				break;
		}
		if(j == nn)
			return hay + i;
	}
	return NULL;
}

// DoH: parse an accumulated HTTP/1.1 response. On a complete 200 response sets
// body_off and body_len to the DNS answer within buf and returns total bytes
// consumed; 0 if more bytes are needed; -1 on a non-200 status, a missing or
// oversized Content-Length, or a malformed/oversized header block.
ssize_t doh_parse_response(const uint8_t *buf, size_t buflen,
                           size_t *body_off, size_t *body_len)
{
	// Locate the end of the header block.
	const uint8_t *hdr_end = NULL;
	for(size_t i = 0; i + 4 <= buflen; i++)
		if(memcmp(buf + i, "\r\n\r\n", 4) == 0)
		{
			hdr_end = buf + i + 4;
			break;
		}
	if(hdr_end == NULL)
		return (buflen > DOH_HEADER_MAX) ? -1 : 0;

	const size_t hlen = (size_t)(hdr_end - buf);

	// A header block that only reaches the terminator past DOH_HEADER_MAX is
	// still oversized (the pre-terminator check above cannot catch this case).
	if(hlen > DOH_HEADER_MAX)
		return -1;

	// Require an HTTP/1.x status line, so a non-HTTP response is rejected
	// outright rather than misclassified (which could leave stray bytes in and
	// desync the pooled connection).
	if(hlen < 8 || memcmp(buf, "HTTP/1.", 7) != 0)
		return -1;

	// Status line must be exactly "HTTP/x.y 200 " - require the 3-digit code to
	// be followed by a space or CR so a malformed "2000" is rejected.
	const uint8_t *sp = memchr(buf, ' ', hlen);
	if(sp == NULL || sp + 5 > buf + hlen)
		return -1;
	if(!(sp[1] == '2' && sp[2] == '0' && sp[3] == '0' &&
	     (sp[4] == ' ' || sp[4] == '\r')))
		return -1;

	// Content-Length is required. Anchor the match to the start of a header
	// line (headers are always preceded by CRLF) so that a header such as
	// "X-Content-Length:" cannot be mistaken for it.
	const uint8_t *cl = mem_findci(buf, hlen, "\r\ncontent-length:");
	if(cl == NULL)
		return -1;
	// Reject a second Content-Length (RFC 7230 Sec. 3.3.3 message smuggling)
	// and any Transfer-Encoding: either lets the real body length differ from
	// the parsed one, leaving unconsumed bytes that desync the pooled
	// connection for the following queries.
	const size_t after_cl = (size_t)(cl + 2 - buf); // just past the leading CRLF
	if(mem_findci(buf + after_cl, hlen - after_cl, "\r\ncontent-length:") != NULL)
		return -1;
	if(mem_findci(buf, hlen, "\r\ntransfer-encoding:") != NULL)
		return -1;
	const uint8_t *v = cl + strlen("\r\ncontent-length:");
	while(v < buf + hlen && (*v == ' ' || *v == '\t'))
		v++;
	size_t content_len = 0;
	bool anydigit = false;
	while(v < buf + hlen && *v >= '0' && *v <= '9')
	{
		content_len = content_len * 10 + (size_t)(*v - '0');
		anydigit = true;
		if(content_len > DNS_MSG_MAX)
			return -1;
		v++;
	}
	// A DNS wire message cannot be empty, so Content-Length: 0 is a protocol
	// error (fail closed), not a valid zero-length answer.
	if(!anydigit || content_len == 0)
		return -1;
	// The value must be properly terminated: only optional whitespace and then
	// the end-of-line CR may follow. Rejecting trailing junk ("2x") prevents a
	// mismatched body length from desyncing the persistent connection.
	while(v < buf + hlen && (*v == ' ' || *v == '\t'))
		v++;
	if(v >= buf + hlen || *v != '\r')
		return -1;

	if(buflen < hlen + content_len)
		return 0; // need more body

	if(body_off != NULL)
		*body_off = hlen;
	if(body_len != NULL)
		*body_len = content_len;
	return (ssize_t)(hlen + content_len);
}
