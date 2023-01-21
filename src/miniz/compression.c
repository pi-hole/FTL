/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Compression routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "miniz.h"
#include "compression.h"
#include "log.h"

bool compress_file(const char *infile, const char *outfile, bool verbose)
{
	// Read entire file into memory
	FILE *fp = fopen(infile, "rb");
	if(fp == NULL)
	{
		log_warn("Failed to open %s: %s (%d)", infile, strerror(errno), errno);
		return false;
	}

	// Get file size
	fseek(fp, 0, SEEK_END);
	const mz_ulong size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	// Read file into memory
	unsigned char *buffer = malloc(size);
	if(buffer == NULL)
	{
		log_warn("Failed to allocate %lu bytes of memory", (unsigned long)size);
		fclose(fp);
		return false;
	}
	if(fread(buffer, 1, size, fp) != size)
	{
		log_warn("Failed to read %lu bytes from %s", (unsigned long)size, infile);
		fclose(fp);
		free(buffer);
		return false;
	}
	fclose(fp);

	// Allocate memory for compressed file
	// (compressBound() returns the maximum size of the compressed data)
	mz_ulong size_compressed = compressBound(size);
	unsigned char *buffer_compressed = malloc(size_compressed);
	if(buffer_compressed == NULL)
	{
		log_warn("Failed to allocate %lu bytes of memory", (unsigned long)size_compressed);
		free(buffer);
		return false;
	}

	// Compress file (ZLIB stream format - not GZIP! - see https://tools.ietf.org/html/rfc1950)
	int ret = compress2(buffer_compressed, &size_compressed, buffer, size, Z_BEST_COMPRESSION);
	if(ret != Z_OK)
	{
		log_warn("Failed to compress %s: %s (%d)", infile, zError(ret), ret);
		free(buffer);
		free(buffer_compressed);
		return false;
	}

	// Create compressed file
	fp = fopen(outfile, "wb");
	if(fp == NULL)
	{
		log_warn("Failed to open %s: %s (%d)", outfile, strerror(errno), errno);
		free(buffer);
		free(buffer_compressed);
		return false;
	}

	// Generate GZIP header (without timestamp and extra flags)
	// (see https://tools.ietf.org/html/rfc1952#section-2.3)
	//
	//   0   1   2   3   4   5   6   7   8   9
	// +---+---+---+---+---+---+---+---+---+---+
	// |ID1|ID2|CM |FLG|     MTIME     |XFL|OS | (more-->)
	// +---+---+---+---+---+---+---+---+---+---+
	//
	// 1F8B: magic number
	// 08: compression method (deflate)
	// 01: flags (FTEXT is set)
	// 00000000: timestamp (set later). For simplicity, we set it to the current time
	// 02: extra flags (maximum compression)
	// 03: operating system (Unix)
	const unsigned char gzip_header[] = { 0x1F, 0x8B, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03 };
	// Set timestamp
	uint32_t now = htole32(time(NULL));
	memcpy((void*)(gzip_header+4), &now, sizeof(now));
	// Write header
	if(fwrite(gzip_header, 1, sizeof(gzip_header), fp) != sizeof(gzip_header))
	{
		log_warn("Failed to write GZIP header to %s", outfile);
		fclose(fp);
		free(buffer);
		free(buffer_compressed);
		return false;
	}

	// Write compressed data, strip ZLIB header (first two bytes) and footer (last four bytes)
	// +=======================+
	// |...compressed blocks...| (more-->)
	// +=======================+
	if(fwrite(buffer_compressed + 2, 1, size_compressed - (2 + 4), fp) != size_compressed - (2 + 4))
	{
		log_warn("Failed to write %lu bytes to %s", (unsigned long)size_compressed, outfile);
		fclose(fp);
		free(buffer);
		free(buffer_compressed);
		return false;
	}

	// Write GZIP footer (CRC32 and uncompressed size)
	// (see https://tools.ietf.org/html/rfc1952#section-2.3)
	//
	//   0   1   2   3   4   5   6   7
	// +---+---+---+---+---+---+---+---+
	// |     CRC32     |     ISIZE     |
	// +---+---+---+---+---+---+---+---+
	//
	// CRC32: This contains a Cyclic Redundancy Check value of the
	//        uncompressed data computed according to CRC-32 algorithm used in
	//        the ISO 3309 standard and in section 8.1.1.6.2 of ITU-T
	//        recommendation V.42.  (See http://www.iso.ch for ordering ISO
	//        documents. See gopher://info.itu.ch for an online version of
	//        ITU-T V.42.)
	// isize: This contains the size of the original (uncompressed) input
	//        data modulo 2^32 (little endian).
	uint32_t crc = mz_crc32(MZ_CRC32_INIT, buffer, size);
	uint32_t isize = htole32(size);
	free(buffer);
	if(fwrite(&crc, 1, sizeof(crc), fp) != sizeof(crc))
	{
		log_warn("Failed to write CRC32 to %s", outfile);
		fclose(fp);
		free(buffer_compressed);
		return false;
	}
	if(fwrite(&isize, 1, sizeof(isize), fp) != sizeof(isize))
	{
		log_warn("Failed to write isize to %s", outfile);
		fclose(fp);
		free(buffer_compressed);
		return false;
	}

	fclose(fp);
	free(buffer_compressed);

	if(verbose)
	{
		// Print compression ratio
		// Compressed size = size of compressed data
		//                 + 10 bytes for GZIP header
		//                 + 8 bytes for GZIP footer
		const size_t csize = size_compressed - (2 + 4) + 10 + 8;
		double raw_size, comp_size;
		char raw_prefix[2], comp_prefix[2];
		format_memory_size(raw_prefix, size, &raw_size);
		format_memory_size(comp_prefix, csize, &comp_size);
		log_info("Compressed %s (%.1f%sB) to %s (%.1f%sB), %.1f%% size reduction",
		         infile, raw_size, raw_prefix, outfile, comp_size, comp_prefix,
		         100.0 - 100.0*csize / size);
	}

	return true;
}
