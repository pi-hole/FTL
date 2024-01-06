/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  GZIP compression routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// le32toh and friends
#include <endian.h>
#include "gzip.h"
#include "log.h"

static int mz_uncompress2_raw(unsigned char *pDest, mz_ulong *pDest_len, const unsigned char *pSource, mz_ulong *pSource_len);

static bool deflate_buffer(const unsigned char *buffer_uncompressed, const mz_ulong size_uncompressed,
                           unsigned char **buffer_compressed, mz_ulong *size_compressed)
{
	// Allocate memory for compressed file
	// (compressBound() returns the maximum size of the compressed data)
	// We add some extra bytes to the buffer to make sure we have enough
	// space for the GZIP header and footer
	*size_compressed = compressBound(size_uncompressed) + 14;
	*buffer_compressed = malloc(*size_compressed);
	if(*buffer_compressed == NULL)
	{
		log_warn("Failed to allocate %lu bytes of memory", (unsigned long)*size_compressed);
		return false;
	}

	// Compress file (ZLIB stream format - not GZIP! - see https://tools.ietf.org/html/rfc1950)
	int ret = compress2(*buffer_compressed, size_compressed, buffer_uncompressed, size_uncompressed, Z_BEST_COMPRESSION);
	if(ret != Z_OK)
	{
		log_warn("Failed to compress: %s", zError(ret));
		return false;
	}


	// Isolate compressed data, strip ZLIB header (first two bytes) and
	// footer (last four bytes)
	// +=======================+
	// |...compressed blocks...| (more-->)
	// +=======================+
	memmove(*buffer_compressed, *buffer_compressed + 2, *size_compressed);
	*size_compressed -= (2 + 4);

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
	// 00000000: timestamp (set later). For simplicity, we set it to the
	// current time
	// 02: extra flags (maximum compression)
	// 03: operating system (Unix)
	unsigned char gzip_header[] = { 0x1F, 0x8B, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03 };
	// Write header
	memmove(*buffer_compressed + sizeof(gzip_header), *buffer_compressed, *size_compressed);
	memcpy(*buffer_compressed, gzip_header, sizeof(gzip_header));
	*size_compressed += sizeof(gzip_header);

	// Set timestamp
	uint32_t now = htole32(time(NULL));
	memcpy(*buffer_compressed + 4, &now, sizeof(now));

	// Add GZIP footer (CRC32 and uncompressed size)
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
	const uint32_t crc = mz_crc32(MZ_CRC32_INIT, buffer_uncompressed, size_uncompressed);
	memcpy(*buffer_compressed + *size_compressed, &crc, sizeof(crc));
	*size_compressed += sizeof(crc);
	const uint32_t isize = htole32(size_uncompressed);
	memcpy(*buffer_compressed + *size_compressed, &isize, sizeof(isize));
	*size_compressed += sizeof(isize);

	return true;
}

bool inflate_buffer(unsigned char *buffer_compressed, mz_ulong size_compressed,
                    unsigned char **buffer_uncompressed, mz_ulong *size_uncompressed)
{
	// Check GZIP header (magic byte 1F 8B and compression algorithm deflate 08)
	if(buffer_compressed[0] != 0x1F || buffer_compressed[1] != 0x8B)
	{
		log_warn("This is not a valid GZIP stream");
		return false;
	}

	// Check compression algorithm
	if(buffer_compressed[2] != 0x08)
	{
		log_warn("Compression algorithm not supported");
		return false;
	}

	// Check header flags
	if(buffer_compressed[3] & 0x02)
	{
		log_warn("Compression with extra fields not supported");
		return false;
	}

	// Skip extra field
	if(buffer_compressed[3] & 0x04)
	{
		// Skip extra field
		// +=======================+
		// |...compressed blocks...| (more-->)
		// +=======================+
		// |...extra field...|     |
		// +===================     |
		// |...compressed blocks...| (more-->)
		// +=======================+
		// |     CRC32     |     ISIZE     |
		// +---+---+---+---+---+---+---+---+
		//
		// Extra field: This contains extra information about the file.  The
		//              format of this information is described in section 2.3.1.
		//              (If this flag is set, the extra field length is stored in
		//              the two bytes immediately following the header.)
		//
		//   0   1   2   3   4   5   6   7
		// +---+---+---+---+---+---+---+---+
		// | XLEN  |...XLEN bytes of "extra field"...|
		// +---+---+---+---+---+---+---+---+
		//
		// XLEN: This contains the length of the extra field, in bytes.
		uint16_t xlen = 0u;
		for(unsigned int i = 0; i < 2; i++)
			xlen |= buffer_compressed[10 + i] << (i * 8);
		xlen = le16toh(xlen);
		if(size_compressed < 12u + xlen)
		{
			log_warn("Invalid GZIP header");
			return false;
		}

		// Move compressed data to the left
		memmove(buffer_compressed + 10, buffer_compressed + 12 + xlen, size_compressed - (12 + xlen));
		size_compressed -= 2 + xlen;
	}

	// Skip file name (if present)
	if(buffer_compressed[3] & 0x08)
	{
		//   0   1   2   3   4   5   6   7
		// +---+---+---+---+---+---+---+---+
		// +=======================+
		// |...compressed blocks...| (more-->)
		// +=======================+
		// |...file name...|       |
		// +===============        |
		// |...compressed blocks...| (more-->)
		// +=======================+
		// |     CRC32     |     ISIZE     |
		// +---+---+---+---+---+---+---+---+
		//
		// File name: This is a zero-terminated string containing a
		//               original file name. This string may be
		//               arbitrarily long. We ignore it.
		//
		size_t i = 10;
		while(i < size_compressed && buffer_compressed[i] != 0)
		{
			i++;
		}
		if(i == size_compressed)
		{
			log_warn("File name is missing or invalid in GZIP header");
			return false;
		}
		i++;

		// Move compressed blocks to the beginning of the in buffer
		memmove(buffer_compressed + 10, buffer_compressed + i, size_compressed - i);
		size_compressed -= i - 10;
	}

	// Skip file comment (if present)
	if(buffer_compressed[3] & 0x10)
	{
		//   0   1   2   3   4   5   6   7
		// +---+---+---+---+---+---+---+---+
		// +=======================+
		// |...compressed blocks...| (more-->)
		// +=======================+
		// |...file comment...|    |
		// +==================     |
		// |...compressed blocks...| (more-->)
		// +=======================+
		// |     CRC32     |     ISIZE     |
		// +---+---+---+---+---+---+---+---+
		//
		// File comment: This is a zero-terminated string containing a
		//               comment about the file. This string may be
		//               arbitrarily long. We ignore it.
		//
		size_t i = 10;
		while(i < size_compressed && buffer_compressed[i] != 0)
		{
			i++;
		}
		if(i == size_compressed)
		{
			log_warn("File comment is missing or invalid in GZIP header");
			return false;
		}
		i++;

		// Move compressed blocks to the beginning of the in
		memmove(buffer_compressed + 10, buffer_compressed + i, size_compressed - i);
		size_compressed -= i - 10;
	}

	// Get the size of the uncompressed file from the GZIP footer (last 4
	// bytes of the file)
	 *size_uncompressed = 0u;
	for(unsigned int i = 0; i < 4; i++)
		*size_uncompressed |= buffer_compressed[size_compressed - 4 + i] << (i * 8);
	*size_uncompressed = le32toh(*size_uncompressed);
	if(*size_uncompressed == 0 || *size_uncompressed > 0x10000000)
	{
		log_warn("File is empty or too large");
		return false;
	}

	// Move compressed blocks 10 bytes to the left to remove the GZIP header
	memmove(buffer_compressed, buffer_compressed + 10, size_compressed - 10);
	size_compressed -= 10;

	// Extract checksum (stored in the first 4 of the last 8 bytes of the
	// file)
	uint32_t crc = 0u;
	for(unsigned int i = 0; i < 4; i++)
		crc |= buffer_compressed[size_compressed - 8 + i] << (i * 8);
	crc = le32toh(crc);

	// ZLIB trailer/footer is an Adler-32 checksum of the uncompressed data.
	// We have to strip the uncompressed size from the GZIP footer.
	size_compressed -= 8;

	// Allocate memory for uncompressed file
	*buffer_uncompressed = malloc(*size_uncompressed);
	if(*buffer_uncompressed == NULL)
	{
		log_warn("Failed to allocate %lu bytes of memory", (unsigned long)*size_uncompressed);
		return false;
	}

	// Uncompress file (ZLIB stream format - not GZIP! - see
	// https://tools.ietf.org/html/rfc1950)
	int ret = mz_uncompress2_raw(*buffer_uncompressed, size_uncompressed, buffer_compressed, &size_compressed);
	if(ret != Z_OK)
	{
		log_warn("Failed to uncompress: %s", zError(ret));
		return false;
	}

	// Checksum verification
	if(crc != mz_crc32(MZ_CRC32_INIT, *buffer_uncompressed, *size_uncompressed))
	{
		log_warn("Checksum mismatch");
		return false;
	}

	return true;
}

bool inflate_file(const char *infilename, const char *outfilename, bool verbose)
{
	// Read entire file into memory
	FILE *infile = fopen(infilename, "rb");
	if(infile == NULL)
	{
		log_warn("Failed to open %s: %s", infilename, strerror(errno));
		return false;
	}

	// Create compressed file
	FILE *outfile = fopen(outfilename, "wb");
	if(outfile == NULL)
	{
		log_warn("Failed to open %s: %s", outfilename, strerror(errno));
		fclose(infile);
		return false;
	}

	// Get file size
	fseek(infile, 0, SEEK_END);
	const mz_ulong size_compressed = ftell(infile);
	fseek(infile, 0, SEEK_SET);

	// Read file into memory
	unsigned char *buffer_compressed = malloc(size_compressed);
	if(buffer_compressed == NULL)
	{
		log_warn("Failed to allocate %lu bytes of memory", (unsigned long)size_compressed);
		fclose(infile);
		fclose(outfile);
		return false;
	}
	if(fread(buffer_compressed, 1, size_compressed, infile) != size_compressed)
	{
		log_warn("Failed to read %lu bytes from %s", (unsigned long)size_compressed, infilename);
		fclose(infile);
		fclose(outfile);
		free(buffer_compressed);
		return false;
	}
	fclose(infile);

	unsigned char *buffer_uncompressed = NULL;
	mz_ulong size_uncompressed = 0;
	bool success = inflate_buffer(buffer_compressed, size_compressed,
	                              &buffer_uncompressed, &size_uncompressed);
	// Free memory
	free(buffer_compressed);

	// Check if uncompression was successful
	if(!success)
	{
		log_warn("Failed to uncompress %s", infilename);
		free(buffer_uncompressed);
		fclose(outfile);
		return false;
	}

	// Write uncompressed file to disk
	if(fwrite(buffer_uncompressed, sizeof(char), size_uncompressed, outfile) != size_uncompressed)
	{
		log_warn("Failed to write %lu bytes to %s", (unsigned long)size_uncompressed, outfilename);
		fclose(outfile);
		return false;
	}
	fclose(outfile);

	free(buffer_uncompressed);

	if(verbose)
	{
		// Print compression ratio
		double raw_size, comp_size;
		char raw_prefix[2], comp_prefix[2];
		format_memory_size(raw_prefix, size_compressed, &raw_size);
		format_memory_size(comp_prefix, size_uncompressed, &comp_size);
		log_info("Uncompressed %s (%.1f%sB) to %s (%.1f%sB), %.1f%% size increase",
		         infilename, raw_size, raw_prefix, outfilename, comp_size, comp_prefix,
		         100.0*size_uncompressed / size_compressed - 100.0);
	}

	return true;
}

bool deflate_file(const char *infilename, const char *outfilename, bool verbose)
{
	// Read entire file into memory
	FILE *infile = fopen(infilename, "rb");
	if(infile == NULL)
	{
		log_warn("Failed to open %s for reading: %s", infilename, strerror(errno));
		return false;
	}

	// Create compressed file
	FILE* outfile = fopen(outfilename, "wb");
	if(outfile == NULL)
	{
		log_warn("Failed to open %s for writing: %s", outfilename, strerror(errno));
		fclose(infile);
		return false;
	}

	// Get file size
	fseek(infile, 0, SEEK_END);
	const mz_ulong size_uncompressed = ftell(infile);
	fseek(infile, 0, SEEK_SET);

	// Read file into memory
	unsigned char *buffer_uncompressed = malloc(size_uncompressed);
	if(buffer_uncompressed == NULL)
	{
		log_warn("Failed to allocate %lu bytes of memory", (unsigned long)size_uncompressed);
		fclose(infile);
		fclose(outfile);
		return false;
	}
	if(fread(buffer_uncompressed, 1, size_uncompressed, infile) != size_uncompressed)
	{
		log_warn("Failed to read %lu bytes from %s", (unsigned long)size_uncompressed, infilename);
		fclose(infile);
		fclose(outfile);
		free(buffer_uncompressed);
		return false;
	}
	fclose(infile);

	unsigned char *buffer_compressed = NULL;
	mz_ulong size_compressed = 0;
	bool success = deflate_buffer(buffer_uncompressed, size_uncompressed,
	                              &buffer_compressed, &size_compressed);

	// Free memory
	free(buffer_uncompressed);

	// Check if compression was successful
	if(!success)
	{
		log_warn("Failed to compress %s", infilename);
		if(buffer_compressed)
			free(buffer_compressed);
		fclose(outfile);
		return false;
	}

	// Write compressed data to file
	if(fwrite(buffer_compressed, sizeof(char), size_compressed, outfile) != size_compressed)
	{
		log_warn("Failed to write %lu bytes to %s", (unsigned long)size_compressed, outfilename);
		fclose(outfile);
		free(buffer_compressed);
		return false;
	}
	fclose(outfile);

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
		format_memory_size(raw_prefix, size_uncompressed, &raw_size);
		format_memory_size(comp_prefix, csize, &comp_size);
		log_info("Compressed %s (%.1f%sB) to %s (%.1f%sB), %.1f%% size reduction",
		         infilename, raw_size, raw_prefix,
		         outfilename, comp_size, comp_prefix,
		         100.0 - 100.0*csize / size_uncompressed);
	}

	return true;
}

// mz_uncompress2_raw() is a copy of mz_uncompress2() from miniz.c with the
// exception of not checking the ZLIB header (first 2 bytes) and the ZLIB
// trailer (last 4 bytes). While we could reconstruct the ZLIB header from the
// GZIP header, the ZLIB trailer (Adler checksum!) is not available in the GZIP
// file so reconstructing it is not possible.
// We still check the GZIP checksum (CRC32) stored in the GZIP footer. So this
// is actually a GZIP uncompressor with a ZLIB uncompressor inside.
static int mz_uncompress2_raw(unsigned char *pDest, mz_ulong *pDest_len, const unsigned char *pSource, mz_ulong *pSource_len)
{
	mz_stream stream;
	int status;
	memset(&stream, 0, sizeof(stream));

	/* In case mz_ulong is 64-bits (argh I hate longs). */
#if defined __x86_64__
	if ((mz_uint64)(*pSource_len | *pDest_len) > 0xFFFFFFFFU)
		return MZ_PARAM_ERROR;
#endif
	stream.next_in = pSource;
	stream.avail_in = (mz_uint32)*pSource_len;
	stream.next_out = pDest;
	stream.avail_out = (mz_uint32)*pDest_len;

	/*** Window bits is passed < 0 to tell that there is no zlib header/footer ***/
	status = mz_inflateInit2(&stream, -MZ_DEFAULT_WINDOW_BITS);
	if (status != MZ_OK)
		return status;

	status = mz_inflate(&stream, MZ_FINISH);
	*pSource_len = *pSource_len - stream.avail_in;
	if (status != MZ_STREAM_END)
	{
		mz_inflateEnd(&stream);
		return ((status == MZ_BUF_ERROR) && (!stream.avail_in)) ? MZ_DATA_ERROR : status;
	}
	*pDest_len = stream.total_out;

	return mz_inflateEnd(&stream);
}
