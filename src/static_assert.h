/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Struct size assertion tool
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <assert.h>


#define STATIC_ASSERT(OBJECT, EXPECTED)   \
  static_assert(sizeof(OBJECT) == EXPECTED , "Expected size of " #OBJECT " is " #EXPECTED " on this architecture.");

// Check based on detected architecture
#if defined(__x86_64__) || defined(__aarch64__)
#define ASSERT_SIZEOF(OBJECT, SIZE64, SIZE32, SIZEARM) \
	STATIC_ASSERT(OBJECT, SIZE64)
#elif defined(__i386__)
#define ASSERT_SIZEOF(OBJECT, SIZE64, SIZE32, SIZEARM) \
	STATIC_ASSERT(OBJECT, SIZE32)
#elif defined(__arm__)
#define ASSERT_SIZEOF(OBJECT, SIZE64, SIZE32, SIZEARM) \
	STATIC_ASSERT(OBJECT, SIZEARM)
#endif