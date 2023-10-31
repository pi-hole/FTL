
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Levenshtein distance routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "config/levenshtein.h"

// Returns the minimum of three size_t values
static size_t min3(size_t x, size_t y, size_t z)
{
	const size_t tmp = x < y ? x : y;
	return tmp < z ? tmp : z;
}

// Simply swaps two size_t pointers in memory
static void swap(size_t **a, size_t **b)
{
	size_t *tmp = *a;
	*a = *b;
	*b = tmp;
}

// The Levenshtein distance is a string metric for measuring the difference
// between two sequences. Informally, the Levenshtein distance between two words
// is the minimum number of single-character edits (insertions, deletions or
// substitutions) required to change one word into the other. It is named after
// the Soviet mathematician Vladimir Levenshtein, who considered this distance
// in 1965. (Wikipedia)
//
// For example, the Levenshtein distance between "kitten" and "sitting" is 3,
// since the following 3 edits change one into the other, and there is no way to
// do it with fewer than 3 edits:
//    kitten -> sitten (substitution of "s" for "k"),
//    sitten -> sittin (substitution of "i" for "e"),
//    sittin -> sitting (insertion of "g" at the end).
//
// Our implementation follows the algorithm described in Wikipedia but was
// inspired by https://stackoverflow.com/a/71810739/2087442
static size_t levenshtein_distance(const char *s1, const size_t len1, const char *s2, const size_t len2)
{
	// Allocate two vectors of size len2 + 1
	size_t *v0 = calloc(len2 + 1, sizeof(size_t));
	size_t *v1 = calloc(len2 + 1, sizeof(size_t));

	// Initialize v0
	// v0[i] = the Levenshtein distance between s1[0..i] and the empty string
	// v0[i] = i
	for (size_t j = 0; j <= len2; ++j)
		v0[j] = j;

	// Calculate v1
	// v1[i] = the Levenshtein distance between s1[0..i] and s2[0..j]
	// v1[i] = min(v0[j] + 1, v1[j - 1] + 1, v0[j - 1] + (s1[i] == s2[j] ? 0 : 1))
	for (size_t i = 0; i < len1; ++i)
	{
		// Initialize v1
		v1[0] = i + 1;

		// Loop over remaining columns
		for (size_t j = 0; j < len2; ++j)
		{
			// Calculate deletion, insertion and substitution costs
			const size_t delcost = v0[j + 1] + 1;
			const size_t inscost = v1[j] + 1;
			const size_t subcost = s1[i] == s2[j] ? v0[j] : v0[j] + 1;

			// Take the minimum of the three costs (see above)
			v1[j + 1] = min3(delcost, inscost, subcost);
		}

		// Swap addresses to avoid copying data around
		swap(&v0, &v1);
	}

	// Return the Levenshtein distance between s1 and s2
	size_t dist = v0[len2];
	free(v0);
	free(v1);
	return dist;
}

// Returns the the closest matching string
const char *__attribute__((pure)) suggest_closest(const char *strings[], size_t nstrings, const char *string)
{
	size_t mindist = 0;
	ssize_t minidx = -1;

	// The Levenshtein distance is at most the length of the longer string
	for(size_t i = 0; i < nstrings; ++i)
	{
		const size_t len = strlen(strings[i]);
		if(len > mindist)
			mindist = len;
	}

	// Loop over all strings and find the closest match
	for (size_t i = 0; i < nstrings; ++i)
	{
		// Calculate the Levenshtein distance between the current string
		// (out of nstrings) and the string we are checking against
		const char *current = strings[i];
		size_t dist = levenshtein_distance(current, strlen(current), string, strlen(string));

		// If the distance is smaller than the smallest minimum we found
		// so far, update the minimum and the index of the closest match
		if (mindist >= dist)
		{
			mindist = dist;
			minidx = i;
		}
	}

	// Return "---" if no match was found (this can only happen if no
	// strings were given)
	if(minidx == -1)
		return "---";

	// else: Return the closest match
	return strings[minidx];
}