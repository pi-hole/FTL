
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  String suggestion routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "config/suggest.h"

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

// The Bitap algorithm (also known as the shift-or, shift-and or Baeza-Yates-
// Gonnet algorithm) is an approximate string matching algorithm. The algorithm
// tells whether a given text contains a substring which is "approximately equal"
// to a given pattern, where approximate equality is defined in terms of Levenshtein
// distance — if the substring and pattern are within a given distance k of each
// other, then the algorithm considers them equal. (Wikipedia)
//
// Bitap distinguishes itself from other well-known string searching algorithms in
// its natural mapping onto simple bitwise operations
//
// Notice that in this implementation, counterintuitively, each bit with value
// zero indicates a match, and each bit with value 1 indicates a non-match. The
// same algorithm can be written with the intuitive semantics for 0 and 1, but
// in that case we must introduce another instruction into the inner loop to set
// R |= 1. In this implementation, we take advantage of the fact that
// left-shifting a value shifts in zeros on the right, which is precisely the
// behavior we need.
//
// This implementation is based on https://en.wikipedia.org/wiki/Bitap_algorithm
static const char *bitap_fuzzy_bitwise_search(const char *text, const char *pattern, unsigned int k)
{
	const size_t m = strlen(pattern);
	const char *result = NULL;
	unsigned long pattern_mask[256];
	unsigned long *R;

	// Sanity checks
	if (pattern[0] == '\0')
		return text;
	if (m > 31)
		return "The pattern is too long!";

	// Initialize the bit array R
	// To perform fuzzy string searching using the bitap algorithm, it is
	// necessary to extend the bit array R into a second dimension. Instead
	// of having a single array R that changes over the length of the text,
	// we now have k distinct arrays R1..k. Array Ri holds a representation
	// of the prefixes of pattern that match any suffix of the current
	// string with i or fewer errors. In this context, an "error" may be an
	// insertion, deletion, or substitution; see Levenshtein distance for
	// more information on these operations.
	R = calloc(k + 1, sizeof(*R));
	for (unsigned int i = 0; i <= k; ++i)
		R[i] = ~1;

	// Initialize the pattern bitmasks
	for (unsigned int i = 0; i < sizeof(pattern_mask)/sizeof(*pattern_mask); ++i)
		pattern_mask[i] = ~0;
	for (unsigned int i = 0; i < m; ++i)
		pattern_mask[(unsigned char)pattern[i]] &= ~(1UL << i);

	// Iterate over all characters in the text
	for (unsigned int i = 0; text[i] != '\0'; ++i)
	{
		// Update the bit arrays
		// R[d] = (R[d] | pattern_mask[text[i]]) << 1;
		unsigned long old_Rd1 = R[0];
		R[0] |= pattern_mask[(unsigned char)text[i]];
		R[0] <<= 1;
		for (unsigned int d = 1; d <= k; ++d)
		{
			unsigned long tmp = R[d];
			// This algorithm only pays attention to substitutions,
			// not to insertions or deletions – in other words, a
			// Hamming distance of k.
			R[d] = (old_Rd1 & (R[d] | pattern_mask[(unsigned char)text[i]])) << 1;
			old_Rd1 = tmp;
		}

		// If the last bit of R[k] is 0, we found a match
		if (0 == (R[k] & (1UL << m)))
		{
			result = (text+i - m) + 1;
			break;
		}
	}

	// Free the memory we allocated
	free(R);

	// Return the result
	return result;
}

// Returns the the closest matching string using the Levenshtein distance
static const char *__attribute__((pure)) suggest_levenshtein(const char *strings[], size_t nstrings, const char *string)
{
	size_t mindist = 0;
	ssize_t minidx = -1;

	// Convert the string to lowercase
	// Skip the first 8 characters (i.e., "FTLCONF_")
	char *lower_string = strdup(string);
	const size_t m = strlen(lower_string);
	for(size_t i = 8; i < strlen(lower_string); ++i)
		lower_string[i] = tolower(lower_string[i]);

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
		size_t dist = levenshtein_distance(current, strlen(current), lower_string, m);

		// If the distance is smaller than the smallest minimum we found
		// so far, update the minimum and the index of the closest match
		if (mindist >= dist)
		{
			mindist = dist;
			minidx = i;
		}
	}

	// Free the memory we allocated
	free(lower_string);

	// Return NULL if no match was found (this can only happen if no
	// strings were given)
	if(minidx == -1)
		return NULL;

	// else: Return the closest match
	return strings[minidx];
}

// Returns the the closest matching string using fuzzy searching
static unsigned int __attribute__((pure)) suggest_bitap(const char *strings[], size_t nstrings, const char *string,
                                                        char **results, unsigned int num_results)
{
	// Convert the string to lowercase
	// Skip the first 8 characters (i.e., "FTLCONF_")
	char *lower_string = strdup(string);
	const size_t m = strlen(lower_string);
	for(size_t i = 8; i < strlen(lower_string); ++i)
		lower_string[i] = tolower(lower_string[i]);

	unsigned int found = 0;

	// Try to find a match with at most j errors
	for(unsigned int j = 0; j < m; j++)
	{
		// Iterate over all strings and try to find a match
		for(unsigned int i = 0; i < nstrings; ++i)
		{
			// Get the current string
			const char *current = strings[i];

			// Use the Bitap algorithm to find a match
			const char *result = bitap_fuzzy_bitwise_search(current, lower_string, j);

			// If we found a match, add it to the list of results
			if(result != NULL)
				results[found++] = (char*)result;

			// If we found enough matches, stop searching
			if(found >= num_results)
				break;
		}

		// If we found enough matches, stop searching
		if(found >= num_results)
			break;
	}

	// Free the memory we allocated
	free(lower_string);

	// Return the number of matches we found
	return found;
}

// Try to find up to two matches using the Bitap algorithm and one using the
// Levenshtein distance
#define MAX_MATCHES 3
char **__attribute__((pure)) suggest_closest(const char *strings[], size_t nstrings,
                                             const char *string, unsigned int *N)
{
	// Allocate memory for MAX_MATCHES matches
	char** matches = calloc(MAX_MATCHES, sizeof(char*));

	// Try to find (MAX_MATCHES - 1) matches using the Bitap algorithm
	*N = suggest_bitap(strings, nstrings, string, matches, MAX_MATCHES - 1);

	// Try to find a last match using the Levenshtein distance
	matches[(*N)++] = (char*)suggest_levenshtein(strings, nstrings, string);

	// Loop over matches and remove duplicates
	for(unsigned int i = 0; i < *N; ++i)
	{
		// Skip if there is no match here
		if(matches[i] == NULL)
			continue;

		// Loop over all matches after the current one
		for(unsigned int j = i + 1; j < *N; ++j)
		{
			// If the current match is a duplicate, set it to NULL
			if(matches[j] != NULL && strcmp(matches[i], matches[j]) == 0)
			{
				matches[j] = NULL;
			}
		}
	}

	// Return the list of matches
	return matches;
}
