/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  General API commands
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"

bool matchesRegex(char *regex_expression, char *input) {
	regex_t regex;
	int result;

	result = regcomp(&regex, regex_expression, REG_EXTENDED);

	if(result != 0) {
		logg("Failed to compile regex");
		exit(EXIT_FAILURE);
	}

	result = regexec(&regex, input, 0, NULL, 0);
	regfree(&regex);

	return result == 0;
}

bool isValidDomain(char *domain) {
	char *valid_chars_regex = "^((-|_)*[a-z0-9]((-|_)*[a-z0-9])*(-|_)*)(\\.(-|_)*([a-z0-9]((-|_)*[a-z0-9])*))*$";
	char *total_length_regex = "^.{1,253}$";
	char *label_length_regex = "^[^\\.]{1,63}(\\.[^\\.]{1,63})*$";

	return matchesRegex(valid_chars_regex, domain) &&
			matchesRegex(total_length_regex, domain) &&
			matchesRegex(label_length_regex, domain);
}
