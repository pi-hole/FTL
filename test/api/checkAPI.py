#!/bin/python3
# Pi-hole: A black hole for Internet advertisements
# (c) 2023 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine - auxiliary files
# API test script
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

from libs.openAPI import openApi
from libs.FTLAPI import FTLAPI
from libs.responseVerifyer import ResponseVerifyer

if __name__ == "__main__":
	# OpenAPI specs are split into multiple files, this script extracts the endpoints from them
	openapi = openApi(base_path = "src/api/docs/content/specs/", api_root = "/api")
	if not openapi.parse("main.yaml"):
		exit(1)

	# Get endpoints from FTL
	ftl = FTLAPI("http://127.0.0.1:8080")
	ftl.get_endpoints()

	errs = [0, 0, 0]
	print("Endpoints in OpenAPI specs but not in FTL:")
	# Check for endpoints in OpenAPI specs that are not defined in FTL
	for path in openapi.endpoints["get"]:
		if path not in ftl.endpoints:
			print("  Missing GET endpoint in FTL: " + path)
			errs[0] += 1
	if errs[0] == 0:
		print("  No missing endpoints\n")

	# Check for endpoints in FTL that are not in the OpenAPI specs
	print("Endpoints in FTL but not in OpenAPI specs:")
	for path in ftl.endpoints:
		if path not in openapi.endpoints["get"]:
			# Ignore the docs endpoint
			if path in ["/api/docs"]:
				continue
			print("  Missing GET endpoint in OpenAPI specs: " + path)
			errs[1] += 1
	if errs[1] == 0:
		print("  No missing endpoints\n")

	print("Verifying endpoints...")
	for path in openapi.endpoints["get"]:
		verifyer = ResponseVerifyer(ftl, openapi)
		errors = verifyer.verify_endpoint(path)
		if len(errors) == 0:
			print("  " + path + ": OK")
		else:
			print("  " + path + ":")
			for error in errors:
				print("  - " + error)
			errs[2] += len(errors)
	print("")

	# Print the number error (if any)
	if errs[0] > 0:
		print("Found " + str(errs[0]) + " non-implemented endpoints")
	if errs[1] > 0:
		print("Found " + str(errs[1]) + " undocumented endpoints")
	if errs[2] > 0:
		print("Found " + str(errs[2]) + " endpoints not matching specs")

	# Exit with an error if there are missing endpoints
	if sum(errs) > 0:
		exit(1)

	# If there are no missing endpoints, exit with success
	print("No missing endpoints")
	exit(0)
