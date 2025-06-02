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

import os
import sys
import trace
from libs.openAPI import openApi
from libs.FTLAPI import FTLAPI
from libs.responseVerifyer import ResponseVerifyer

TRACE = False

def main():
	# OpenAPI specs are split into multiple files, this script extracts the endpoints from them
	openapi = openApi(base_path = "src/api/docs/content/specs/", api_root = "/api", trace = TRACE)
	if not openapi.parse("main.yaml"):
		exit(1)

	# Get endpoints from FTL
	ftl = FTLAPI("http://127.0.0.1", "ABC")
	ftl.get_endpoints()

	errs = [0, 0, 0]
	print("Endpoints in OpenAPI specs but not in FTL:")
	# Check for endpoints in OpenAPI specs that are not defined in FTL
	for path in openapi.endpoints["get"]:
		if path not in ftl.endpoints["get"]:
			print("  Missing GET endpoint in FTL: " + path)
			errs[0] += 1
	if errs[0] == 0:
		print("  No missing endpoints\n")

	# Check for endpoints in FTL that are not in the OpenAPI specs
	print("Endpoints in FTL but not in OpenAPI specs:")
	for path in ftl.endpoints["get"]:
		if path not in openapi.endpoints["get"]:
			# Ignore the docs endpoint
			if path in ["/api/docs"]:
				continue
			print("  Missing GET endpoint in OpenAPI specs: " + path)
			errs[1] += 1
	if errs[1] == 0:
		print("  No missing endpoints\n")

	# Check if endpoints that are in both FTL and OpenAPI specs match
	# and have the same response format. Also verify that the examples
	# matches the OpenAPI specs.
	print("Verifying the individual OpenAPI endpoint properties...")
	teleporter = None
	for path in openapi.endpoints["get"]:
		# We do not check the action endpoints as they'd trigger
		# possibly unwanted action such as restarting FTL, running
		# gravity, stutting down the system, etc.
		if path.startswith("/api/action"):
			continue
		with ResponseVerifyer(ftl, openapi) as verifyer:
			errors = verifyer.verify_endpoint(path)
			if verifyer.teleporter_archive is not None:
				teleporter = verifyer.teleporter_archive
			if len(errors) == 0:
				print("  GET " + path + " (" + verifyer.auth_method + " auth): OK")
			else:
				print("  GET " + path + " (" + verifyer.auth_method + " auth):")
				for error in errors:
					print("  - " + error)
				errs[2] += len(errors)
	print("")

	# Verify that all the endpoint defined by /api/endpoints are documented
	# and that there are no undocumented endpoints
	print("Comparing all endpoints defined in FTL against the OpenAPI specs...")
	with ResponseVerifyer(ftl, openapi) as verifyer:
		errors, checked = verifyer.verify_endpoints()
		if len(errors) == 0:
			print("  OK (" + str(checked) + " endpoints checked)")
		else:
			print("  Errors (" + str(checked) + " endpoints checked):")
			for error in errors:
				print("  - " + error)
			errs[2] += len(errors)
	print("")

	# Verify FTL Teleporter import
	print("Verifying FTL Teleporter import...")
	with ResponseVerifyer(ftl, openapi) as verifyer:
		errors = verifyer.verify_teleporter_zip(teleporter)
		if len(errors) == 0:
			print("  POST /api/teleporter: OK")
		else:
			print("  Errors:")
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
		print("Found " + str(errs[2]) + " specs mismatches")

	# Exit with an error if there are missing endpoints
	if sum(errs) > 0:
		exit(1)

	# If there are no errors, exit with success
	print("Everything okay!")
	#exit(0)

if __name__ == "__main__":
	# Exit early when this is a RISCV build
	if os.getenv("CI_ARCH") == "linux/riscv64":
		print("Skipping API test on RISCV builds")
		exit(0)

	if TRACE:
		tracer = trace.Trace(ignoredirs=[sys.prefix, sys.exec_prefix],
				trace=1, count=1)
		tracer.run('main()')

		# make a report, placing output in the current directory
		r = tracer.results()
		print(r.write_results(show_missing=True, coverdir="."))

		# Exit with success
		exit(0)
	else:
		main()

		# Exit with success
		exit(0)
