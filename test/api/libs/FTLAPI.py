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

import urllib.request
from typing import List
import json

# Class to query the FTL API
class FTLAPI():
	def __init__(self, api_url: str):
		self.api_url = api_url
		self.endpoints = []
		self.errors = []

	# Query the FTL API and return the response
	def getFTLresponse(self, uri: str, params: List[str] = []):
		self.errors = []
		try:
			if len(params) > 0:
				uri = uri + "?" + "&".join(params)
			with urllib.request.urlopen(self.api_url + uri) as url:
				return json.load(url)
		except Exception as e:
			self.errors.append("Exception when querying endpoints from FTL: " + str(e))
			return None

	# Query the endpoints from FTL for comparison with the OpenAPI specs
	def get_endpoints(self):
		try:
			# Get all endpoints from FTL and sort them for comparison
			for endpoint in self.getFTLresponse("/api/ftl/endpoints")["endpoints"]:
				self.endpoints.append(endpoint["uri"] + endpoint["parameters"])
			self.endpoints = sorted(self.endpoints)
		except Exception as e:
			print("Exception when pre-processing endpoints from FTL: " + str(e))
			exit(1)

		return self.endpoints