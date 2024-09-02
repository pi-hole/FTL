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

from enum import Enum
import random
import requests
from typing import List
import json
from hashlib import sha256
import urllib.parse

url = "http://pi.hole/api/auth"

class AuthenticationMethods(Enum):
	RANDOM = 0
	HEADER = 1
	BODY = 2
	COOKIE = 3
	QUERY_STR = 4

# Class to query the FTL API
class FTLAPI():

	auth_method = "?"

	def __init__(self, api_url: str, password: str = None):
		self.api_url = api_url
		self.endpoints = {
			"get": [],
			"post": [],
			"put": [],
			"patch": [],
			"delete": []
		}
		self.errors = []
		self.session = None
		self.verbose = False

		# Login to FTL API
		if password is not None:
			self.login(password)
			if self.session is None or 'valid' not in self.session or not self.session['valid']:
				raise Exception("Could not login to FTL API")

	def login(self, password: str = None):
		# Check if we even need to login
		response = self.GET("/api/auth")

		# Check if we are already logged in or authentication is not
		# required
		if response is None:
			raise Exception("No response from FTL API")
		if 'session' not in response:
			raise Exception("FTL returned invalid challenge item")
		if 'session' in response and response['session']['valid'] == True:
			self.session = response["session"]
			print(response)
			if password is not None:
				raise Exception("Password provided but API does not require authentication")
			return

		response = self.POST("/api/auth", {"password": password})
		if "error" in response:
			raise Exception("FTL returned error: " + json.dumps(response["error"]))
		if 'session' not in response:
			raise Exception("FTL returned invalid response item")
		self.session = response["session"]


	def get_jsondata_headers_cookies(self, authenticate: AuthenticationMethods):
		# Add session ID to the request (if any)
		json_data = None
		headers = None
		cookies = None
		if self.session is not None and 'sid' in self.session:
			# Pick a random authentication method if requested
			# Try again if the method comes out as random again
			while authenticate == AuthenticationMethods.RANDOM:
				authenticate = random.choice(list(AuthenticationMethods))

			# Add the session ID to the request
			if authenticate == AuthenticationMethods.HEADER:
				headers = {"X-FTL-SID": self.session['sid']}
			elif authenticate == AuthenticationMethods.BODY:
				json_data = {"sid": self.session['sid'] }
			elif authenticate == AuthenticationMethods.COOKIE:
				# Cookie authentication needs both the session ID and the CSRF header
				cookies = {"sid": self.session['sid'] }
				headers = { "X-CSRF-Token": self.session['csrf'] }

			self.auth_method = authenticate.name

		return json_data, headers, cookies


	# Query the FTL API (GET) and return the response
	def GET(self, uri: str, params: List[str] = [], expected_mimetype: str = "application/json", authenticate: AuthenticationMethods = AuthenticationMethods.BODY):
		self.errors = []
		try:
			# Get json_data, headers and cookies
			json_data, headers, cookies = self.get_jsondata_headers_cookies(authenticate)

			# Add session ID to the request if authenticating via query string
			if self.auth_method == AuthenticationMethods.QUERY_STR.name:
				encoded_sid = urllib.parse.quote(self.session['sid'], safe='')
				params.append("sid=" + encoded_sid)

			# Add parameters to the URI (if any)
			if len(params) > 0:
				uri = uri + "?" + "&".join(params)

			if self.verbose:
				print("GET " + self.api_url + uri + " with json_data: " + json.dumps(json_data))

			# Query the API
			with requests.get(url = self.api_url + uri, json = json_data, headers=headers, cookies=cookies) as response:
				if self.verbose:
					print(json.dumps(response.json(), indent=4))
				if expected_mimetype == "application/json":
					return response.json()
				else:
					return response.content
		except Exception as e:
			self.errors.append("Exception when GETing from FTL: " + str(e))
			return None


	# Query the FTL API (POST) and return the response
	def POST(self, uri: str, json_data: dict = {}, authenticate: AuthenticationMethods = AuthenticationMethods.HEADER, files = None):
		self.errors = []
		try:
			# Get json_data, headers and cookies
			_, headers, cookies = self.get_jsondata_headers_cookies(authenticate)

			if self.verbose:
				print("POST " + self.api_url + uri + " with json_data: " + json.dumps(json_data))

			# Query the API
			with requests.post(url = self.api_url + uri, json = json_data, files = files, headers=headers, cookies=cookies) as response:
				if self.verbose:
					print(json.dumps(response.json(), indent=4))
				return response.json()
		except Exception as e:
			self.errors.append("Exception when POSTing to FTL: " + str(e))
			return None


	# Query the endpoints from FTL for comparison with the OpenAPI specs
	def get_endpoints(self):
		try:
			# Get all endpoints from FTL and sort them for comparison
			response = self.GET("/api/endpoints")
			for method in response["endpoints"]:
				for endpoint in response["endpoints"][method]:
					self.endpoints[method].append(endpoint["uri"] + endpoint["parameters"])
			for method in self.endpoints:
				self.endpoints[method] = sorted(self.endpoints[method])
		except Exception as e:
			print("Exception when pre-processing endpoints from FTL: " + str(e))
			exit(1)

		return self.endpoints
