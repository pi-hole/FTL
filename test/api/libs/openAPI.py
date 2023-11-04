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

import yaml
import json

class openApi():

	# List of methods we want to extract
	METHODS = ["get", "post", "put", "patch", "delete"]

	def __init__(self, base_path: str, api_root: str = "/api") -> None:
		# Store arguments
		self.base_path = base_path
		self.api_root = api_root

		# Prepare list of YAML endpoints
		self.endpoints = {}
		for method in self.METHODS:
			self.endpoints[method] = []

		# Cache for already read files
		self.yaml_cache = {}

	# Read YAML file and add content to a cache
	def read_yaml_maybe_cache(self, file: str) -> dict:
		# Check if we have already read + parsed this file
		if file not in self.yaml_cache:
			# Read the file
			try:
				with open(file, "r") as stream:
					try:
						# Parse the file
						self.yaml_cache[file] = yaml.safe_load(stream)
					except Exception as e:
						print("Exception when trying to parse " + file + ": " + str(e))
						exit(1)
			except Exception as e:
				print("Exception when trying to read " + file + ": " + str(e))
				exit(1)

		return self.yaml_cache[file]


	# Resolve a reference
	def resolveSingleReference(self, ref_str: str):
		# Read and parse the referenced file
		ref = ref_str.partition("#")
		if len(ref[0]) == 0:
			# Empty references are not allowed
			raise Exception("Empty reference, always specify a file in the API specification")
		# If the file link is empty, we refer to the current file
		file = self.base_path + ref[0]

		# Read the referenced file
		try:
			# Extract the YAML
			refYML_full = self.read_yaml_maybe_cache(file)
			refYML = refYML_full.copy()
			# Reduce to what we want to import
			for x in ref[2].split("/"):
				if len(x) > 0:
					#if x not in refYML:
					refYML = refYML[x]
			return refYML
		except Exception as e:
			print("Exception when reading " + file + ": " + str(e))
			print("Tried to resolve " + ref_str + " in:\n" + json.dumps(refYML, indent=2))
			exit(1)


	# Recursively resolve references, this can take a few seconds
	def recurseRef(self, dict_in: dict, dict_key: str):
		# Loop over all items in this dict
		for a in dict_in.keys():
			# Create the next dict key
			next_dict_key = dict_key + "/" + a if len(dict_key) > 0 else a
			# If the item is a dict, we check if it is a reference
			if isinstance(dict_in[a], dict):
				# Check if this is a reference
				if "$ref" in dict_in[a]:
					# Yes, this is a reference, replace it with the actual content and ...
					dict_in[a] = self.resolveSingleReference(dict_in[a]["$ref"])
					# ... recurse into the new reference
					self.recurseRef(dict_in[a],  next_dict_key)
				else:
					# No reference, just recurse into the next level
					self.recurseRef(dict_in[a], next_dict_key)
			# If it is not a dict, it may be a list with references (e.g., OpenAPI's "allOf/anyOf")
			elif isinstance(dict_in[a], list):
				# Loop over all items in the list
				for i in range(len(dict_in[a])):
					# If the item is a dict, we check if it is a reference
					if isinstance(dict_in[a][i], dict):
						if "$ref" in dict_in[a][i]:
							# Yes, this is a reference, replace it with the actual content and ...
							dict_in[a][i] = self.resolveSingleReference(dict_in[a][i]["$ref"])
							# ... recurse into the new reference
							self.recurseRef(dict_in[a][i],  next_dict_key)
						else:
							# No reference, just recurse into the next level
							self.recurseRef(dict_in[a][i],  next_dict_key)


	def parse(self, filename: str):
		# Read and parse the main file
		try:
			# Get the paths
			self.paths = self.read_yaml_maybe_cache(self.base_path + filename)["paths"]
		except Exception as e:
			print("Exception when trying to read " + e)
			return False

		# Recursively resolve references in the paths
		# We do this in a separate step to avoid resolving references multiple
		# times. References are resolved in-place
		print("Resolving references...")
		self.recurseRef(self.paths, "")
		print("...done\n")

		# Build and sort the list of endpoints
		for method in self.METHODS:
			for path in self.paths:
				if method in self.paths[path]:
					# Strip possible variables from path
					clean_path = self.api_root + path
					self.endpoints[method].append(clean_path)
			# Sort the list of endpoints
			self.endpoints[method] = sorted(self.endpoints[method])

		return True


