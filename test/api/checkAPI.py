#!/bin/python3

import yaml
import json
import urllib.request

# OpenAPI specs are split into multiple files, this script extracts the endpoints from them
base_path = "src/api/docs/content/specs/"

# List of methods we want to extract
methods = ["get", "post", "put", "delete"]

# Prepare list of endpoints
endpoints = {}
for method in methods:
	endpoints[method] = []

# Cache for already read files
yamls = {}

def read_yaml_maybe_cache(file: str) -> dict:
	if file not in yamls:
		# Read the file
		with open(file, "r") as stream:
			try:
				yamls[file] = yaml.safe_load(stream)
			except Exception as e:
				print("Exception when reading " + file + ": " + e)
				exit(1)
	return yamls[file]

# Read and parse the main file
try:
	# Get the paths
	paths = read_yaml_maybe_cache(base_path + "main.yaml")["paths"]
except Exception as e:
	print(e)
	exit(1)

# Resolve a reference
def resolveSingleReference(ref: str, k: str):
	# Read and parse the referenced file
	ref = ref.partition("#")
	if len(ref[0]) == 0:
		# Empty references are not allowed
		raise Exception("Empty reference, always specify a file in the API specification")
	# If the file link is empty, we refer to the current file
	file = base_path + ref[0]

	# Read the referenced file
	try:
		# Extract the YAML
		refYML_full = read_yaml_maybe_cache(file)
		refYML = refYML_full.copy()
		# Reduce to what we want to import
		for x in ref[2].split("/"):
			if len(x) > 0:
				refYML = refYML[x]
		return refYML
	except Exception as e:
		print("Exception when reading " + file + ": " + e)
		print("Tried to read" + ref + " in:\n" + json.dumps(refYML, indent=2))
		print("Tried to resolve " + k + " pointing to " + ref)
		exit(1)

# Recursively resolve references, this can take a few seconds
def recurseRef(dict_in: dict, dict_key: str):
	for a in dict_in.keys():
		next_dict_key = dict_key + "/" + a if len(dict_key) > 0 else a
		if isinstance(dict_in[a], dict):
			if "$ref" in dict_in[a]:
				dict_in[a] = resolveSingleReference(dict_in[a]["$ref"], next_dict_key)
				# Recurse into the new reference
				recurseRef(dict_in[a],  next_dict_key)
			else:
				# Recurse into the dictionary
				recurseRef(dict_in[a],  next_dict_key)

# Recursively resolve references in the paths
# We do this in a separate step to avoid resolving references multiple times
# References are resolved in-place
print("Resolving references...")
recurseRef(paths, "")
print("...done\n")

# Sort the list of endpoints
YAMLendpoints = {}
for method in methods:
	YAMLendpoints[method] = sorted(endpoints[method])

# Query the endpoints from FTL for comparison with the OpenAPI specs
try:
	with urllib.request.urlopen("http://127.0.0.1:8080/api/ftl/endpoints") as url:
		FTLendpoints = sorted(json.load(url)["endpoints"])
except Exception as e:
	print("Exception: " + e)
	exit(1)

errs = [0, 0]
print("Endpoints in OpenAPI specs but not in FTL:")
# Check for endpoints in OpenAPI specs that are not defined in FTL
for path in YAMLendpoints["get"]:
	if path not in FTLendpoints:
		print("  Missing GET endpoint in FTL: " + path)
		errs[0] += 1
if errs[0] == 0:
	print("  No missing endpoints\n")

# Check for endpoints in FTL that are not in the OpenAPI specs
print("Endpoints in FTL but not in OpenAPI specs:")
for path in FTLendpoints:
	if path not in YAMLendpoints["get"]:
		# Ignore the docs endpoint
		if path in ["/api/docs"]:
			continue
		print("  Missing GET endpoint in OpenAPI specs: " + path)
		errs[1] += 1
if errs[1] == 0:
	print("  No missing endpoints\n")

# Print the number of missing endpoints (if there are any)
if errs[0] > 0:
	print("Found " + str(errs[0]) + " non-implemented endpoints")
if errs[1] > 0:
	print("Found " + str(errs[1]) + " undocumented endpoints")

# Exit with an error if there are missing endpoints
if sum(errs) > 0:
	exit(1)

# If there are no missing endpoints, exit with success
print("No missing endpoints")
exit(0)
