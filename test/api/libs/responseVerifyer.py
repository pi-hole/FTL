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
import urllib.request, urllib.parse
from libs.FTLAPI import FTLAPI
from collections.abc import MutableMapping

class ResponseVerifyer():

	# Translate between OpenAPI and Python types
	YAML_TYPES = { "string": [str], "integer": [int], "number": [int, float], "boolean": [bool], "array": [list] }

	def __init__(self, ftl: FTLAPI, openapi: openApi):
		self.ftl = ftl
		self.openapi = openapi
		self.errors = []


	def flatten_dict(self, d: MutableMapping, parent_key: str = '', sep: str ='.') -> MutableMapping:
		items = []
		# Iterate over all items in the dictionary
		for k, v in d.items():
			# Create a new key by appending the current key to the parent key
			new_key = parent_key + sep + k if parent_key else k
			# If the value is a dictionary, recursively flatten it, otherwise
			# simply add it to the list of items
			if isinstance(v, MutableMapping):
				items.extend(self.flatten_dict(v, new_key, sep=sep).items())
			else:
				items.append((new_key, v))
		return dict(items)


	def verify_endpoint(self, endpoint: str):
		# If the endpoint starts with /api, remove this part (it is not
		# part of the YAML specs)
		if endpoint.startswith("/api"):
			endpoint = endpoint[4:]

		method = 'get'
		rcode = '200'
		# Check if the endpoint is defined in the API specs
		if endpoint not in self.openapi.paths:
			self.errors.append("Endpoint " + endpoint + " not found in the API specs")
			return self.errors
		# Check if this endpoint + method are defined in the API specs
		if method not in self.openapi.paths[endpoint]:
			self.errors.append("Method " + method + " not found in the API specs")
			return self.errors

		# Get YAML response schema and examples (if applicable)
		jsonData = self.openapi.paths[endpoint][method]['responses'][str(rcode)]['content']['application/json']
		YAMLresponseSchema = jsonData['schema']
		YAMLresponseExamples = jsonData['examples'] if 'examples' in jsonData else None

		# Prepare required parameters (if any)
		FTLparameters = []
		if 'parameters' in self.openapi.paths[endpoint][method]:
			YAMLparameters = self.openapi.paths[endpoint][method]['parameters']
			for param in YAMLparameters:
				# We are only handling QUERY parameters here as we're doing GET
				if param['in'] != 'query':
					continue
				# We are only adding required parameters here
				if param['required'] == False:
					continue
				FTLparameters.append(param['name'] + "=" + urllib.parse.quote_plus(str(param['example'])))

		# Get FTL response
		FTLresponse = self.ftl.GET("/api" + endpoint, FTLparameters)
		if FTLresponse is None:
			return self.ftl.errors

		self.YAMLresponse = {}
		# Check if the response is an object. If so, we have to check it
		# recursively
		if 'type' in YAMLresponseSchema and YAMLresponseSchema['type'] == 'object':
			# Loop over all properties of the object
			for prop in YAMLresponseSchema['properties']:
				self.verify_property(YAMLresponseSchema['properties'], YAMLresponseExamples, FTLresponse, [prop])

		# Check if the response is a gather-all object. If so, we have
		# to check all objects in the array individually
		elif 'allOf' in YAMLresponseSchema and len(YAMLresponseSchema['allOf']) > 0:
			for i in range(len(YAMLresponseSchema['allOf'])):
				for prop in YAMLresponseSchema['allOf'][i]['properties']:
					self.verify_property(YAMLresponseSchema['allOf'][i]['properties'], YAMLresponseExamples, FTLresponse, [prop])

		# If neither of the above is true, thie definition is invalid
		else:
			self.errors.append("Top-level response should be either an object or a non-empty allOf/anyOf/oneOf")

		# Finally, we check if there are extra properties in the FTL response
		# that are not defined in the API specs

		# Flatten the FTL response
		FTLflat = self.flatten_dict(FTLresponse)
		YAMLflat = self.YAMLresponse

		# Check for properties in FTL that are not in the API specs
		for property in FTLflat.keys():
			if property not in YAMLflat.keys():
				self.errors.append("Property '" + property + "' missing in the API specs")

		# Return all errors
		return self.errors


	# Verify a single property's type
	def verify_type(self, prop_type: any, yaml_type: str, yaml_nullable: bool):
		# None is an acceptable reply when this is specified in the API specs
		if prop_type is type(None) and yaml_nullable:
			return True
		# Check if the type is correct using the YAML_TYPES translation table
		if yaml_type not in self.YAML_TYPES:
			self.errors.append("Property type \"" + yaml_type + "\" is not valid in OpenAPI specs")
			return False
		return prop_type in self.YAML_TYPES[yaml_type]


	# Verify a single property
	def verify_property(self, YAMLprops: dict, YAMLexamples: dict, FTLprops: dict, props: list):
		all_okay = True

		# Build flat path of this property
		flat_path = ".".join(props)

		# Check if the property is defined in the API specs
		if props[-1] not in YAMLprops:
			self.errors.append("Property '" + flat_path + "' missing in the API specs")
			return False
		YAMLprop = YAMLprops[props[-1]]

		# Check if the property is defined in the FTL response
		if props[-1] not in FTLprops:
			self.errors.append("Property '" + flat_path + "' missing in FTL's response")
			return False
		FTLprop = FTLprops[props[-1]]

		# If this is another object, we have to dive deeper
		if YAMLprop['type'] == 'object':
			# Loop over all properties of the object ...
			for prop in YAMLprop['properties']:
				# ... and check them recursively
				if not self.verify_property(YAMLprop['properties'], YAMLexamples, FTLprop, props + [prop]):
					all_okay = False
		else:
			# Check this property

			# Get type of this property using the YAML_TYPES translation table
			yaml_type = YAMLprop['type']

			# Check if this property is nullable (can be None even
			# if not defined as string, integer, etc.)
			yaml_nullable = 'nullable' in YAMLprop and YAMLprop['nullable'] == True

			# Add this property to the YAML response
			self.YAMLresponse[flat_path] = []

			# Check type of YAML example (if defined)
			if 'example' in YAMLprop:
				example_type = type(YAMLprop['example'])
				# Check if the type of the example matches the
				# type we defined in the API specs
				self.YAMLresponse[flat_path].append(YAMLprop['example'])
				if not self.verify_type(example_type, yaml_type, yaml_nullable):
					self.errors.append(f"API example ({str(example_type)}) does not match defined type ({yaml_type}) in {flat_path} (nullable: " + ("True" if yaml_nullable else "False") + ")")
					return False

			# Check type of externally defined YAML examples (next to schema)
			elif YAMLexamples is not None:
				for t in YAMLexamples:
					if 'value' not in YAMLexamples[t]:
						self.errors.append(f"Example {flat_path} does not have a 'value' property")
						return False
					example = YAMLexamples[t]['value']
					# Dive into the example to get to the property we want
					for p in props:
						if p not in example:
							self.errors.append(f"Example {flat_path} does not have an '{p}' item")
							return False
						example = example[p]
					# Check if the type of the example matches the type we defined in the API specs
					example_type = type(example)
					self.YAMLresponse[flat_path].append(example)
					if not self.verify_type(example_type, yaml_type, yaml_nullable):
						self.errors.append(f"API example ({str(example_type)}) does not match defined type ({yaml_type}) in {flat_path} (nullable: " + ("True" if yaml_nullable else "False") + ")")
						return False

			# Compare type of FTL's reply against what we defined in the API specs
			ftl_type = type(FTLprop)
			if not self.verify_type(ftl_type, yaml_type, yaml_nullable):
				self.errors.append(f"FTL's reply ({str(ftl_type)}) does not match defined type ({yaml_type}) in {flat_path}")
				return False
		return all_okay
