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

from types import NoneType
from libs.openAPI import openApi
import urllib.request, urllib.parse
from libs.FTLAPI import FTLAPI

class ResponseVerifyer():

	# Translate between OpenAPI and Python types
	YAML_TYPES = { "string": [str], "integer": [int], "number": [int, float], "boolean": [bool], "array": [list] }

	def __init__(self, ftl: FTLAPI, openapi: openApi):
		self.ftl = ftl
		self.openapi = openapi
		self.errors = []

	def verify_endpoint(self, endpoint: str):

		if endpoint.startswith("/api"):
			endpoint = endpoint[4:]

		method = 'get'
		rcode = '200'
		if endpoint not in self.openapi.paths:
			self.errors.append("Endpoint " + endpoint + " not found in OpenAPI specs")
			return self.errors
		if method not in self.openapi.paths[endpoint]:
			self.errors.append("Method " + method + " not found in OpenAPI specs (" + endpoint + ")")
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

		FTLresponse = self.ftl.getFTLresponse("/api" + endpoint, FTLparameters)
		if FTLresponse is None:
			return self.ftl.errors

		if 'type' in YAMLresponseSchema and YAMLresponseSchema['type'] == 'object':
			for prop in YAMLresponseSchema['properties']:
				self.verify_property(YAMLresponseSchema['properties'], YAMLresponseExamples, FTLresponse, [prop])

		elif 'allOf' in YAMLresponseSchema and len(YAMLresponseSchema['allOf']) > 0:
			for i in range(len(YAMLresponseSchema['allOf'])):
				for prop in YAMLresponseSchema['allOf'][i]['properties']:
					self.verify_property(YAMLresponseSchema['allOf'][i]['properties'], YAMLresponseExamples, FTLresponse, [prop])
		else:
			self.errors.append("Top-level response should be either an object or a non-empty allOf/anyOf/oneOf")

		return self.errors


	def verify_type(self, prop_type: any, yaml_type: str, yaml_nullable: bool):
		# None is an acceptable reply when this is specified in the API specs
		if prop_type == NoneType and yaml_nullable:
			return True
		return prop_type in self.YAML_TYPES[yaml_type]


	def verify_property(self, YAMLprops: dict, YAMLexamples: dict, FTLprops: dict, props: list):
		all_okay = True

		if props[-1] not in YAMLprops:
			self.errors.append("Property " + props[-1] + " missing in API specs")
			return False
		YAMLprop = YAMLprops[props[-1]]
		if props[-1] not in FTLprops:
			self.errors.append("Property " + props[-1] + " missing in FTL's response")
			return False
		FTLprop = FTLprops[props[-1]]

		# If this is another object, we have to dive deeper
		if YAMLprop['type'] == 'object':
			for prop in YAMLprop['properties']:
				if not self.verify_property(YAMLprop['properties'], YAMLexamples, FTLprop, props + [prop]):
					all_okay = False
		else:
			# Check this property
			full_path = " => ".join(props)
			yaml_type = YAMLprop['type']
			yaml_nullable = 'nullable' in YAMLprop and YAMLprop['nullable'] == True

			# Check type of YAML example (if defined)
			if 'example' in YAMLprop:
				example_type = type(YAMLprop['example'])
				if not self.verify_type(example_type, yaml_type, yaml_nullable):
					self.errors.append(f"API example ({str(example_type)}) does not match defined type ({yaml_type}) in {full_path}")
					return False
			elif YAMLexamples is not None:
				for t in YAMLexamples:
					example = YAMLexamples[t]['value']
					for p in props:
						example = example[p]
					example_type = type(example)
					if not self.verify_type(example_type, yaml_type, yaml_nullable):
						self.errors.append(f"API example ({str(example_type)}) does not match defined type ({yaml_type}) in {full_path}")
						return False

			# Compare type of FTL's reply against what we defined in the API specs
			ftl_type = type(FTLprop)
			if not self.verify_type(ftl_type, yaml_type, yaml_nullable):
				self.errors.append(f"FTL's reply ({str(ftl_type)}) does not match defined type ({yaml_type}) in {full_path}")
				return False
		return all_okay
