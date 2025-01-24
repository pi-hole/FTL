#!/bin/python3
# Pi-hole: A black hole for Internet advertisements
# (c) 2023 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine - auxiliary files
# Send a dynamic update to the DNS server to update the a zone
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

import sys
import dns.query
import dns.update
import dns.rcode

# Create a new update object
update = dns.update.Update('example.com')

# Add a new A record
update.add('www.example.com', 300, 'A', '127.0.0.1')

# Send the update to the DNS server and print the response
if sys.argv[1] == 'udp':
	response = dns.query.udp(update, '127.0.0.1')
	print("UDP response: " + dns.rcode.to_text(response.rcode()))
elif sys.argv[1] == 'tcp':
	response = dns.query.tcp(update, '127.0.0.1')
	print("TCP response: " + dns.rcode.to_text(response.rcode()))
else:
	print("Invalid argument, use 'udp' or 'tcp'")
	sys.exit(1)
