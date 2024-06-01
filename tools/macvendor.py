# Pi-hole: A black hole for Internet advertisements
# (c) 2019 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine - auxiliary files
# MAC -> Vendor database generator
#
# This is a python3 script
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

import os
import re
import requests
import sqlite3

# Download raw data from Wireshark's website
# We use the official URL recommended in the header of this file
URL = "https://www.wireshark.org/download/automated/data/manuf"
# User-Agent string to use for the request
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
print("Downloading...")
manuf = requests.get(URL, headers={"User-Agent": USER_AGENT}).text.splitlines()
print("...done")

# Read file into memory and process lines
data = []
print("Processing...")
for line in manuf:
	line = line.strip()

	# Skip comments and empty lines
	if line == "" or line[0] == "#":
		continue

	# Remove quotation marks as these might interfere with later INSERT / UPDATE commands
	line = re.sub("\'|\"","", line)
	# \s = Unicode whitespace characters, including [ \t\n\r\f\v]
	cols = re.split("\s\s+|\t", line)
	# Use try/except chain to catch empty/incomplete lines without failing hard
	try:
		# Strip whitespace and quotation marks (some entries are incomplete and cause errors with the CSV parser otherwise)
		mac = cols[0].strip().strip("\"")
	except:
		continue
	try:
		desc_short = cols[1].strip().strip("\"")
	except:
		desc_short = ""
	try:
		desc_long = cols[2].strip().strip("\"")
	except:
		desc_long = ""

	# Only add long description where available
	# There are a few vendors for which only the
	# short description field is used
	if(desc_long):
		data.append([mac, desc_long])
	else:
		data.append([mac, desc_short])
print("...done")

# Create database
database = "macvendor.db"

# Try to delete old database file, pass if no old file exists
try:
	os.remove(database)
except OSError:
	pass

print("Generating database...")
con = sqlite3.connect(database)
cur = con.cursor()
cur.execute("CREATE TABLE macvendor (mac TEXT NOT NULL, vendor TEXT NOT NULL, PRIMARY KEY (mac))")
cur.executemany("INSERT INTO macvendor (mac, vendor) VALUES (?, ?);", data)
con.commit()
print("...done.")
print("Optimizing database...")
con.execute("VACUUM")
print("...done")
print("Lines inserted into database:", cur.rowcount)
