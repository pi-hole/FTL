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
import urllib.request
import sqlite3

# Download raw data from Wireshark's website
# We use the official URL recommended in the header of this file
# Thanks to mibere for the update
print("Downloading...")
opener = urllib.request.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0')]
urllib.request.install_opener(opener)
urllib.request.urlretrieve("https://gitlab.com/wireshark/wireshark/-/raw/master/manuf", "manuf.data")
print("...done")

# Read file into memory and process lines
manuf = open("manuf.data", "r")
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
manuf.close()

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
