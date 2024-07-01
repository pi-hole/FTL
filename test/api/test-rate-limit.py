# Script that sends a number of randomly generated passwords to the
# /api/auth endpoint checking that rate limiting is enforced
import random
import string
from libs.FTLAPI import FTLAPI

if __name__ == "__main__":
	# Create FTLAPI object
	ftl = FTLAPI("http://127.0.0.1:8080")

	# Try to login with random passwords
	for i in range(0, 100):
		pw = "".join(random.choices(string.printable, k=random.randint(1, 64)))
		try:
			ftl.login(pw)
		except Exception as e:
			if "too_many_requests" in str(e):
				print("Rate-limited on attempt no. "  + str(i))
				exit(0)
			else:
				print("Unexpected error: " + str(e))
				exit(1)
	print("Rate-limiting was not enforced")
	exit(1)
