/* uds_client.c */
#include <sys/types.h>
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Unix socket connection test program
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define BUF 1024
#define UDS_FILE "/var/run/pihole/FTL.sock"

int main (int argc, char **argv) {
	int socketfd;
	char *buffer = malloc (BUF);
	struct sockaddr_un address;
	int size, ret;

	socketfd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if(socket <= 0)
	{
		printf("Error creating socket!\n");
		exit(EXIT_FAILURE);
	}
	printf ("Socket created\n");

	address.sun_family = AF_LOCAL;
	strcpy(address.sun_path, UDS_FILE);
	ret = connect(socketfd, (struct sockaddr *) &address, sizeof (address));
	if (ret != 0)
	{
		printf("Error establishing connection!\n");
		exit(EXIT_FAILURE);
	}
	printf("Connection established\n");

	sprintf(buffer, ">stats");
	send(socketfd, buffer, strlen (buffer), 0);

	// Receive message
	size = recv(socketfd, buffer, BUF-1, 0);

	while (strstr(buffer, "--EOM--") != 0)
	{
		// Zero-terminate incoming message
		if(size > 0)
			buffer[size] = '\0';

		printf("Message received: \"%s\"\n", buffer);

		// Receive message
		size = recv(socketfd, buffer, BUF-1, 0);
	}

	printf("Message received: \"%s\"\n", buffer);

	close (socketfd);
	return EXIT_SUCCESS;
	}
