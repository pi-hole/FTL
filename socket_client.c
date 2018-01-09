/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Unix socket connection test program
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define BUF 1024

int main (int argc, char **argv) {
	int socketfd;
	char *buffer = malloc (BUF);
	struct sockaddr_un address;
	int size, ret;

	// Create socket
	socketfd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if(socketfd <= 0)
	{
		printf("Error creating socket!\n");
		exit(EXIT_FAILURE);
	}
	printf("Socket created\n");

	// Set socket family to local socket (not an Internet socket)
	address.sun_family = AF_LOCAL;

	// Set socket file location (respect special location on the CI system Travis)
	if(argc == 2 && strcmp(argv[1], "travis") == 0)
		strcpy(address.sun_path,"pihole-FTL.sock");
	else
		strcpy(address.sun_path,"/var/run/pihole/FTL.sock");

	// Connect to the socket provided by pihole-FTL
	ret = connect(socketfd, (struct sockaddr *) &address, sizeof (address));
	if (ret != 0)
	{
		printf("Error establishing connection!\n");
		exit(EXIT_FAILURE);
	}
	printf("Connection established\n");

	// As an example, we query the current statistics from FTL through the socket here
	sprintf(buffer, ">stats");
	send(socketfd, buffer, strlen (buffer), 0);

	// Try to receive data until either recv() fails or we see "--EOM--"
	while((size = recv(socketfd, buffer, BUF-1, 0)) > -1)
	{
		// Zero-terminate incoming message
		if(size > 0)
			buffer[size] = '\0';

		// Print received data to stdout
		printf("%s", buffer);

		// Exit on End Of Message
		if(strstr(buffer, "--EOM--") != NULL)
			break;

	}

	// Close Unix socket connection
	close(socketfd);
	return EXIT_SUCCESS;
}
