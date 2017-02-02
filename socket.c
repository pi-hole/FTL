/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Socket connection routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

// The backlog argument defines the maximum length
// to which the queue of pending connections for
// sockfd may grow. If a connection request arrives
// when the queue is full, the client may receive an
// error with an indication of ECONNREFUSED or, if
// the underlying protocol supports retransmission,
// the request may be ignored so that a later
// reattempt at connection succeeds.
#define BACKLOG 5
#define PORT 4711

int sockfd;
// Private prototype
void saveport(int port);

void init_socket(void)
{
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		logg("Error opening socket");
		exit(1);
	}

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 1000;
	setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	struct sockaddr_in serv_addr;
	// The function bzero() sets all values in a buffer to zero.
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
#if defined(LISTENLOCALHOST)
	serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#else
	serv_addr.sin_addr.s_addr = INADDR_ANY;
#endif
	// The bind() system call binds a socket to an address,
	// in this case the address of the current host and
	// port number on which the server will run.
	// convert this to network byte order using the function htons()
	// which converts a port number in host byte order to a port number
	// in network byte order
	int port;
	for(port=PORT; port <= PORT+20; port++)
	{
		serv_addr.sin_port = htons(port);
		if(bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		{
			logg_int("Error on binding on port ", port);
		}
		else
		{
			break;
		}
	}
	if(port == PORT+20)
	{
		logg("Error listening on any port");
		exit(1);
	}
	saveport(port);

	// The listen system call allows the process to listen on the socket for connections
	if(listen(sockfd,BACKLOG) == -1)
	{
		logg("Error on listening");
		exit(1);
	}
}

bool check_socket(void)
{
	char buffer[32];
	if (recv(clientsocket, buffer, sizeof(buffer), MSG_PEEK | MSG_DONTWAIT) == 0)
	{
		close(clientsocket);
		clientsocket = 0;
		return false;
	}
	else
	{
		return true;
	}
}

bool listen_socket(void)
{
	struct sockaddr_in cli_addr;
	// The function bzero() sets all values in a buffer to zero.
	bzero((char *) &cli_addr, sizeof(cli_addr));
	socklen_t clilen = sizeof(cli_addr);
	clientsocket = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	// if (newsockfd < 0)
		// printf("ERROR on accept");
	if (clientsocket > 0)
	{
#if defined(DEBUG)
		logg_str("Client connected: ", inet_ntoa (cli_addr.sin_addr));
#endif
		// const char * msg = "This is the Pi-hole FTL daemon, enter \"quit\" to quit\n\n";
		// write(clientsocket, msg, strlen(msg));
		return true;
	}
	else
	{
		return false;
	}
}

void read_socket(void)
{
	bzero(socketrecvbuffer,SOCKETBUFFERLEN);
	ssize_t n = recv(clientsocket,socketrecvbuffer,SOCKETBUFFERLEN-1, MSG_DONTWAIT);
	if (n > 0)
	{
#if defined(DEBUG)
//		logg_str("SOCK Recv:\n", socketrecvbuffer);
#endif
		process_request();
	}
}

void close_sockets(void)
{
	close(clientsocket);
	close(sockfd);
}

void seom(void)
{
	sprintf(socketsendbuffer,"---EOM---\n\n");
	swrite();
}

void swrite(void)
{
	write(clientsocket, socketsendbuffer, strlen(socketsendbuffer));
}

void saveport(int port)
{
	FILE *f;
	if((f = fopen("/etc/pihole/FTL.port", "w+")) == NULL)
	{
		logg("WARNING: Unable to write used port to file.");
		logg("         Continuing anyway (API might not find the port).");
	}
	else
	{
		fprintf(f, "%i", port);
		fclose(f);
	}
	logg_int("Listening on port ", port);
}
