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
// socketfd may grow. If a connection request arrives
// when the queue is full, the client may receive an
// error with an indication of ECONNREFUSED or, if
// the underlying protocol supports retransmission,
// the request may be ignored so that a later
// reattempt at connection succeeds.
#define BACKLOG 5

// File descriptors
int socketfd;
bool dualstack = false;

void saveport(int port)
{
	FILE *f;
	if((f = fopen(FTLfiles.port, "w+")) == NULL)
	{
		logg("WARNING: Unable to write used port to file.");
		logg("         Continuing anyway (API might not find the port).");
	}
	else
	{
		fprintf(f, "%i", port);
		fclose(f);
	}
}

void bind_to_port(char type, int *socketdescriptor)
{
	*socketdescriptor = socket(AF_INET6, SOCK_STREAM, 0);

	if(*socketdescriptor < 0)
	{
		logg("Error opening socket");
		exit(EXIT_FAILURE);
	}

	// Set SO_REUSEADDR to allow re-binding to the port that has been used
	// previously by FTL. A common pattern is that you change FTL's
	// configuration file and need to restart that server to make it reload
	// its configuration. Without SO_REUSEADDR, the bind() call in the restarted
	// new instance will fail if there were connections open to the previous
	// instance when you killed it. Those connections will hold the TCP port in
	// the TIME_WAIT state for 30-120 seconds, so you fall into case 1 above.
	setsockopt(*socketdescriptor, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

	struct sockaddr_in6 serv_addr;
	// set all values in the buffer to zero
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin6_family = AF_INET6;

	if(config.socket_listenlocal && type == SOCKET)
		serv_addr.sin6_addr = in6addr_loopback;
	else
		serv_addr.sin6_addr = in6addr_any;

	// The bind() system call binds a socket to an address,
	// in this case the address of the current host and
	// port number on which the server will run.
	// convert this to network byte order using the function htons()
	// which converts a port number in host byte order to a port number
	// in network byte order
	int port, port_init;

	switch(type)
	{
		case SOCKET:
			port_init = 4711;
			break;
		default:
			logg("Incompatible socket type %i", (int)type);
			exit(EXIT_FAILURE);
			break;
	}

	bool bound = false;
	// Try dual-stack socket
	for(port = port_init; port <= (port_init + 20); port++)
	{
		serv_addr.sin6_port = htons(port);
		if(bind(*socketdescriptor, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		{
			logg("Error on binding on port %i", port);
		}
		else
		{
			bound = true;
			dualstack = true;
			break;
		}
	}

	// Try IPv4 only socket, much of the code seen above is duplicated here for IPv4,
	// see the comments further up for details
	if(!bound)
	{
		logg("Error listening on any IPv4 + IPv6 port, trying IPv4-only binding");
		*socketdescriptor = socket(AF_INET, SOCK_STREAM, 0);

		struct sockaddr_in serv_addr4;
		memset(&serv_addr4, 0, sizeof(serv_addr4));
		serv_addr4.sin_family = AF_INET;

		if(config.socket_listenlocal && type == SOCKET)
			serv_addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		else
			serv_addr4.sin_addr.s_addr = INADDR_ANY;

		for(port = port_init; port <= (port_init + 20); port++)
		{
			serv_addr4.sin_port = htons(port);
			if(bind(*socketdescriptor, (struct sockaddr *) &serv_addr4, sizeof(serv_addr4)) < 0)
			{
				logg("Error on binding on IPv4 port %i", port);
			}
			else
			{
				bound = true;
				break;
			}
		}
	}

	if(!bound)
	{
		logg("Error listening on any IPv4 port");
		exit(EXIT_FAILURE);
	}

	if(type == SOCKET)
		saveport(port);

	// The listen system call allows the process to listen on the socket for connections
	if(listen(*socketdescriptor, BACKLOG) == -1)
	{
		logg("Error on listening");
		exit(EXIT_FAILURE);
	}

	logg("Listening on port %i for incoming %s connections", port, dualstack == true ? "IPv4 + IPv6" : "IPv4");
}

// Called from main() at graceful shutdown
void removeport(void)
{
	FILE *f;
	if((f = fopen(FTLfiles.port, "w+")) == NULL)
	{
		logg("WARNING: Unable to empty port file");
		return;
	}
	fclose(f);
}

void seom(char server_message[SOCKETBUFFERLEN], int sock)
{
	sprintf(server_message,"---EOM---\n\n");
	swrite(server_message, sock);
}

void swrite(char server_message[SOCKETBUFFERLEN], int sock)
{
	if(!write(sock, server_message, strlen(server_message)))
		logg("WARNING: Socket write returned error code %i", errno);
}

int listener(int sockfd)
{
	struct sockaddr_in6 cli_addr;
	struct sockaddr_in cli_addr4;
	// set all values in the buffer to zero
	memset(&cli_addr, 0, sizeof(cli_addr));
	socklen_t clilen = sizeof(cli_addr);
	int clientsocket = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

	if(clientsocket > 0)
	{
		char str[INET6_ADDRSTRLEN];
		if(dualstack)
		{
			// Determine the client address.  Note that if we bound to a dual-stack
			// socket and the client is an IPv4 client, the address will be shown
			// as an IPv4 Mapped IPv6 address, like "::ffff:127.0.0.1"
			getpeername(clientsocket, (struct sockaddr *)&cli_addr, &clilen);
			if(inet_ntop(AF_INET6, &cli_addr.sin6_addr, str, sizeof(str)))
			{
				int port = ntohs(cli_addr.sin6_port);
				if(debugclients)
					logg("Client connected: %s:%d, ID: %i", str, port, clientsocket);
			}
		}
		else
		{
			getpeername(clientsocket, (struct sockaddr *)&cli_addr4, &clilen);
			if(inet_ntop(AF_INET, &cli_addr4.sin_addr, str, sizeof(str)))
			{
				int port = ntohs(cli_addr4.sin_port);
				if(debugclients)
					logg("Client connected: %s:%d, ID: %i", str, port, clientsocket);
			}
		}
	}
	return clientsocket;
}

void close_socket(char type)
{
	switch(type)
	{
		case SOCKET:
			removeport();
			// Using global variable here
			close(socketfd);
			break;
		default:
			logg("Incompatible socket type %i, cannot close",(int)type);
			exit(EXIT_FAILURE);
			break;
	}
}

void *socket_connection_handler_thread(void *socket_desc)
{
	//Get the socket descriptor
	int sock = *(int*)socket_desc;
	// Store copy only for displaying the debug messages
	int sockID = sock;
	char client_message[SOCKETBUFFERLEN] = "";

	// Set thread name
	char threadname[16];
	sprintf(threadname,"client-%i",sockID);
	prctl(PR_SET_NAME,threadname,0,0,0);
	//Receive from client
	ssize_t n;
	while((n = recv(sock,client_message,SOCKETBUFFERLEN-1, 0)))
	{
		if (n > 0)
		{
			char *message = calloc(strlen(client_message)+1,sizeof(char));
			strcpy(message, client_message);

			// Clear client message receive buffer
			memset(client_message, 0, sizeof client_message);

			// Lock FTL data structure, since it is likely that it will be changed here
			// Requests should not be processed/answered when data is about to change
			enable_thread_lock(threadname);

			process_request(message, &sock);
			free(message);

			// Release thread lock
			disable_thread_lock(threadname);

			if(sock == 0)
			{
				// Client disconnected by seding EOT or ">quit"
				break;
			}
		}
		else if(n == -1)
		{
			if(debugclients)
				logg("Client connection interrupted, ID: %i", sockID);
		}
	}
	if(debugclients)
		logg("Client disconnected, ID: %i", sockID);

	//Free the socket pointer
	if(sock != 0)
		close(sock);
	free(socket_desc);

	return 0;
}

void *socket_listenting_thread(void *args)
{
	int *newsock;
	// We will use the attributes object later to start all threads in detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically released back to
	// the system without the need for another thread to join with the terminated thread
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Set thread name
	prctl(PR_SET_NAME,"socket listener",0,0,0);

	// Initialize sockets only after initial log parsing in listenting_thread
	bind_to_port(SOCKET, &socketfd);

	// Listen as long as FTL is not killed
	while(!killed)
	{
		// Look for new clients that want to connect
		int csck = listener(socketfd);

		// Allocate memory used to transport client socket ID to client listening thread
		newsock = calloc(1,sizeof(int));
		*newsock = csck;

		pthread_t socket_connection_thread;
		// Create a new thread
		if(pthread_create( &socket_connection_thread, &attr, socket_connection_handler_thread, (void*) newsock ) != 0)
		{
			// Log the error code description
			logg("WARNING: Unable to open clients processing thread, error: %s", strerror(errno));
		}
	}
	return 0;
}
