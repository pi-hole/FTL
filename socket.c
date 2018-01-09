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
// telnetfd may grow. If a connection request arrives
// when the queue is full, the client may receive an
// error with an indication of ECONNREFUSED or, if
// the underlying protocol supports retransmission,
// the request may be ignored so that a later
// reattempt at connection succeeds.
#define BACKLOG 5

// File descriptors
int telnetfd, socketfd;
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

void bind_to_telnet_port(char type, int *socketdescriptor)
{
	int port, port_init = 4711;

	if(ipv6_available())
	{
		*socketdescriptor = socket(AF_INET6, SOCK_STREAM, 0);

		if(*socketdescriptor < 0)
		{
			logg("Error opening telnet socket");
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

		bool bound = false;
		// Bind to dual-stack socket
		for(port = port_init; port <= (port_init + 20); port++)
		{
			serv_addr.sin6_port = htons(port);
			if(bind(*socketdescriptor, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) >= 0)
			{
				bound = true;
				dualstack = true;
				break;
			}
		}

		if(!bound)
		{
			logg("Error listening on any IPv4 + IPv6 port");
			exit(EXIT_FAILURE);
		}

	}
	else
	{
		// Try IPv4 only socket
		// see the comments further up for details
		logg("Error listening on any IPv4 + IPv6 port, trying IPv4-only binding");
		*socketdescriptor = socket(AF_INET, SOCK_STREAM, 0);

		struct sockaddr_in serv_addr4;
		memset(&serv_addr4, 0, sizeof(serv_addr4));
		serv_addr4.sin_family = AF_INET;

		if(config.socket_listenlocal && type == SOCKET)
			serv_addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		else
			serv_addr4.sin_addr.s_addr = INADDR_ANY;

		bool bound = false;
		// Bind to IPv4 port
		for(port = port_init; port <= (port_init + 20); port++)
		{
			serv_addr4.sin_port = htons(port);
			if(bind(*socketdescriptor, (struct sockaddr *) &serv_addr4, sizeof(serv_addr4)) >= 0)
			{
				bound = true;
				break;
			}
		}

		if(!bound)
		{
			logg("Error listening on any IPv4 port");
			exit(EXIT_FAILURE);
		}
	}

	saveport(port);

	// The listen system call allows the process to listen on the socket for connections
	if(listen(*socketdescriptor, BACKLOG) == -1)
	{
		logg("Error on listening");
		exit(EXIT_FAILURE);
	}

	logg("Listening on port %i for incoming %s connections", port, dualstack ? "IPv4 + IPv6" : "IPv4");
}


void bind_to_unix_socket(int *socketdescriptor)
{
	*socketdescriptor = socket(AF_LOCAL, SOCK_STREAM, 0);

	if(*socketdescriptor < 0)
	{
		logg("Error opening unix socket");
		exit(EXIT_FAILURE);
	}

	// Make sure unix socket file handle does not exist, if it exists, remove it
	unlink(FTLfiles.socketfile);

	struct sockaddr_un address;
	address.sun_family = AF_LOCAL;
	strcpy(address.sun_path, FTLfiles.socketfile);

	// Bild to Unix socket handle
	errno = 0;
	if(bind(*socketdescriptor, (struct sockaddr *) &address, sizeof (address)) != 0) {
		logg("Error on binding on unix socket %s", FTLfiles.socketfile);
		logg("Reason: %s (%i)", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	// The listen system call allows the process to listen on the Unix socket for connections
	if(listen(*socketdescriptor, BACKLOG) == -1)
	{
		logg("Error on listening");
		exit(EXIT_FAILURE);
	}

	logg("Listening on Unix socket");
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

void close_telnet_socket(void)
{
	removeport();
	// Using global variable here
	close(telnetfd);
}

void close_unix_socket(void)
{
	// The process has to take care of unlinking the socket file description on exit
	unlink(FTLfiles.socketfile);
	// Using global variable here
	close(socketfd);
}

void *telnet_connection_handler_thread(void *socket_desc)
{
	//Get the socket descriptor
	int sock = *(int*)socket_desc;
	// Store copy only for displaying the debug messages
	int sockID = sock;
	char client_message[SOCKETBUFFERLEN] = "";

	// Set thread name
	char threadname[16];
	sprintf(threadname,"telnet-%i",sockID);
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
				// Client disconnected by sending EOT or ">quit"
				break;
			}
		}
		else if(n == -1)
		{
			if(debugclients) logg("Telnet connection interrupted (%s), ID: %i", strerror(errno), sockID);
			break;
		}
	}
	if(debugclients)
		logg("Telnet disconnected, ID: %i", sockID);

	//Free the socket pointer
	if(sock != 0)
		close(sock);
	free(socket_desc);

	return 0;
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
	sprintf(threadname,"socket-%i",sockID);
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
				// Socket connection interrupted by sending EOT or ">quit"
				break;
			}
		}
		else if(n == -1)
		{
			if(debugclients) logg("Unix socket connection interrupted (%s), ID: %i", strerror(errno), sockID);
			break;
		}
	}
	if(debugclients) logg("Socket disconnected, ID: %i", sockID);

	//Free the socket pointer
	if(sock != 0)
		close(sock);
	free(socket_desc);

	return 0;
}

void *telnet_listening_thread(void *args)
{
	// We will use the attributes object later to start all threads in detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically released back to
	// the system without the need for another thread to join with the terminated thread
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Set thread name
	prctl(PR_SET_NAME,"telnet listener",0,0,0);

	// Initialize sockets only after initial log parsing in listenting_thread
	bind_to_telnet_port(SOCKET, &telnetfd);

	// Listen as long as FTL is not killed
	while(!killed)
	{
		// Look for new clients that want to connect
		int csck = listener(telnetfd);

		// Allocate memory used to transport client socket ID to client listening thread
		int *newsock;
		newsock = calloc(1,sizeof(int));
		*newsock = csck;

		pthread_t telnet_connection_thread;
		// Create a new thread
		if(pthread_create( &telnet_connection_thread, &attr, telnet_connection_handler_thread, (void*) newsock ) != 0)
		{
			// Log the error code description
			logg("WARNING: Unable to open telnet processing thread, error: %s", strerror(errno));
		}
	}
	return 0;
}

void *socket_listening_thread(void *args)
{
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
	bind_to_unix_socket(&socketfd);

	// Listen as long as FTL is not killed
	while(!killed)
	{
		// Look for new clients that want to connect
		int csck = listener(socketfd);

		// Allocate memory used to transport client socket ID to client listening thread
		int *newsock;
		newsock = calloc(1,sizeof(int));
		*newsock = csck;

		pthread_t socket_connection_thread;
		// Create a new thread
		if(pthread_create( &socket_connection_thread, &attr, socket_connection_handler_thread, (void*) newsock ) != 0)
		{
			// Log the error code description
			logg("WARNING: Unable to open socket processing thread, error: %s", strerror(errno));
		}
	}
	return 0;
}

bool ipv6_available(void)
{
	struct ifaddrs *allInterfaces;
	int iface[2] = { 0 };

	// Get all interfaces
	if (getifaddrs(&allInterfaces) == 0)
	{
		struct ifaddrs *interface;
		// Loop over interfaces
		for (interface = allInterfaces; interface != NULL; interface = interface->ifa_next)
		{
			unsigned int flags = interface->ifa_flags;
			struct sockaddr *addr = interface->ifa_addr;

			// Check only for up and running IPv4, IPv6 interfaces
			if ((flags & (IFF_UP|IFF_RUNNING)) && addr != NULL)
			{
				iface[addr->sa_family == AF_INET6 ? 1 : 0]++;

				// Debug statement that is only executed on TravisCI
				if(travis)
					logg("Interface %s is %s", interface->ifa_name, addr->sa_family == AF_INET6 ? "IPv6" : "IPv4");
			}
		}
		freeifaddrs(allInterfaces);
	}

	if(debug)
	{
		logg("Found %i IPv4 and %i IPv6 capable interfaces", iface[0], iface[1]);
	}

	return (iface[1] > 0);
}
