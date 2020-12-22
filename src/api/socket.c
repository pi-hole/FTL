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
#include "api.h"
#include "../log.h"
#include "socket.h"
#include "request.h"
#include "../config.h"
// global variable killed
#include "../signals.h"

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
int socketfd = 0, telnetfd4 = 0, telnetfd6 = 0;
bool dualstack = false;
bool ipv4telnet = false, ipv6telnet = false, sock_avail = false;
bool istelnet[MAXCONNS];

void saveport(int port)
{
	FILE *f;
	// Open "w" for truncation/creating file
	if((f = fopen(FTLfiles.port, "w")) == NULL)
	{
		// Opening failed (permissions, path does not exist, etc.)
		logg("WARNING: Unable to write used port to file");
		logg("         (API might not find the port)");
	}
	else if(port > 0)
	{
		// Save port to file
		fprintf(f, "%i", port);
		fclose(f);
	}
	else
	{
		// FTL is terminating: Leave file truncated
		fclose(f);
	}
}

static bool bind_to_telnet_port_IPv4(int *socketdescriptor)
{
	// IPv4 socket
	*socketdescriptor = socket(AF_INET, SOCK_STREAM, 0);

	if(*socketdescriptor < 0)
	{
		logg("Error opening IPv4 telnet socket: %s (%i)", strerror(errno), errno);
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

	struct sockaddr_in serv_addr4;
	// set all values in the buffer to zero
	memset(&serv_addr4, 0, sizeof(serv_addr4));
	serv_addr4.sin_family = AF_INET;

	if(config.socket_listenlocal)
		serv_addr4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else
		serv_addr4.sin_addr.s_addr = INADDR_ANY;

	// Bind to IPv4 port
	serv_addr4.sin_port = htons(config.port);
	if(bind(*socketdescriptor, (struct sockaddr *) &serv_addr4, sizeof(serv_addr4)) < 0)
	{
		logg("Error listening on IPv4 port %i: %s (%i)", config.port, strerror(errno), errno);
		return false;
	}

	// The listen system call allows the process to listen on the socket for connections
	if(listen(*socketdescriptor, BACKLOG) == -1)
	{
		logg("Error listening on IPv4 socket: %s (%i)", strerror(errno), errno);
		return false;
	}

	logg("Listening on port %i for incoming IPv4 telnet connections", config.port);
	return true;
}

static bool bind_to_telnet_port_IPv6(int *socketdescriptor)
{
	// IPv6 socket
	*socketdescriptor = socket(AF_INET6, SOCK_STREAM, 0);

	if(*socketdescriptor < 0)
	{
		logg("Error opening IPv6 telnet socket: %s (%i)", strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	// If this flag is set to true (nonzero), then the  socket  is  re‐
	// stricted  to  sending  and receiving IPv6 packets only.  In this
	// case, an IPv4 and an IPv6 application can bind to a single  port
	// at the same time.
	setsockopt(*socketdescriptor, IPPROTO_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int));

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

	if(config.socket_listenlocal)
		serv_addr.sin6_addr = in6addr_loopback;
	else
		serv_addr.sin6_addr = in6addr_any;

	// The bind() system call binds a socket to an address,
	// in this case the address of the current host and
	// port number on which the server will run.
	// convert this to network byte order using the function htons()
	// which converts a port number in host byte order to a port number
	// in network byte order

	// Bind to IPv6 socket
	serv_addr.sin6_port = htons(config.port);
	if(bind(*socketdescriptor, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		logg("Error listening on IPv6 port %i: %s (%i)", config.port, strerror(errno), errno);
		return false;
	}

	// The listen system call allows the process to listen on the socket for connections
	if(listen(*socketdescriptor, BACKLOG) == -1)
	{
		logg("Error listening on IPv6 socket: %s (%i)", strerror(errno), errno);
		return false;
	}

	logg("Listening on port %i for incoming IPv6 telnet connections", config.port);
	return true;
}

static bool bind_to_unix_socket(int *socketdescriptor)
{
	*socketdescriptor = socket(AF_LOCAL, SOCK_STREAM, 0);

	if(*socketdescriptor < 0)
	{
		logg("WARNING: Error opening Unix socket.");
		return false;
	}

	// Make sure unix socket file handle does not exist, if it exists, remove it
	unlink(FTLfiles.socketfile);

	struct sockaddr_un address;
	address.sun_family = AF_LOCAL;
	// The sockaddr_un.sum_path may be shorter than the size of the
	// FTLfiles.socketfile buffer
	strncpy(address.sun_path, FTLfiles.socketfile, sizeof(address.sun_path)-1);
	address.sun_path[sizeof(address.sun_path)-1] = '\0';

	// Bind to Unix socket handle
	errno = 0;
	if(bind(*socketdescriptor, (struct sockaddr *) &address, sizeof (address)) != 0)
	{
		logg("WARNING: Cannot bind on Unix socket %s: %s (%i)", FTLfiles.socketfile, strerror(errno), errno);
		return false;
	}

	// The listen system call allows the process to listen on the Unix socket for connections
	if(listen(*socketdescriptor, BACKLOG) == -1)
	{
		logg("WARNING: Cannot listen on Unix socket: %s (%i)", strerror(errno), errno);
		return false;
	}

	logg("Listening on Unix socket");
	return true;
}

void seom(const int sock)
{
	if(istelnet[sock])
		ssend(sock, "---EOM---\n\n");
	else
		pack_eom(sock);
}

void __attribute__ ((format (gnu_printf, 2, 3))) ssend(const int sock, const char *format, ...)
{
	char *buffer;
	va_list args;
	va_start(args, format);
	int bytes = vasprintf(&buffer, format, args);
	va_end(args);
	if(bytes > 0 && buffer != NULL)
	{
		write(sock, buffer, bytes);
		free(buffer);
	}
}

static inline int checkClientLimit(const int socket) {
	if(socket < MAXCONNS)
	{
		return socket;
	}
	else
	{
		logg("Client denied (at max capacity of %i): %i", MAXCONNS, socket);

		close(socket);
		return -1;
	}
}

static int listener(const int sockfd, const char type)
{
	struct sockaddr_un un_addr;
	struct sockaddr_in in4_addr;
	struct sockaddr_in6 in6_addr;
	socklen_t socklen = 0;
	int socket;

	switch(type)
	{
		case 0: // Unix socket
			memset(&un_addr, 0, sizeof(un_addr));
			socklen = sizeof(un_addr);
			return accept(sockfd, (struct sockaddr *) &un_addr, &socklen);

		case 4: // Internet socket (IPv4)
			memset(&in4_addr, 0, sizeof(in4_addr));
			socklen = sizeof(un_addr);
			socket = accept(sockfd, (struct sockaddr *) &in4_addr, &socklen);
			return checkClientLimit(socket);

		case 6: // Internet socket (IPv6)
			memset(&in6_addr, 0, sizeof(in6_addr));
			socklen = sizeof(un_addr);
			socket = accept(sockfd, (struct sockaddr *) &in6_addr, &socklen);
			return checkClientLimit(socket);

		default: // Should not happen
			logg("Cannot listen on type %i connection, code error!", type);
			exit(EXIT_FAILURE);
	}
}

void close_telnet_socket(void)
{
	// Using global variable here
	if(telnetfd4)
		close(telnetfd4);
	if(telnetfd6)
		close(telnetfd6);
}

void close_unix_socket(bool unlink_file)
{
	if(unlink_file)
	{
		// The process has to take care of unlinking the socket file description on exit
		unlink(FTLfiles.socketfile);
	}

	// Using global variable here
	if(sock_avail)
		close(socketfd);
}

static void *telnet_connection_handler_thread(void *socket_desc)
{
	//Get the socket descriptor
	int sock = *(int*)socket_desc;
	// Set connection type to telnet
	istelnet[sock] = true;

	// Define buffer for client's message
	char client_message[SOCKETBUFFERLEN] = "";

	// Set thread name
	char threadname[16];
	sprintf(threadname,"telnet-%i",sock);
	prctl(PR_SET_NAME,threadname,0,0,0);
	//Receive from client
	ssize_t n;
	while((n = recv(sock,client_message,SOCKETBUFFERLEN-1, 0)))
	{
		if (n > 0)
		{
			char *message = strdup(client_message);
			if(message == NULL) break;

			// Clear client message receive buffer
			memset(client_message, 0, sizeof client_message);

			// Process received message
			process_request(message, &sock);
			free(message);

			if(sock == 0)
			{
				// Client disconnected by sending EOT or ">quit"
				break;
			}
		}
		else if(n == -1)
		{
			break;
		}
	}

	//Free the socket pointer
	if(sock != 0)
		close(sock);
	free(socket_desc);

	return false;
}


static void *socket_connection_handler_thread(void *socket_desc)
{
	//Get the socket descriptor
	int sock = *(int*)socket_desc;
	// Set connection type to not telnet
	istelnet[sock] = false;

	// Define buffer for client's message
	char client_message[SOCKETBUFFERLEN] = "";

	// Set thread name
	char threadname[16];
	sprintf(threadname,"socket-%i",sock);
	prctl(PR_SET_NAME,threadname,0,0,0);

	// Receive from client
	ssize_t n;
	while((n = recv(sock,client_message,SOCKETBUFFERLEN-1, 0)))
	{
		if (n > 0)
		{
			char *message = strdup(client_message);
			if(message == NULL) break;

			// Clear client message receive buffer
			memset(client_message, 0, sizeof client_message);

			// Process received message
			process_request(message, &sock);
			free(message);

			if(sock == 0)
			{
				// Socket connection interrupted by sending EOT or ">quit"
				break;
			}
		}
		else if(n == -1)
		{
			break;
		}
	}

	//Free the socket pointer
	if(sock != 0)
		close(sock);
	free(socket_desc);

	return false;
}

void *telnet_listening_thread_IPv4(void *args)
{
	// We will use the attributes object later to start all threads in detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically released back to
	// the system without the need for another thread to join with the terminated thread
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Set thread name
	prctl(PR_SET_NAME,"telnet-IPv4",0,0,0);

	// Initialize IPv4 telnet socket
	ipv4telnet = bind_to_telnet_port_IPv4(&telnetfd4);
	if(!ipv4telnet)
		return NULL;

	// Listen as long as FTL is not killed
	while(!killed)
	{
		// Look for new clients that want to connect
		const int csck = listener(telnetfd4, 4);
		if(csck == -1)
		{
			logg("IPv4 telnet error: %s (%i)", strerror(errno), errno);
			continue;
		}

		// Allocate memory used to transport client socket ID to client listening thread
		int *newsock;
		newsock = calloc(1,sizeof(int));
		if(newsock == NULL) break;
		*newsock = csck;

		pthread_t telnet_connection_thread;
		// Create a new thread
		if(pthread_create( &telnet_connection_thread, &attr, telnet_connection_handler_thread, (void*) newsock ) != 0)
		{
			// Log the error code description
			logg("WARNING: Unable to open telnet processing thread: %s", strerror(errno));
		}
	}
	return false;
}

void *telnet_listening_thread_IPv6(void *args)
{
	// We will use the attributes object later to start all threads in detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically released back to
	// the system without the need for another thread to join with the terminated thread
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Set thread name
	prctl(PR_SET_NAME,"telnet-IPv6",0,0,0);

	// Initialize IPv6 telnet socket but only if IPv6 interfaces are available
	if(!ipv6_available())
		return NULL;

	ipv6telnet = bind_to_telnet_port_IPv6(&telnetfd6);
	if(!ipv6telnet)
		return NULL;

	// Listen as long as FTL is not killed
	while(!killed)
	{
		// Look for new clients that want to connect
		const int csck = listener(telnetfd6, 6);
		if(csck == -1)
		{
			logg("IPv6 telnet error: %s (%i)", strerror(errno), errno);
			continue;
		}

		// Allocate memory used to transport client socket ID to client listening thread
		int *newsock;
		newsock = calloc(1,sizeof(int));
		if(newsock == NULL) break;
		*newsock = csck;

		pthread_t telnet_connection_thread;
		// Create a new thread
		if(pthread_create( &telnet_connection_thread, &attr, telnet_connection_handler_thread, (void*) newsock ) != 0)
		{
			// Log the error code description
			logg("WARNING: Unable to open telnet processing thread: %s", strerror(errno));
		}
	}
	return false;
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

	// Return early to avoid CPU spinning if Unix socket is not available
	sock_avail = bind_to_unix_socket(&socketfd);
	if(!sock_avail)
	{
		logg("INFO: Unix socket will not be available");
		return NULL;
	}

	// Listen as long as FTL is not killed
	while(!killed)
	{
		// Look for new clients that want to connect
		const int csck = listener(socketfd, 0);
		if(csck < 0)
			continue;

		// Allocate memory used to transport client socket ID to client listening thread
		int *newsock;
		newsock = calloc(1,sizeof(int));
		if(newsock == NULL) break;
		*newsock = csck;

		pthread_t socket_connection_thread;
		// Create a new thread
		if(pthread_create( &socket_connection_thread, &attr, socket_connection_handler_thread, (void*) newsock ) != 0)
		{
			// Log the error code description
			logg("WARNING: Unable to open socket processing thread: %s", strerror(errno));
		}
	}
	return false;
}

bool ipv6_available(void)
{
	struct ifaddrs *allInterfaces;
	enum { IPv4, IPv6 };
	int iface[2] = { 0 };

	// Get all interfaces
	if (getifaddrs(&allInterfaces) == 0)
	{
		struct ifaddrs *interface;
		// Loop over interfaces
		for (interface = allInterfaces; interface != NULL; interface = interface->ifa_next)
		{
			const unsigned int flags = interface->ifa_flags;
			const struct sockaddr *addr = interface->ifa_addr;

			// Check only for up and running IPv4, IPv6 interfaces
			if ((flags & (IFF_UP|IFF_RUNNING)) && addr != NULL)
			{
				iface[addr->sa_family == AF_INET6 ? IPv6 : IPv4]++;

				if(config.debug & DEBUG_NETWORKING)
					logg("Interface %s is %s", interface->ifa_name, addr->sa_family == AF_INET6 ? "IPv6" : "IPv4");
			}
		}
		freeifaddrs(allInterfaces);
	}

	if(config.debug & DEBUG_NETWORKING)
	{
		logg("Found %i IPv4 and %i IPv6 capable interfaces", iface[IPv4], iface[IPv6]);
	}

	return (iface[IPv6] > 0);
}
