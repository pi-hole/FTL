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
// sleepms()
#include "../timers.h"
// global variable killed
#include "../signals.h"
// API thread storage
#include "../daemon.h"
#include "../shmem.h"

// The backlog argument defines the maximum length
// to which the queue of pending connections for
// telnetfd may grow. If a connection request arrives
// when the queue is full, the client may receive an
// error with an indication of ECONNREFUSED or, if
// the underlying protocol supports retransmission,
// the request may be ignored so that a later
// reattempt at connection succeeds.
#define BACKLOG 5

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

static int bind_to_telnet_socket(const enum telnet_type type, const char *stype)
{
	const int socketdescriptor = socket(type == TELNET_SOCK ? AF_LOCAL : (type == TELNETv4 ? AF_INET : AF_INET6), SOCK_STREAM, 0);
	if(socketdescriptor < 0)
	{
		logg("Error opening %s telnet socket: %s (%i)", stype, strerror(errno), errno);
		return -1;
	}

	const size_t addrlen = MAX(sizeof(struct sockaddr_un), MAX(sizeof(struct sockaddr_in), sizeof(struct sockaddr_in6)));
	void *address = calloc(1, addrlen);

	if(type == TELNETv4 || type == TELNETv6)
	{
		// Set SO_REUSEADDR to allow re-binding to the port that has been used
		// previously by FTL. A common pattern is that you change FTL's
		// configuration file and need to restart that server to make it reload
		// its configuration. Without SO_REUSEADDR, the bind() call in the restarted
		// new instance will fail if there were connections open to the previous
		// instance when you killed it. Those connections will hold the TCP port in
		// the TIME_WAIT state for 30-120 seconds, so you fall into case 1 above.
		if(setsockopt(socketdescriptor, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) != 0)
			logg("WARN: allowing re-binding (%s) failed: %s", stype, strerror(errno));

		if(type == TELNETv6)
		{
			// If this flag is set to true (nonzero), then the  socket  is  re‐
			// stricted  to  sending  and receiving IPv6 packets only.  In this
			// case, an IPv4 and an IPv6 application can bind to a single  port
			// at the same time.
			if(setsockopt(socketdescriptor, IPPROTO_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int)) != 0)
				logg("WARN: setting socket to IPv6-only failed: %s", strerror(errno));

			if(config.socket_listenlocal)
				((struct sockaddr_in6*) address)->sin6_addr = in6addr_loopback;
			else
				((struct sockaddr_in6*) address)->sin6_addr = in6addr_any;

			// The bind() system call binds a socket to an address,
			// in this case the address of the current host and
			// port number on which the server will run.
			// convert this to network byte order using the function htons()
			// which converts a port number in host byte order to a port number
			// in network byte order

			// Bind to IPv6 socket
			((struct sockaddr_in6*) address)->sin6_family = AF_INET6;
			((struct sockaddr_in6*) address)->sin6_port = htons(config.port);
		}
		else // IPv4
		{

			if(config.socket_listenlocal)
				((struct sockaddr_in*) address)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			else
				((struct sockaddr_in*) address)->sin_addr.s_addr = INADDR_ANY;

			// Bind to IPv4 port
			((struct sockaddr_in*) address)->sin_family = AF_INET;
			((struct sockaddr_in*) address)->sin_port = htons(config.port);
		}
	}
	else // socket
	{
		// Make sure unix socket file handle does not exist, if it exists, remove it
		unlink(FTLfiles.socketfile);

		((struct sockaddr_un*) address)->sun_family = AF_LOCAL;
		// The sockaddr_un.sum_path may be shorter than the size of the FTLfiles.socketfile
		// buffer. Ensure that the string is null-terminated even when the string is too large.
		// In case strlen(FTLfiles.socketfile) < sizeof(address.sun_path) [this will virtually
		// always be the case], the explicit setting of the last byte to zero is a no-op as
		// strncpy() writes additional null bytes to ensure that a total of n bytes are written.
		strncpy(((struct sockaddr_un*) address)->sun_path, FTLfiles.socketfile, sizeof(((struct sockaddr_un*) address)->sun_path));
		((struct sockaddr_un*) address)->sun_path[sizeof(((struct sockaddr_un*) address)->sun_path)-1] = '\0';

	}

	// Bind to socket
	if(bind(socketdescriptor, (struct sockaddr *) address, addrlen) < 0)
	{
		logg("Error listening on Unix socket %s: %s (%i)", FTLfiles.socketfile, strerror(errno), errno);
		return -1;
	}

	// The listen system call allows the process to listen on the socket for connections
	if(listen(socketdescriptor, BACKLOG) == -1)
	{
		logg("Error listening on %s socket: %s (%i)", stype, strerror(errno), errno);
		return -1;
	}

	logg("Listening on port %i for incoming %s telnet connections", config.port, stype);
	return socketdescriptor;
}

static void *telnet_connection_handler_thread(void *args)
{
	struct thread_info *tinfo = args;
	// Set thread name
	char threadname[16] = { 0 };
	snprintf(threadname, sizeof(threadname), "telnet-%s-%i", tinfo->stype, tinfo->tid);
	prctl(PR_SET_NAME, threadname, 0, 0, 0);

	// Ensure this thread can be canceled at any time (not only at
	// cancellation points)
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	if(config.debug & DEBUG_API)
		logg("Started telnet thread %s", threadname);

	// Listen as long as this thread is not canceled
	int errors = 0;
	while(!killed)
	{
		// Look for new clients that want to connect
		const int csck = accept(tinfo->fd, NULL, NULL);
		if(csck == -1)
		{
			logg("Telnet error in %s: %s (%i, fd: %d)", threadname, strerror(errno), errno, tinfo->fd);
			if(errors++ > 20)
				break;
			sleepms(100);
			continue;
		}

		// Define buffer for client's message
		char client_message[SOCKETBUFFERLEN] ={ 0 };

		// Receive from client
		ssize_t n;
		while((n = recv(csck, client_message, SOCKETBUFFERLEN-1, 0)))
		{
			if (n > 0 && n < SOCKETBUFFERLEN)
			{
				// Null-terminate client string
				client_message[n] = '\0';
				char *message = strdup(client_message);
				if(message == NULL)
				{
					if(config.debug & DEBUG_API)
						logg("Break in telnet thread for socket %d/%d: Memory error", tinfo->fd, csck);
					break;
				}

				// Clear client message receive buffer
				memset(client_message, 0, sizeof client_message);

				// Process received message
				const bool eom = process_request(message, csck, tinfo->istelnet);
				free(message);
				if(eom) break;
			}
			else if(n == -1)
			{
				if(config.debug & DEBUG_API)
					logg("Break in telnet thread for socket %d/%d: No data received", tinfo->fd, csck);
				break;
			}
		}

		// Close client socket
		close(csck);
	}

	if(config.debug & DEBUG_API)
		logg("Terminating telnet thread %s (%d errors)", threadname, errors);

	// Free thread-private memory
	free(tinfo);
	return NULL;
}

void listen_telnet(const enum telnet_type type)
{
	// We will use the attributes object later to start all threads in detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);
	// When a detached thread terminates, its resources are automatically released back to
	// the system without the need for another thread to join with the terminated thread
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	// Initialize telnet socket
	const char *stype = type == TELNET_SOCK ? "socket" : (type == TELNETv4 ? "IPv4" : "IPv6");
	const int fd = bind_to_telnet_socket(type, stype);
	if(fd < 0)
	{
		logg("WARN: Cannot bind to %s telnet socket", stype);
		return;
	}

	if(config.debug & DEBUG_API)
		logg("Telnet-%s listener accepting on fd %d", stype, fd);

	for(unsigned int i = 0; i < MAX_API_THREADS; i++)
	{
		// Spawn telnet thread
		// Create a private copy of the socket fd for the child thread
		struct thread_info *tinfo = calloc(1, sizeof(struct thread_info));
		if(!tinfo)
			continue;

		tinfo->fd = fd;
		tinfo->tid = i;
		tinfo->istelnet = (type == TELNETv4 || type == TELNETv6);
		tinfo->stype = stype;
		if(pthread_create(&api_threads[i], &attr, telnet_connection_handler_thread, (void*) tinfo) != 0)
		{
			// Log the error code description
			logg("WARNING: Unable to open telnet processing thread: %s", strerror(errno));
		}
	}
}

void seom(const int sock, const bool istelnet)
{
	if(istelnet)
		ssend(sock, "---EOM---\n\n");
	else
		pack_eom(sock);
}

bool __attribute__ ((format (gnu_printf, 5, 6))) _ssend(const int sock, const char *file, const char *func, const int line, const char *format, ...)
{
	char *buffer;
	va_list args;
	va_start(args, format);
	int bytes = vasprintf(&buffer, format, args);
	va_end(args);
	if(bytes > 0 && buffer != NULL)
	{
		FTLwrite(sock, buffer, bytes, short_path(file), func, line);
		free(buffer);
	}
	return errno == 0;
}
