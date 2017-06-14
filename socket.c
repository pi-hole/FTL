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
int socketfd, apifd;

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
	*socketdescriptor = socket(AF_INET, SOCK_STREAM, 0);

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

	struct sockaddr_in serv_addr;
	// set all values in the buffer to zero
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;

	if(config.socket_listenlocal && type == SOCKET)
		serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else
		serv_addr.sin_addr.s_addr = INADDR_ANY;

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
		case API:
			port_init = 4747;
			break;
		default:
			logg("Incompatible socket type %i", (int)type);
			exit(EXIT_FAILURE);
			break;
	}

	bool bound = false;
	for(port = port_init; port <= (port_init + 20); port++)
	{
		serv_addr.sin_port = htons(port);
		if(bind(*socketdescriptor, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		{
			logg("Error on binding on port %i", port);
		}
		else
		{
			bound = true;
			break;
		}
	}

	if(!bound)
	{
		logg("Error listening on any port");
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
	switch(type)
	{
		case SOCKET:
			logg("Listening on port %i for incoming socket connections", port);
			break;
		case API:
			logg("Listening on port %i for incoming API connections", port);
			break;
		default:
			/* That cannot happen */
			break;
	}
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

void seom(int sock)
{
	ssend(sock, "---EOM---\n\n");
}

void ssend(int sock, const char *format, ...)
{
	char *buffer;
	va_list args;
	va_start(args, format);
	int ret = vasprintf(&buffer, format, args);
	va_end(args);
	if(ret > 0)
		if(!write(sock, buffer, strlen(buffer)))
			logg("WARNING: Socket write returned error code %i", errno);
}

int listener(int sockfd)
{
	struct sockaddr_in cli_addr;
	// set all values in the buffer to zero
	memset(&cli_addr, 0, sizeof(cli_addr));
	socklen_t clilen = sizeof(cli_addr);
	int clientsocket = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

	if(debugclients)
		logg("Client connected: %s, ID: %i", inet_ntoa (cli_addr.sin_addr), clientsocket);

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
		case API:
			close(apifd);
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

			process_socket_request(message, &sock);
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

void *socket_listening_thread(void *args)
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

	// Initialize sockets only after initial log parsing in listening_thread
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
			logg("WARNING: Unable to open client socket thread, error: %s", strerror(errno));
		}
	}
	return 0;
}

void *api_connection_handler_thread(void *socket_desc)
{
	//Get the socket descriptor
	int sock = *(int*)socket_desc;
	// Store copy only for displaying the debug messages
	int sockID = sock;
	char client_message[SOCKETBUFFERLEN] = "";

	// Set thread name
	char threadname[16];
	sprintf(threadname,"api-%i",sockID);
	prctl(PR_SET_NAME,threadname,0,0,0);

	//Receive from client
	if(recv(sock, client_message, SOCKETBUFFERLEN-1, 0) > 0)
	{
		char *message = calloc(strlen(client_message)+1,sizeof(char));
		strcpy(message, client_message);

		// Clear client message receive buffer
		memset(client_message, 0, sizeof client_message);

		if(strncmp(message, "GET ", 4) == 0)
		{
			if(debug)
				logg("API GET request received");
			// HTTP requests can be simple or full.
			// A simple request contains one line only, and looks like this:
			//   GET /index.html
			// A full request can contain more than one line and may look like this:
			//   GET /index.html HTTP/1.1
			//   User-Agent: Wget/1.16 (linux-gnueabihf)
			//   Accept: */*
			//   Host: 127.0.0.1:4747
			//   Connection: Keep-Alive
			bool header = false;

			// Extract requested URL including arguments
			const char *p2;
			if(strstr(message, "HTTP/") != NULL)
			{
				// Output HTTP response headers only if we have a full request
				header = true;
				// End of request = "HTTP/"
				p2 = strstr(message, " HTTP/");
			}
			else
			{
				// End of requst = end of first line
				p2 = strstr(message, "\n");
			}
			if(p2 != NULL)
			{
				size_t len = p2 - message;
				char *request = calloc(len+1, sizeof(char));
				strncpy(request, message, len);
				request[len] = '\0';
				logg("request: \"%s\" (%i)", request, (int)len);

				// Are we asked for a favicon?
				if(strstr(request, "/favicon.ico") != NULL)
					ssend(sock, "HTTP/1.0 404 Not Found\nServer: FTL\n\n");
				else
					process_api_request(request, &sock, header);

				// Free allocated memory
				free(request);
			}
			else
			{
				logg("API received malformated request: \"%s\"", message);
			}

			// Close connection to show that we reached the end of the transmission
			close(sock);
			sock = 0;
		}
		else if(strncmp(message, "HEAD ", 5) == 0)
		{
			// HEAD request: We do not send any content at all
			if(debug)
				logg("API HEAD request received");

			ssend(sock, "HTTP/1.0 200 OK\nServer: FTL\n\n");

			// Close connection to show that we reached the end of the transmission
			close(sock);
			sock = 0;
		}
		else
		{
			if(debug)
				logg("API received something strange");
		}

		// Free allocated memory
		free(message);
	}

	//Free the socket pointer
	if(sock != 0)
		close(sock);
	free(socket_desc);

	return 0;
}

void *api_listening_thread(void *args)
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
	prctl(PR_SET_NAME,"API listener",0,0,0);

	// Initialize sockets only after initial log parsing in listening_thread
	bind_to_port(API, &apifd);

	// Listen as long as FTL is not killed
	while(!killed)
	{
		// Look for new clients that want to connect
		int csck = listener(apifd);

		// Allocate memory used to transport client socket ID to client listening thread
		newsock = calloc(1,sizeof(int));
		*newsock = csck;

		pthread_t api_connection_thread;
		// Create a new thread
		if(pthread_create( &api_connection_thread, &attr, api_connection_handler_thread, (void*) newsock ) != 0)
		{
			// Log the error code description
			logg("WARNING: Unable to open client API thread, error: %s", strerror(errno));
		}
	}
	return 0;
}
