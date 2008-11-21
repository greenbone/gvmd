/* OpenVAS Manager
 * $Id$
 * Description: Main module for OpenVAS Manager: the system daemon.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2008 Intevation GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/** @file openvasmd.c
 *  \brief The OpenVAS Manager
 *
 *  This file defines the OpenVAS Manager, a daemon that is layered between
 *  the real OpenVAS Server (openvasd) and a client (e.g.
 *  OpenVAS-Client).
 */

/** \mainpage
 *
 *  \section Introduction
 *  \verbinclude README
 *
 *  \section manpages Manual Pages
 *  \subpage manpage
 *
 *  \section Installation
 *  \verbinclude INSTALL
 *
 *  \section Implementation
 *  \ref openvasmd.c
 */

/** \page manpage openvasmd
 *  \htmlinclude openvasmd.html
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openvas/network.h>
#include <openvas/plugutils.h>

/** The name of this program.
 * \todo Use `program_invocation[_short]_name'? */
#define PROGNAME "openvasmd"

/** The version number of this program. */
#ifndef OPENVASMD_VERSION
#define OPENVASMD_VERSION "FIX"
#endif

/** The name of the underlying Operating System. */
#ifndef OPENVAS_OS_NAME
#define OPENVAS_OS_NAME "FIX"
#endif

/** Manager (openvasmd) address. */
#define OPENVASMD_ADDRESS "127.0.0.1"

/** Server (openvasd) address. */
#define OPENVASD_ADDRESS "127.0.0.1"

/** Location of server certificate. */
#ifndef SERVERCERT
#define SERVERCERT "/var/lib/openvas/CA/servercert.pem"
#endif

/** Location of server certificate private key. */
#ifndef SERVERKEY
#define SERVERKEY  "/var/lib/openvas/private/CA/serverkey.pem"
#endif

/** Location of Certificate Authority certificate. */
#ifndef CACERT
#define CACERT     "/var/lib/openvas/CA/cacert.pem"
#endif

/** Server port.  Used if /etc/services "openvas" and -port missing. */
#define OPENVASD_PORT 1241

/** Manager port.  Used if /etc/services "omp" and -sport are missing. */
#define OPENVASMD_PORT 1241

/** The size of the data buffers.  When the client/server buffer is full
  * `select' stops watching for input from the client/server.
  */
#define BUFFER_SIZE 2048

/** Second argument to `listen'. */
#define MAX_CONNECTIONS 512

/** Logging flag.  All data transfered to and from the client is logged to
  * a file.  If 0 then logging is turned off.
  */
#define LOG 1

/** Name of log file. */
#define LOG_FILE "/tmp/openvasmd.log"

/** Trace flag.  0 to turn off all tracing messages. */
#define TRACE 0

/** Trace text flag.  0 to turn off echoing of actual data transfered
  * (requires TRACE). */
#define TRACE_TEXT 1

/** Security flag.  0 to turn off all security (i.e. TLS). */
#define OVAS_SSL 1

#if OVAS_SSL
#include <gnutls/gnutls.h>
#endif

#if BUFFER_SIZE > SSIZE_MAX
#error BUFFER_SIZE too big for `read'
#endif

#if TRACE
/** Formatted trace output.
  * Prints the printf style \a args to stderr, preceded by the process ID. */
#define tracef(args...)                   \
  do {                                    \
    fprintf (stderr, "%7i  ", getpid());  \
    fprintf (stderr, args);               \
    fflush (stderr);                      \
  } while (0);
#else
/** Dummy macro, enabled with TRACE. */
#define tracef(format, args...)
#endif

#if LOG
/** Formatted logging output.
  * Prints the printf style \a args to log_stream, preceded by the process ID. */
#define logf(args...)                         \
  do {                                        \
    fprintf (log_stream, "%7i  ", getpid());  \
    fprintf (log_stream, args);               \
    fflush (log_stream);                      \
  } while (0);
#else
/** Dummy macro, enabled with LOG. */
#define logf(format, args...)
#endif

/** The socket accepting OMP connections from clients. */
int manager_socket = -1;

/** The IP address of this program, "the manager". */
struct sockaddr_in manager_address;

/** The IP address of openvasd, "the server". */
struct sockaddr_in server_address;

#if LOG
/** The log stream. */
FILE* log_stream = NULL;
#endif

#if OVAS_SSL
/* The server context. */
static ovas_server_context_t server_context = NULL;
#endif

/** File descriptor set mask: selecting on client read. */
#define CLIENT_READ  1
/** File descriptor set mask: selecting on client write. */
#define CLIENT_WRITE 2
/** File descriptor set mask: selecting on server read. */
#define SERVER_READ  4
/** File descriptor set mask: selecting on server write. */
#define SERVER_WRITE 8

/** Serve the OMP protocol.
  *
  * Connect to the openvasd server, then pass all messages from the client
  * to the server, and vice versa.
  *
  * @param[in]  client_socket  The socket connected to the client.
  *
  * \return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
  */
int
serve_omp (int client_socket)
{
  int ret;
  char from_client[BUFFER_SIZE];
  char from_server[BUFFER_SIZE];
  int from_client_end = 0, from_server_end = 0;
  int from_client_start = 0, from_server_start = 0;
  int server_socket;

  /* Make the server socket. */
  server_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (server_socket == -1)
    {
      perror ("Failed to create server socket");
      return EXIT_FAILURE;
    }

#if OVAS_SSL
  /* Setup server session. */

  gnutls_certificate_credentials_t server_credentials;
  if (gnutls_certificate_allocate_credentials (&server_credentials))
    {
      fprintf (stderr, "Failed to allocate server credentials.\n");
      goto close_fail;
    }

  gnutls_session_t server_session;
  if (gnutls_init (&server_session, GNUTLS_CLIENT))
    {
      fprintf (stderr, "Failed to initialise server session.\n");
      goto server_free_fail;
    }

  if (gnutls_set_default_priority (server_session))
    {
      fprintf (stderr, "Failed to set server session priority.\n");
      goto server_fail;
    }

  const int kx_priority[] = { GNUTLS_KX_DHE_RSA,
                              GNUTLS_KX_RSA,
                              GNUTLS_KX_DHE_DSS,
                              0 };
  if (gnutls_kx_set_priority (server_session, kx_priority))
    {
      fprintf (stderr, "Failed to set server key exchange priority.\n");
      goto server_fail;
    }

  if (gnutls_credentials_set (server_session,
                              GNUTLS_CRD_CERTIFICATE,
                              server_credentials))
    {
      fprintf (stderr, "Failed to set server key exchange priority.\n");
      goto server_fail;
    }
#endif

  /* Connect to the server. */
  if (connect (server_socket,
               (struct sockaddr *) &server_address,
               sizeof (server_address))
      == -1)
    {
      perror ("Failed to connect to server");
      goto server_fail;
    }
  tracef ("Connected to server on socket %i.\n", server_socket);

#if OVAS_SSL
  /* Complete setup of server session. */

  gnutls_transport_set_ptr (server_session,
                            (gnutls_transport_ptr_t) server_socket);

 retry:
  ret = gnutls_handshake (server_session);
  if (ret < 0)
    {
      if (ret == GNUTLS_E_AGAIN
          || ret == GNUTLS_E_INTERRUPTED
          || errno == EAGAIN
          || errno == EINTR)
        goto retry;
      fprintf (stderr, "Failed to shake hands with server.\n");
      gnutls_perror (ret);
      if (shutdown (server_socket, SHUT_RDWR) == -1)
        perror ("Failed to shutdown server socket");
      goto server_fail;
    }
#endif

  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (server_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set server socket flag");
      goto fail;
    }

#if OVAS_SSL
  /* Get client socket and session from libopenvas. */

  int real_socket = nessus_get_socket_from_connection (client_socket);
  if (real_socket == -1 || real_socket == client_socket)
    {
      perror ("Failed to get client socket from libopenvas");
      goto fail;
    }

  gnutls_session_t* client_session = ovas_get_tlssession_from_connection(client_socket);
  if (client_session == NULL)
    {
      perror ("Failed to get connection from client socket");
      goto fail;
    }
  client_socket = real_socket;

  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set real client socket flag");
      goto fail;
    }
  gnutls_transport_set_lowat (*client_session, 0);
#endif

  /* Loop handling input from the sockets. */
  int nfds = 1 + (client_socket > server_socket
                  ? client_socket : server_socket);
  fd_set readfds, exceptfds, writefds;
  while (1)
    {
      /* Setup for select. */
      unsigned char fds = 0; /* What `select' is going to watch. */
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_SET (client_socket, &exceptfds);
      FD_SET (server_socket, &exceptfds);
      if (from_client_end < BUFFER_SIZE)
        {
          FD_SET (client_socket, &readfds);
          fds |= CLIENT_READ;
        }
      if (from_server_end < BUFFER_SIZE)
        {
          FD_SET (server_socket, &readfds);
          fds |= SERVER_READ;
        }
      if (from_server_start < from_server_end)
        {
          FD_SET (client_socket, &writefds);
          fds |= CLIENT_WRITE;
        }
      if (from_client_start < from_client_end)
        {
          FD_SET (server_socket, &writefds);
          fds |= SERVER_WRITE;
        }

      /* Select, then handle result. */
      ret = select (nfds, &readfds, &writefds, &exceptfds, NULL);
      if (ret < 0)
        {
          if (errno == EINTR) continue;
          perror ("Child select failed");
          goto fail;
        }
      if (ret > 0)
        {
          if (FD_ISSET (client_socket, &exceptfds))
            {
              fprintf (stderr, "Exception on client in child select.\n");
              goto fail;
            }

          if (FD_ISSET (server_socket, &exceptfds))
            {
              fprintf (stderr, "Exception on server in child select.\n");
              goto fail;
            }

          if (fds & CLIENT_READ && FD_ISSET (client_socket, &readfds))
            {
#if TRACE || LOG
              int initial_start = from_client_end;
#endif
              /* Read as much as possible from the client. */
              while (from_client_end < BUFFER_SIZE)
                {
                  ssize_t count;
#if OVAS_SSL
                  count = gnutls_record_recv (*client_session,
                                              from_client + from_client_end,
                                              BUFFER_SIZE
                                              - from_client_end);
#else
                  count = read (client_socket,
                                from_client + from_client_end,
                                BUFFER_SIZE - from_client_end);
#endif
                  if (count < 0)
                    {
#if OVAS_SSL
                      if (count == GNUTLS_E_AGAIN || errno == EAGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (count == GNUTLS_E_INTERRUPTED || errno == EINTR)
                        /* Interrupted, try read again. */
                        continue;
                      if (errno == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to read from client.\n");
                      gnutls_perror (count);
#else
                      if (errno == EAGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (errno == EINTR)
                        /* Interrupted, try read again. */
                        continue;
                      perror ("Failed to read from client");
#endif
                      goto fail;
                    }
                  if (count == 0)
                    /* End of file. */
                    goto succeed;
                  from_client_end += count;
                }
#if TRACE || LOG
              /* This check prevents output in the "asynchronous network
                 error" case. */
              if (from_client_end > initial_start)
                {
                  logf ("<= %.*s\n",
                        from_client_end - initial_start,
                        from_client + initial_start);
#if TRACE_TEXT
                  tracef ("<= client  \"%.*s\"\n",
                          from_client_end - initial_start,
                          from_client + initial_start);
#else
                  tracef ("<= client  %i bytes\n",
                          from_client_end - initial_start);
#endif
                }
#endif /* TRACE || LOG */
            }

          if (fds & SERVER_WRITE && FD_ISSET (server_socket, &writefds))
            {
              /* Write as much as possible to the server. */
              while (from_client_start < from_client_end)
                {
                  ssize_t count;
#if OVAS_SSL
                  count = gnutls_record_send (server_session,
                                              from_client + from_client_start,
                                              from_client_end - from_client_start);
#else
                  count = write (server_socket,
                                 from_client + from_client_start,
                                 from_client_end - from_client_start);
#endif
                  if (count < 0)
                    {
#if OVAS_SSL
                      if (count == GNUTLS_E_AGAIN || errno == EAGAIN)
                        /* Wrote as much as possible, return to `select'. */
                        goto end_server_write;
                      if (count == GNUTLS_E_INTERRUPTED || errno == EINTR)
                        /* Interrupted, try write again. */
                        continue;
                      if (errno == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to write to server.\n");
                      gnutls_perror (count);
#else
                      if (errno == EAGAIN)
                        /* Wrote as much as possible, return to `select'. */
                        goto end_server_write;
                      if (errno == EINTR)
                        /* Interrupted, try write again. */
                        continue;
                      perror ("Failed to write to server");
#endif
                      goto fail;
                    }
                  from_client_start += count;
                  tracef ("=> server  %i bytes\n", count);
                }
              tracef ("=> server  done\n");
              from_client_start = from_client_end = 0;
             end_server_write:
              ;
            }

          if (fds & SERVER_READ && FD_ISSET (server_socket, &readfds))
            {
#if TRACE
              int initial_start = from_server_end;
#endif
              /* Read as much as possible from the server. */
              while (from_server_end < BUFFER_SIZE)
                {
                  ssize_t count;
#if OVAS_SSL
                  count = gnutls_record_recv (server_session,
                                              from_server + from_server_end,
                                              BUFFER_SIZE
                                              - from_server_end);
#else
                  count = read (server_socket,
                                from_server + from_server_end,
                                BUFFER_SIZE - from_server_end);
#endif
                  if (count < 0)
                    {
#if OVAS_SSL
                      if (count == GNUTLS_E_AGAIN || errno == EAGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (count == GNUTLS_E_INTERRUPTED || errno == EINTR)
                        /* Interrupted, try read again. */
                        continue;
                      if (errno == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to read to server.\n");
                      gnutls_perror (count);
#else
                      if (errno == EAGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (errno == EINTR)
                        /* Interrupted, try read again. */
                        continue;
                      perror ("Failed to read from server");
#endif
                      goto fail;
                    }
                  if (count == 0)
                    /* End of file. */
                    goto succeed;
                  from_server_end += count;
                }
#if TRACE
              /* This check prevents output in the "asynchronous network
                 error" case. */
              if (from_server_end > initial_start)
                {
#if TRACE_TEXT
                  tracef ("<= server  \"%.*s\"\n",
                          from_server_end - initial_start,
                          from_server + initial_start);
#else
                  tracef ("<= server  %i bytes\n",
                          from_server_end - initial_start);
#endif
                }
#endif /* TRACE */
            }

          if (fds & CLIENT_WRITE && FD_ISSET (client_socket, &writefds))
            {
              /* Write as much as possible to the client. */
              while (from_server_start < from_server_end)
                {
                  ssize_t count;
#if OVAS_SSL
                  count = gnutls_record_send (*client_session,
                                              from_server + from_server_start,
                                              from_server_end - from_server_start);
#else
                  count = write (client_socket,
                                 from_server + from_server_start,
                                 from_server_end - from_server_start);
#endif
                  if (count < 0)
                    {
#if OVAS_SSL
                      if (count == GNUTLS_E_AGAIN || errno == EAGAIN)
                        /* Wrote as much as possible, return to `select'. */
                        goto end_client_write;
                      if (count == GNUTLS_E_INTERRUPTED || errno == EINTR)
                        /* Interrupted, try write again. */
                        continue;
                      if (errno == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to write to client.\n");
                      gnutls_perror (count);
#else
                      if (errno == EAGAIN)
                        /* Wrote as much as possible, return to `select'. */
                        goto end_client_write;
                      if (errno == EINTR)
                        /* Interrupted, try write again. */
                        continue;
                      perror ("Failed to write to client");
#endif
                      goto fail;
                    }
                  logf ("=> %.*s\n",
                        from_server_end - from_server_start,
                        from_server + from_server_start);
                  from_server_start += count;
                  tracef ("=> client  %i bytes\n", count);
                }
              tracef ("=> client  done\n");
              from_server_start = from_server_end = 0;
             end_client_write:
              ;
            }
        }
    }

 succeed:
#if OVAS_SSL
  gnutls_bye (server_session, GNUTLS_SHUT_RDWR);
  gnutls_deinit (server_session);
  gnutls_certificate_free_credentials (server_credentials);
#else
  if (shutdown (server_socket, SHUT_RDWR) == -1)
    perror ("Failed to shutdown server socket");
#endif
  close (server_socket);
  return EXIT_SUCCESS;

 fail:
#if OVAS_SSL
  gnutls_bye (server_session, GNUTLS_SHUT_RDWR);
 server_fail:
  gnutls_deinit (server_session);

 server_free_fail:
  gnutls_certificate_free_credentials (server_credentials);

 close_fail:
#else
  if (shutdown (server_socket, SHUT_RDWR) == -1)
    perror ("Failed to shutdown server socket");
 server_fail:
#endif

  close (server_socket);

  return EXIT_FAILURE;
}

#undef CLIENT_READ
#undef CLIENT_WRITE
#undef SERVER_READ
#undef SERVER_WRITE

/** Accept and fork.
  *
  * Accept the client connection and fork a child process.  The child calls
  * \ref serve_omp to do the rest of the work.
  */
void
accept_and_maybe_fork () {
  /* Accept the client connection. */
  struct sockaddr_in client_address;
  client_address.sin_family = AF_INET;
  socklen_t size = sizeof (client_address);
  int client_socket;
  while ((client_socket = accept (manager_socket,
                                  (struct sockaddr *) &client_address,
                                  &size))
         == -1)
    {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        /* The connection is gone, return to select. */
        return;
      perror ("Failed to accept client connection");
      exit (EXIT_FAILURE);
    }

  /* Fork a child to serve the client. */
  pid_t pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child. */
        {
          /* The socket must have O_NONBLOCK set, in case an "asynchronous
           * network error" removes the data between `select' and `read'.
           */
          if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
            {
              perror ("Failed to set client socket flag");
              close (client_socket);
              exit (EXIT_FAILURE);
            }
#if OVAS_SSL
          int secure_client_socket
            = ovas_server_context_attach (server_context, client_socket);
          if (secure_client_socket == -1)
            {
              fprintf (stderr,
                       "Failed to attach server context to socket %i.\n",
                       client_socket);
              close (client_socket);
              exit (EXIT_FAILURE);
            }
          tracef ("Server context attached.\n")
          int ret = serve_omp (secure_client_socket);
          close_stream_connection (secure_client_socket);
#else
          int ret = serve_omp (client_socket);
#endif
          close (client_socket);
          exit (ret);
        }
      case -1:
        /* Parent when error, return to select. */
        perror ("Failed to fork child");
        break;
      default:
        /* Parent.  Return to select. */
        break;
    }
}

/** at_exit handler.  Close sockets and streams, free the ovas context. */
void
cleanup ()
{
  tracef ("Cleaning up.\n");
  if (manager_socket > -1) close (manager_socket);
#if LOG
  if (fclose (log_stream)) perror ("Failed to close log stream");
#endif
#if OVAS_SSL
  ovas_server_context_free (server_context);
#endif
}

/** Handler for all signals.
  *
  * @param[in]  signal  The signal that caused this function to run.
  */
void
handle_signal (int signal)
{
  switch (signal)
    {
      case SIGTERM:
      case SIGHUP:
      case SIGINT:
        exit (EXIT_SUCCESS);
    }
}

/** Entry point to the manager.
  *
  * Setup the manager and then loop forever passing connections to
  * \ref accept_and_maybe_fork.
  *
  * @param[in]  argc  The number of arguments in argv.
  * @param[in]  argv  The list of arguments to the program.
  *
  * \return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
  */
int
main (int argc, char** argv)
{
  int server_port, manager_port;
  tracef ("OpenVAS Manager\n");

  /* Process options. */

  static gboolean print_version = FALSE;
  static gchar *manager_address_string = NULL;
  static gchar *manager_port_string = NULL;
  static gchar *server_address_string = NULL;
  static gchar *server_port_string = NULL;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry option_entries[]
    = {
        { "listen", 'a', 0, G_OPTION_ARG_STRING, &manager_address_string, "Listen on <address>.", "<address>" },
        { "port", 'p', 0, G_OPTION_ARG_STRING, &manager_port_string, "Use port number <number>.", "<number>" },
        { "slisten", 'l', 0, G_OPTION_ARG_STRING, &server_address_string, "Server (openvasd) address.", "<address>" },
        { "sport", 's', 0, G_OPTION_ARG_STRING, &server_port_string, "Server (openvasd) port number.", "<number>" },
        { "version", 'v', 0, G_OPTION_ARG_NONE, &print_version, "Print version.", NULL },
        { NULL }
      };

  option_context = g_option_context_new ("- OpenVAS security scanner manager");
  g_option_context_add_main_entries (option_context, option_entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      printf ("%s\n\n", error->message);
      exit (EXIT_FAILURE);
    }

  if (print_version)
    {
      printf ("openvasmd (%s) %s for %s\n",
              PROGNAME, OPENVASMD_VERSION, OPENVAS_OS_NAME);
      printf ("Copyright (C) 2008 Intevation GmbH\n\n");
      exit (EXIT_SUCCESS);
    }

  if (manager_address_string == NULL)
    manager_address_string = OPENVASMD_ADDRESS;

  if (server_address_string == NULL)
    server_address_string = OPENVASD_ADDRESS;

  if (manager_port_string)
    {
      manager_port = atoi (manager_port_string);
      if (manager_port <= 0 || manager_port >= 65536)
	{
	  fprintf (stderr, "Manager port must be a number between 0 and 65536.\n");
	  exit (EXIT_FAILURE);
	}
      manager_port = htons (manager_port);
    }
  else
    {
      struct servent *servent = getservbyname ("openvas", "tcp");
      if (servent)
	// FIX free servent?
	manager_address.sin_port = servent->s_port;
      else
	manager_address.sin_port = htons (OPENVASMD_PORT);
    }

  if (server_port_string)
    {
      server_port = atoi (server_port_string);
      if (server_port <= 0 || server_port >= 65536)
	{
	  fprintf (stderr, "Server port must be a number between 0 and 65536.\n");
	  exit (EXIT_FAILURE);
	}
      server_port = htons (server_port);
    }
  else
    {
      struct servent *servent = getservbyname ("omp", "tcp");
      if (servent)
	// FIX free servent?
        server_port = servent->s_port;
      else
        server_port = htons (OPENVASD_PORT);
    }

  /* Register the `cleanup' function. */

  if (atexit (&cleanup))
    {
      fprintf (stderr, "Failed to register `atexit' cleanup function.\n");
      exit (EXIT_FAILURE);
    }

  /* Create the manager socket. */

  manager_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (manager_socket == -1)
    {
      perror ("Failed to create manager socket");
      exit (EXIT_FAILURE);
    }

#if LOG
  /* Open the log file. */

  log_stream = fopen (LOG_FILE, "w");
  if (log_stream == NULL)
    {
      perror ("Failed to open log file");
      exit (EXIT_FAILURE);
    }
#endif

  /* Register the signal handler. */

  if (signal (SIGTERM, handle_signal) == SIG_ERR
      || signal (SIGINT, handle_signal) == SIG_ERR
      || signal (SIGHUP, handle_signal) == SIG_ERR
      || signal (SIGCHLD, SIG_IGN) == SIG_ERR)
    {
      fprintf (stderr, "Failed to register signal handler.\n");
      exit (EXIT_FAILURE);
    }

  /* Setup the server address. */

  server_address.sin_family = AF_INET;
  server_address.sin_port = server_port;
  if (!inet_aton(server_address_string, &server_address.sin_addr))
    {
      fprintf (stderr, "Failed to create server address %s.\n",
               server_address_string);
      exit (EXIT_FAILURE);
    }

#if OVAS_SSL
  /* Setup security. */

  if (nessus_SSL_init (NULL) < 0)
    {
      fprintf (stderr, "Failed to initialise security.\n");
      exit (EXIT_FAILURE);
    }
  server_context
    = ovas_server_context_new (NESSUS_ENCAPS_TLSv1,
                               SERVERCERT,
                               SERVERKEY,
                               NULL,
                               CACERT,
                               0);
  if (server_context == NULL)
    {
      fprintf (stderr, "Failed to create server context.\n");
      exit (EXIT_FAILURE);
    }
#endif

  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the connection between `select' and `accept'. */
  if (fcntl (manager_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set manager socket flag");
      exit (EXIT_FAILURE);
    }

  /* Bind the manager socket to a port. */

  manager_address.sin_family = AF_INET;
  manager_address.sin_port = manager_port;
  if (!inet_aton(manager_address_string, &manager_address.sin_addr))
    {
      fprintf (stderr, "Failed to create manager address %s.\n",
	       manager_address_string);
      exit (EXIT_FAILURE);
    }

  if (bind (manager_socket,
            (struct sockaddr *) &manager_address,
            sizeof (manager_address))
      == -1)
    {
      perror ("Failed to bind manager socket");
      close (manager_socket);
      exit (EXIT_FAILURE);
    }

  tracef ("Manager bound to address %s port %i\n",
          manager_address_string,
          ntohs (manager_address.sin_port));
  tracef ("Set to connect to address %s port %i\n",
          server_address_string,
          ntohs (server_address.sin_port));

  /* Enable connections to the socket. */

  if (listen (manager_socket, MAX_CONNECTIONS) == -1)
    {
      perror ("Failed to listen on manager socket");
      close (manager_socket);
      exit (EXIT_FAILURE);
    }

  /* Loop waiting for connections and passing the work to
   * `accept_and_maybe_fork'.
   *
   * FIX This could just loop accept_and_maybe_fork.  Might the manager
   *     want to communicate with anything else here, like the server? */

  int ret, nfds;
  fd_set readfds, exceptfds;
  while (1)
    {
      FD_ZERO (&readfds);
      FD_SET (manager_socket, &readfds);
      FD_ZERO (&exceptfds);
      FD_SET (manager_socket, &exceptfds);
      nfds = manager_socket + 1;

      ret = select (nfds, &readfds, NULL, &exceptfds, NULL);

      if (ret == -1)
        {
          perror ("Select failed");
          exit (EXIT_FAILURE);
        }
      if (ret > 0)
        {
          if (FD_ISSET (manager_socket, &exceptfds))
            {
              fprintf (stderr, "Exception in select.\n");
              exit (EXIT_FAILURE);
            }
          if (FD_ISSET (manager_socket, &readfds))
            accept_and_maybe_fork();
        }
    }

  return EXIT_SUCCESS;
}
