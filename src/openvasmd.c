/* OpenVAS Manager
 * $Id$
 * Description: Main module for OpenVAS Manager: the system daemon.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
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

/**
 * @file  openvasmd.c
 * @brief The OpenVAS Manager daemon.
 *
 * This file defines the OpenVAS Manager, a daemon that is layered between
 * the real OpenVAS Server (openvasd) and a client (such as
 * OpenVAS-Client).
 *
 * The entry point to the daemon is the \ref main function.  From there
 * the references in the function documentation describe the flow of
 * control in the program.
 */

/**
 * \mainpage
 *
 * \section Introduction
 * \verbinclude README
 *
 * \section manpages Manual Pages
 * \subpage manpage
 *
 * \section Installation
 * \verbinclude INSTALL
 *
 * \section Implementation
 *
 * The command line entry to the manager is defined in
 * src/\ref openvasmd.c.  The manager can run as an OTP logger or an
 * OMP server.
 *
 * The OTP logger is defined in src/\ref otpd.c.
 *
 * The OMP server is defined in src/\ref ompd.c.  It uses the OTP library
 * to handle the OTP server and the OMP library to handle the OMP client.
 * The OTP library is defined in src/\ref otp.c.  The OMP library is defined
 * in src/\ref omp.c.  Both the OMP and OTP libraries use the Manage library
 * to manage credentials and tasks.  The manage
 * library is defined in src/\ref manage.c, src/\ref tasks_sql.h and
 * src/\ref tasks_fs.h.
 *
 * The OTP and Manage libraries both use the Comm library to communication
 * with the OTP server (src/\ref ovas-mngr-comm.c).  There are also two
 * general libraries at src/\ref string.c and src/\ref file.c, which provide
 * string and file utilities.
 *
 * The Manager tests share the code in src/tests/\ref common.c.  This code
 * enables a client to communicate with the manager, and may become a
 * general interface for programming manager clients.
 */

/**
 * \page manpage openvasmd
 * \htmlinclude doc/openvasmd.html
 */

#ifndef S_SPLINT_S
#include <arpa/inet.h>
#endif
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <netdb.h>
#ifndef S_SPLINT_S
#include <netinet/in.h>
#include <netinet/ip.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <network.h>
#include <plugutils.h>

#include "logf.h"
#include "manage.h"
#include "ompd.h"
#include "otpd.h"
#include "ovas-mngr-comm.h"
#include "tracef.h"

/**
 * @brief The name of this program.
 *
 * \todo Use `program_invocation[_short]_name'?
 */
#define PROGNAME "openvasmd"

/**
 * @brief The version number of this program.
 */
#ifndef OPENVASMD_VERSION
#define OPENVASMD_VERSION "FIX"
#endif

/**
 * @brief The name of the underlying Operating System.
 */
#ifndef OPENVAS_OS_NAME
#define OPENVAS_OS_NAME "FIX"
#endif

/**
 * @brief Server (openvasd) address.
 */
#define OPENVASD_ADDRESS "127.0.0.1"

/**
 * @brief Location of server certificate.
 */
#ifndef SERVERCERT
#define SERVERCERT "/var/lib/openvas/CA/servercert.pem"
#endif

/**
 * @brief Location of server certificate private key.
 */
#ifndef SERVERKEY
#define SERVERKEY  "/var/lib/openvas/private/CA/serverkey.pem"
#endif

/**
 * @brief Location of Certificate Authority certificate.
 */
#ifndef CACERT
#define CACERT     "/var/lib/openvas/CA/cacert.pem"
#endif

/**
 * @brief Server port.
 *
 * Used if /etc/services "openvas" and -port missing.
 */
#define OPENVASD_PORT 1241

/**
 * @brief Manager port.
 *
 * Used if /etc/services "omp" and -sport are missing.
 */
#define OPENVASMD_PORT 1241

/**
 * @brief Second argument to `listen'.
 */
#define MAX_CONNECTIONS 512

#if FROM_BUFFER_SIZE > SSIZE_MAX
#error FROM_BUFFER_SIZE too big for `read'
#endif

/**
 * @brief The socket accepting OMP connections from clients.
 */
int manager_socket = -1;

/**
 * @brief The IP address of this program, "the manager".
 */
struct sockaddr_in manager_address;

#if LOG
/**
 * @brief The log stream.
 */
FILE* log_stream = NULL;
#endif

/**
 * @brief The server context.
 */
static ovas_server_context_t server_context = NULL;

/**
 * @brief The type of the return value from \ref read_protocol.
 */
typedef enum
{
  PROTOCOL_OTP,
  PROTOCOL_OMP,
  PROTOCOL_CLOSE,
  PROTOCOL_FAIL
} protocol_read_t;

/**
 * @brief Size of \ref from_client and \ref from_server data buffers, in bytes.
 */
#define FROM_BUFFER_SIZE 1048576

/**
 * @brief Buffer of input from the client.
 */
char from_client[FROM_BUFFER_SIZE];
/**
 * @brief Buffer of input from the server.
 */
char from_server[FROM_BUFFER_SIZE];

// FIX for passing to otp[d].c,omp[d].c
/**
 * @brief Size of \ref from_client and \ref from_server data buffers, in bytes.
 */
buffer_size_t from_buffer_size = FROM_BUFFER_SIZE;

// FIX just make these pntrs?
/**
 * @brief The start of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_start = 0;
/**
 * @brief The start of the data in the \ref from_server buffer.
 */
buffer_size_t from_server_start = 0;
/**
 * @brief The end of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_end = 0;

/**
 * @brief The end of the data in the \ref from_server buffer.
 */
buffer_size_t from_server_end = 0;


/* Checking protocol, forking, serving the client. */

/**
 * @brief Read and return the type of protocol from the client.
 *
 * @param[in]  client_session  The TLS session with the client.
 * @param[in]  client_socket   The socket connected to the client.
 *
 * @return PROTOCOL_FAIL, PROTOCOL_CLOSE, PROTOCOL_OTP or PROTOCOL_OMP.
 */
protocol_read_t
read_protocol (gnutls_session_t* client_session, int client_socket)
{
  /* Turn on blocking. */
  // FIX get flags first
  if (fcntl (client_socket, F_SETFL, 0L) == -1)
    {
      perror ("Failed to set client socket flag (read_protocol)");
      return PROTOCOL_FAIL;
    }

  /* Read from the client, checking the protocol when a newline or return
   * is read. */
  protocol_read_t ret = PROTOCOL_FAIL;
  char* from_client_current = from_client + from_client_end;
  while (from_client_end < FROM_BUFFER_SIZE)
    {
      ssize_t count;

      while (1)
        {
          count = gnutls_record_recv (*client_session,
                                      from_client + from_client_end,
                                      FROM_BUFFER_SIZE
                                      - from_client_end);
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try read again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* Try again. TODO Rehandshake. */
            continue;
          break;
        }

      if (count < 0)
        {
          if (gnutls_error_is_fatal (count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*client_session);
              fprintf (stderr, "TLS Alert %d: %s.\n",
                       alert,
                       gnutls_alert_get_name (alert));
            }
          fprintf (stderr, "Failed to read from client (read_protocol).\n");
          gnutls_perror (count);
          break;
        }
      if (count == 0)
        {
          /* End of file. */
          ret = PROTOCOL_CLOSE;
          break;
        }
      from_client_end += count;

#if 0
      /* Check for newline or return. */
      from_client[from_client_end] = '\0';
      if (strchr (from_client_current, 10) || strchr (from_client_current, 13))
        {
          if (strstr (from_client, "< OTP/1.0 >"))
            ret = PROTOCOL_OTP;
          else
            ret = PROTOCOL_OMP;
          break;
        }
#else
      /* Check for ">".  FIX need a better check */
      from_client[from_client_end] = '\0';
      if (strchr (from_client_current, '>'))
        {
          if (strstr (from_client, "< OTP/1.0 >"))
            ret = PROTOCOL_OTP;
          else
            ret = PROTOCOL_OMP;
          break;
        }
#endif

      from_client_current += count;
    }

  // FIX use orig value
  /* Turn blocking back off. */
  if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to reset client socket flag (read_protocol)");
      return PROTOCOL_FAIL;
    }

  return ret;
}

/**
 * @brief Serve the client.
 *
 * Connect to the openvasd server, then call either \ref serve_otp or \ref
 * serve_omp to serve the protocol, depending on the first message that
 * the client sends.  Read the first message with \ref read_protocol.
 *
 * @param[in]  client_socket  The socket connected to the client.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int
serve_client (int client_socket)
{
  int server_socket;
  gnutls_session_t server_session;
  gnutls_certificate_credentials_t server_credentials;

  /* Make the server socket. */
  server_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (server_socket == -1)
    {
      perror ("Failed to create server socket");
      return EXIT_FAILURE;
    }

  if (make_session (server_socket, &server_session, &server_credentials))
    return EXIT_FAILURE;

  /* Get client socket and session from libopenvas. */

  int real_socket = nessus_get_socket_from_connection (client_socket);
  if (real_socket == -1 || real_socket == client_socket)
    {
      perror ("Failed to get client socket from libopenvas");
      goto fail;
    }

  gnutls_session_t* client_session;
  client_session = ovas_get_tlssession_from_connection (client_socket);
  if (client_session == NULL)
    {
      perror ("Failed to get connection from client socket");
      goto fail;
    }
  client_socket = real_socket;

  // FIX get flags first
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set real client socket flag");
      goto fail;
    }
  gnutls_transport_set_lowat (*client_session, 0);

  /* Read a message from the client, and call the appropriate protocol
   * handler. */

  // FIX some of these are client errs, all EXIT_FAILURE
  switch (read_protocol (client_session, client_socket))
    {
      case PROTOCOL_OTP:
        if (serve_otp (client_session, &server_session,
                       client_socket, server_socket))
          goto fail;
        break;
      case PROTOCOL_OMP:
        if (serve_omp (client_session, &server_session, &server_credentials,
                       client_socket, &server_socket))
          goto fail;
        break;
      case PROTOCOL_CLOSE:
        fprintf (stderr, "EOF while trying to read protocol.\n");
        goto fail;
      default:
        fprintf (stderr, "Failed to determine protocol.\n");
    }

  end_session (server_socket, server_session, server_credentials);
  if (close (server_socket) == -1)
    {
      perror ("Failed to close server socket.");
      return EXIT_FAILURE;
    }
  return EXIT_SUCCESS;

 fail:
  end_session (server_socket, server_session, server_credentials);
  close (server_socket);
  return EXIT_FAILURE;
}

/**
 * @brief Accept and fork.
 *
 * Accept the client connection and fork a child process to serve the client.
 * The child calls \ref serve_client to do the rest of the work.
 */
void
accept_and_maybe_fork ()
{
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
          // FIX get flags first
          /* The socket must have O_NONBLOCK set, in case an "asynchronous
           * network error" removes the data between `select' and `read'.
           */
          if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
            {
              perror ("Failed to set client socket flag");
              shutdown (client_socket, SHUT_RDWR);
              close (client_socket);
              exit (EXIT_FAILURE);
            }
          int secure_client_socket
            = ovas_server_context_attach (server_context, client_socket);
          if (secure_client_socket == -1)
            {
              fprintf (stderr,
                       "Failed to attach server context to socket %i.\n",
                       client_socket);
              shutdown (client_socket, SHUT_RDWR);
              close (client_socket);
              exit (EXIT_FAILURE);
            }
          tracef ("   Server context attached.\n");
          int ret = serve_client (secure_client_socket);
          close_stream_connection (secure_client_socket);
          save_tasks ();
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


/* Maintenance functions. */

/**
 * @brief Clean up for exit.
 *
 * Close sockets and streams, free the ovas context.
 */
void
cleanup ()
{
  tracef ("   Cleaning up.\n");
  // FIX should be via omp, maybe cleanup_omp ();
  cleanup_manage ();
  if (manager_socket > -1) close (manager_socket);
#if LOG
  if (log_stream != NULL)
    {
      if (fclose (log_stream)) perror ("Failed to close log stream");
    }
#endif
  ovas_server_context_free (server_context);
}

/**
 * @brief Handle a SIGTERM signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
void
handle_sigterm (int signal)
{
  exit (EXIT_SUCCESS);
}

/**
 * @brief Handle a SIGHUP signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
void
handle_sighup (int signal)
{
  exit (EXIT_SUCCESS);
}

/**
 * @brief Handle a SIGINT signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
void
handle_sigint (int signal)
{
  exit (EXIT_SUCCESS);
}


/* Main. */

/**
 * @brief Entry point to the manager.
 *
 * Setup the manager and then loop forever passing connections to
 * \ref accept_and_maybe_fork.
 *
 * @param[in]  argc  The number of arguments in argv.
 * @param[in]  argv  The list of arguments to the program.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int
main (int argc, char** argv)
{
  int server_port, manager_port;

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
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Print progress messages.", NULL },
        { "version", 0, 0, G_OPTION_ARG_NONE, &print_version, "Print version.", NULL },
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
      printf ("Copyright (C) 2009 Greenbone Networks GmbH\n\n");
      exit (EXIT_SUCCESS);
    }

  tracef ("   OpenVAS Manager\n");

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

#if 0
  /* Initialise server information needed by `cleanup'. */

  server.preferences = NULL;
  server.rules = NULL;
#endif

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

  if (g_mkdir_with_parents (OPENVAS_LOG_DIR,
                            0755) /* "rwxr-xr-x" */
      == -1)
    {
      perror ("Failed to create log directory");
      exit (EXIT_FAILURE);
    }

  log_stream = fopen (LOG_FILE, "w");
  if (log_stream == NULL)
    {
      perror ("Failed to open log file");
      exit (EXIT_FAILURE);
    }
#endif

  /* Register the signal handler. */

  /* Warning from RATS heeded (signals now use small, separate handlers)
   * hence annotations. */
  if (signal (SIGTERM, handle_sigterm) == SIG_ERR  /* RATS: ignore */
      || signal (SIGINT, handle_sigint) == SIG_ERR /* RATS: ignore */
      || signal (SIGHUP, handle_sighup) == SIG_ERR /* RATS: ignore */
      || signal (SIGCHLD, SIG_IGN) == SIG_ERR)     /* RATS: ignore */
    {
      fprintf (stderr, "Failed to register signal handler.\n");
      exit (EXIT_FAILURE);
    }

  /* Setup the server address. */

  server_address.sin_family = AF_INET;
  server_address.sin_port = server_port;
  if (!inet_aton (server_address_string, &server_address.sin_addr))
    {
      fprintf (stderr, "Failed to create server address %s.\n",
               server_address_string);
      exit (EXIT_FAILURE);
    }

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

  // FIX get flags first
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
  if (manager_address_string)
    {
      if (!inet_aton (manager_address_string, &manager_address.sin_addr))
        {
          fprintf (stderr, "Failed to create manager address %s.\n",
                   manager_address_string);
          exit (EXIT_FAILURE);
        }
    }
  else
    manager_address.sin_addr.s_addr = INADDR_ANY;

  if (bind (manager_socket,
            (struct sockaddr *) &manager_address,
            sizeof (manager_address))
      == -1)
    {
      perror ("Failed to bind manager socket");
      close (manager_socket);
      exit (EXIT_FAILURE);
    }

  tracef ("   Manager bound to address %s port %i\n",
          manager_address_string ? manager_address_string : "*",
          ntohs (manager_address.sin_port));
  tracef ("   Set to connect to address %s port %i\n",
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
   *     want to communicate with anything else here, like the server?
   */

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
