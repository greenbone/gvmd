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
 * library is defined in src/\ref manage.c and src/\ref tasks_sql.h.
 *
 * The OTP and Manage libraries both use the Comm library to communication
 * with the OTP server (src/\ref ovas-mngr-comm.c).  There are also two
 * general libraries at src/\ref string.c and src/\ref file.c, which provide
 * string and file utilities.
 *
 * The Manager tests share the code in src/tests/\ref common.c.  This code
 * enables a client to communicate with the manager, and may become a
 * general interface for programming manager clients.
 *
 * \section copying License Information
 * \verbinclude COPYING
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
#include <glib/gstdio.h>
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
#include <openvas_logging.h>

#include "logf.h"
#include "manage.h"
#include "oxpd.h"
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

// FIX rename ~manager_ovas_context
/**
 * @brief The server context.
 */
static ovas_server_context_t server_context = NULL;


/* Forking, serving the client. */

/**
 * @brief Serve the client.
 *
 * Connect to the openvasd server, then call either \ref serve_otp or \ref
 * serve_omp to serve the protocol, depending on the first message that
 * the client sends.  Read the first message with \ref read_protocol.
 *
 * In all cases, close client_socket before returning.
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
      g_warning ("%s: failed to create server socket: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      close_stream_connection (client_socket);
      return EXIT_FAILURE;
    }

  if (make_session (server_socket, &server_session, &server_credentials))
    {
      close_stream_connection (client_socket);
      return EXIT_FAILURE;
    }

  /* Get client socket and session from libopenvas. */

  int real_socket = nessus_get_socket_from_connection (client_socket);
  if (real_socket == -1 || real_socket == client_socket)
    {
      g_warning ("%s: failed to get client socket from libopenvas: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      goto fail;
    }

  gnutls_session_t* client_session;
  client_session = ovas_get_tlssession_from_connection (client_socket);
  if (client_session == NULL)
    {
      g_warning ("%s: failed to get connection from client socket: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      goto fail;
    }
  client_socket = real_socket;

  // FIX get flags first
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to set real client socket flag: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      goto fail;
    }

  /* Read a message from the client, and call the appropriate protocol
   * handler. */

  // FIX some of these are client errs, all EXIT_FAILURE
  switch (read_protocol (client_session, client_socket))
    {
      case PROTOCOL_OTP:
        /* It's up to serve_otp to close_stream_connection on client_socket. */
        if (serve_otp (client_session, &server_session,
                       client_socket, server_socket))
          goto fail;
        break;
      case PROTOCOL_OMP:
        /* It's up to serve_omp to close_stream_connection on client_socket. */
        if (serve_omp (client_session, &server_session, &server_credentials,
                       client_socket, &server_socket))
          goto fail;
        break;
      case PROTOCOL_CLOSE:
        close_stream_connection (client_socket);
        g_message ("   EOF while trying to read protocol\n");
        goto fail;
      case PROTOCOL_TIMEOUT:
        close_stream_connection (client_socket);
        break;
      default:
        g_warning ("%s: Failed to determine protocol\n", __FUNCTION__);
    }

  end_session (server_socket, server_session, server_credentials);
  return EXIT_SUCCESS;

 fail:
  close_stream_connection (client_socket); // FIX why close only on fail?
  end_session (server_socket, server_session, server_credentials);
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
      g_critical ("%s: failed to accept client connection: %s\n",
                  __FUNCTION__,
                  strerror (errno));
      exit (EXIT_FAILURE);
    }

#define FORK 1
#if FORK
  /* Fork a child to serve the client. */
  pid_t pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child. */
        {
#endif /* FORK */
          // FIX get flags first
          /* The socket must have O_NONBLOCK set, in case an "asynchronous
           * network error" removes the data between `select' and `read'.
           */
          if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
            {
              g_critical ("%s: failed to set client socket flag: %s\n",
                          __FUNCTION__,
                          strerror (errno));
              shutdown (client_socket, SHUT_RDWR);
              close (client_socket);
              exit (EXIT_FAILURE);
            }
          int secure_client_socket
            = ovas_server_context_attach (server_context, client_socket);
          if (secure_client_socket == -1)
            {
              g_critical ("%s: failed to attach server context to socket %i\n",
                          __FUNCTION__,
                          client_socket);
              shutdown (client_socket, SHUT_RDWR);
              close (client_socket);
              exit (EXIT_FAILURE);
            }
          tracef ("   Server context attached.\n");
          /* It's up to serve_client to close_stream_connection on
           * secure_client_socket. */
#if FORK
          int ret = serve_client (secure_client_socket);
          save_tasks ();
#else
          serve_client (secure_client_socket);
          save_tasks ();
          cleanup_manage_process ();
#endif
#if FORK
          exit (ret);
        }
      case -1:
        /* Parent when error, return to select. */
        g_warning ("%s: failed to fork child: %s\n",
                   __FUNCTION__,
                   strerror (errno));
        close (client_socket);
        break;
      default:
        /* Parent.  Return to select. */
#endif /* FORK */
        close (client_socket);
#if FORK
        break;
    }
#endif /* FORK */
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
  cleanup_manage_process ();
  if (manager_socket > -1) close (manager_socket);
#if LOG
  if (log_stream != NULL)
    {
      if (fclose (log_stream))
        g_critical ("%s: failed to close log stream: %s\n",
                    __FUNCTION__,
                    strerror (errno));
    }
#endif
  tracef ("   Exiting.\n");
  if (log_config) free_log_configuration (log_config);
  ovas_server_context_free (server_context);
  // Delete pidfile
  gchar *pidfile_name = g_strdup (OPENVAS_PID_DIR "/openvasmd.pid");
  g_unlink (pidfile_name);
  g_free (pidfile_name);
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

  static gboolean migrate_database = FALSE;
  static gboolean update_nvt_cache = FALSE;
  static gboolean foreground = FALSE;
  static gboolean print_version = FALSE;
  static gchar *manager_address_string = NULL;
  static gchar *manager_port_string = NULL;
  static gchar *server_address_string = NULL;
  static gchar *server_port_string = NULL;
  static gchar *rc_name = NULL;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry option_entries[]
    = {
        { "foreground", 'f', 0, G_OPTION_ARG_NONE, &foreground, "Run in foreground.", NULL },
        { "listen", 'a', 0, G_OPTION_ARG_STRING, &manager_address_string, "Listen on <address>.", "<address>" },
        { "migrate", 'm', 0, G_OPTION_ARG_NONE, &migrate_database, "Migrate the database and exit.", NULL },
        { "port", 'p', 0, G_OPTION_ARG_STRING, &manager_port_string, "Use port number <number>.", "<number>" },
        { "slisten", 'l', 0, G_OPTION_ARG_STRING, &server_address_string, "Server (openvasd) address.", "<address>" },
        { "sport", 's', 0, G_OPTION_ARG_STRING, &server_port_string, "Server (openvasd) port number.", "<number>" },
        { "update", 'u', 0, G_OPTION_ARG_NONE, &update_nvt_cache, "Update the NVT cache and exit.", NULL },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Print progress messages.", NULL },
        { "version", 0, 0, G_OPTION_ARG_NONE, &print_version, "Print version and exit.", NULL },
        { NULL }
      };

  option_context = g_option_context_new ("- OpenVAS security scanner manager");
  g_option_context_add_main_entries (option_context, option_entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_critical ("%s: %s\n\n", __FUNCTION__, error->message);
      exit (EXIT_FAILURE);
    }

  if (print_version)
    {
      printf ("openvasmd (%s) %s with db %i for %s\n",
              PROGNAME,
              OPENVASMD_VERSION,
              manage_db_supported_version (),
              OPENVAS_OS_NAME);
      printf ("Copyright (C) 2009 Greenbone Networks GmbH\n\n");
      exit (EXIT_SUCCESS);
    }

  /* Setup logging. */

  rc_name = g_build_filename (OPENVAS_SYSCONF_DIR,
                              "openvasmd_log.conf",
                              NULL);
  if (g_file_test (rc_name, G_FILE_TEST_EXISTS))
    log_config = load_log_configuration (rc_name);
  g_free (rc_name);
  setup_log_handlers (log_config);
  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     openvas_log_func,
                     log_config);
  g_log_set_handler ("md   file",
                     ALL_LOG_LEVELS,
                     openvas_log_func,
                     log_config);
  g_log_set_handler ("md string",
                     ALL_LOG_LEVELS,
                     openvas_log_func,
                     log_config);
  g_log_set_handler ("md   comm",
                     ALL_LOG_LEVELS,
                     openvas_log_func,
                     log_config);
  g_log_set_handler ("md    otp",
                     ALL_LOG_LEVELS,
                     openvas_log_func,
                     log_config);

  tracef ("   OpenVAS Manager\n");

  if (migrate_database)
    {
      tracef ("   Migrating database.\n");

      /* Migrate the database to the version supported by this manager. */
      switch (manage_migrate (log_config))
        {
          case 0:
            tracef ("   Migration succeeded.\n");
            return EXIT_SUCCESS;
          case 1:
            g_warning ("%s: database is already at the supported version\n",
                       __FUNCTION__);
            return EXIT_SUCCESS;
          case 2:
            g_warning ("%s: database migration too hard\n",
                       __FUNCTION__);
            return EXIT_FAILURE;
          case -1:
            g_critical ("%s: database migration failed\n",
                        __FUNCTION__);
            return EXIT_FAILURE;
          default:
            assert (0);
            g_critical ("%s: strange return from manage_migrate\n",
                        __FUNCTION__);
            return EXIT_FAILURE;
        }
    }

  /* Complete option processing. */

  if (server_address_string == NULL)
    server_address_string = OPENVASD_ADDRESS;

  if (server_port_string)
    {
      server_port = atoi (server_port_string);
      if (server_port <= 0 || server_port >= 65536)
        {
          g_critical ("%s: Server port must be a number between 0 and 65536\n",
                      __FUNCTION__);
          free_log_configuration (log_config);
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

  if (update_nvt_cache)
    {
      /* Run the NVT caching manager: update NVT cache and then exit. */

      int server_socket;
      gnutls_session_t server_session;
      gnutls_certificate_credentials_t server_credentials;

      /* Initialise OMP daemon. */

      switch (init_ompd (log_config))
        {
          case 0:
            break;
          case -2:
            g_critical ("%s: database is wrong version\n", __FUNCTION__);
            free_log_configuration (log_config);
            exit (EXIT_FAILURE);
            break;
          case -1:
          default:
            g_critical ("%s: failed to initialise OMP daemon\n", __FUNCTION__);
            free_log_configuration (log_config);
            exit (EXIT_FAILURE);
        }

      /* Register the `cleanup' function. */

      if (atexit (&cleanup))
        {
          g_critical ("%s: failed to register `atexit' cleanup function\n",
                      __FUNCTION__);
          free_log_configuration (log_config);
          exit (EXIT_FAILURE);
        }

      /* Register the signal handlers. */

      /* Warning from RATS heeded (signals now use small, separate handlers)
       * hence annotations. */
      if (signal (SIGTERM, handle_sigterm) == SIG_ERR  /* RATS: ignore */
          || signal (SIGINT, handle_sigint) == SIG_ERR /* RATS: ignore */
          || signal (SIGHUP, handle_sighup) == SIG_ERR /* RATS: ignore */
          || signal (SIGCHLD, SIG_IGN) == SIG_ERR)     /* RATS: ignore */
        {
          g_critical ("%s: failed to register signal handler\n", __FUNCTION__);
          exit (EXIT_FAILURE);
        }

      /* Setup the server address. */

      server_address.sin_family = AF_INET;
      server_address.sin_port = server_port;
      if (!inet_aton (server_address_string, &server_address.sin_addr))
        {
          g_critical ("%s: failed to create server address %s\n",
                      __FUNCTION__,
                      server_address_string);
          exit (EXIT_FAILURE);
        }

      /* Setup security. */

      if (openvas_SSL_init () < 0)
        {
          g_critical ("%s: failed to initialise security\n", __FUNCTION__);
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
          g_critical ("%s: failed to create server context\n", __FUNCTION__);
          exit (EXIT_FAILURE);
        }

      tracef ("   Set to connect to address %s port %i\n",
              server_address_string,
              ntohs (server_address.sin_port));

      /* Make the server socket. */
      server_socket = socket (PF_INET, SOCK_STREAM, 0);
      if (server_socket == -1)
        {
          g_warning ("%s: failed to create server socket: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          return EXIT_FAILURE;
        }

      if (make_session (server_socket, &server_session, &server_credentials))
        return EXIT_FAILURE;

      /* Call the OMP client serving function with client -1.  This invokes a
       * scanner-only manager loop.  As nvt_cache_mode is true, the manager
       * loop will request and cache the plugins, then exit. */

      if (serve_omp (NULL, &server_session, &server_credentials,
                     -1, &server_socket))
        {
          end_session (server_socket, server_session, server_credentials);
          return EXIT_FAILURE;
        }
      else
        {
          end_session (server_socket, server_session, server_credentials);
          return EXIT_SUCCESS;
        }
    }

  /* Run the standard manager. */

  if (manager_port_string)
    {
      manager_port = atoi (manager_port_string);
      if (manager_port <= 0 || manager_port >= 65536)
        {
          g_critical ("%s: Manager port must be a number between 0 and 65536\n",
                      __FUNCTION__);
          free_log_configuration (log_config);
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

#if 0
  /* Initialise server information needed by `cleanup'. */

  server.preferences = NULL;
  server.rules = NULL;
#endif

  if (foreground == FALSE)
    {
      /* Fork into the background. */
      pid_t pid = fork ();
      switch (pid)
        {
          case 0:
            /* Child. */
            break;
          case -1:
            /* Parent when error. */
            g_critical ("%s: failed to fork into background: %s\n",
                        __FUNCTION__,
                        strerror (errno));
            free_log_configuration (log_config);
            exit (EXIT_FAILURE);
            break;
          default:
            /* Parent. */
            free_log_configuration (log_config);
            exit (EXIT_SUCCESS);
            break;
        }
    }

  /* Initialise OMP daemon. */

  switch (init_ompd (log_config))
    {
      case 0:
        break;
      case -2:
        g_critical ("%s: database is wrong version\n", __FUNCTION__);
        free_log_configuration (log_config);
        exit (EXIT_FAILURE);
        break;
      case -1:
      default:
        g_critical ("%s: failed to initialise OMP daemon\n", __FUNCTION__);
        free_log_configuration (log_config);
        exit (EXIT_FAILURE);
    }

  /* Register the `cleanup' function. */

  if (atexit (&cleanup))
    {
      g_critical ("%s: failed to register `atexit' cleanup function\n",
                  __FUNCTION__);
      free_log_configuration (log_config);
      exit (EXIT_FAILURE);
    }

  /* Create the manager socket. */

  manager_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (manager_socket == -1)
    {
      g_critical ("%s: failed to create manager socket: %s\n",
                  __FUNCTION__,
                  strerror (errno));
      exit (EXIT_FAILURE);
    }

#if LOG
  /* Open the log file. */

  if (g_mkdir_with_parents (OPENVAS_LOG_DIR,
                            0755) /* "rwxr-xr-x" */
      == -1)
    {
      g_critical ("%s: failed to create log directory: %s\n",
                  __FUNCTION__,
                  strerror (errno));
      exit (EXIT_FAILURE);
    }

  log_stream = fopen (LOG_FILE, "w");
  if (log_stream == NULL)
    {
      g_critical ("%s: failed to open log file: %s\n",
                  __FUNCTION__,
                  strerror (errno));
      exit (EXIT_FAILURE);
    }
#endif

  /* Register the signal handlers. */

  /* Warning from RATS heeded (signals now use small, separate handlers)
   * hence annotations. */
  if (signal (SIGTERM, handle_sigterm) == SIG_ERR  /* RATS: ignore */
      || signal (SIGINT, handle_sigint) == SIG_ERR /* RATS: ignore */
      || signal (SIGHUP, handle_sighup) == SIG_ERR /* RATS: ignore */
      || signal (SIGCHLD, SIG_IGN) == SIG_ERR)     /* RATS: ignore */
    {
      g_critical ("%s: failed to register signal handler\n", __FUNCTION__);
      exit (EXIT_FAILURE);
    }

  /* Setup the server address. */

  server_address.sin_family = AF_INET;
  server_address.sin_port = server_port;
  if (!inet_aton (server_address_string, &server_address.sin_addr))
    {
      g_critical ("%s: failed to create server address %s\n",
                  __FUNCTION__,
                  server_address_string);
      exit (EXIT_FAILURE);
    }

  /* Setup security. */

  if (openvas_SSL_init () < 0)
    {
      g_critical ("%s: failed to initialise security\n", __FUNCTION__);
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
      g_critical ("%s: failed to create server context\n", __FUNCTION__);
      exit (EXIT_FAILURE);
    }

  // FIX get flags first
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the connection between `select' and `accept'. */
  if (fcntl (manager_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_critical ("%s: failed to set manager socket flag: %s\n",
                  __FUNCTION__,
                  strerror (errno));
      exit (EXIT_FAILURE);
    }

  /* Bind the manager socket to a port. */

  manager_address.sin_family = AF_INET;
  manager_address.sin_port = manager_port;
  if (manager_address_string)
    {
      if (!inet_aton (manager_address_string, &manager_address.sin_addr))
        {
          g_critical ("%s: failed to create manager address %s\n",
                      __FUNCTION__,
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
      g_critical ("%s: failed to bind manager socket: %s\n",
                  __FUNCTION__,
                  strerror (errno));
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
      g_critical ("%s: failed to listen on manager socket: %s\n",
                  __FUNCTION__,
                  strerror (errno));
      close (manager_socket);
      exit (EXIT_FAILURE);
    }

  /* Set our pidfile. */

  gchar *pidfile_name = g_strdup (OPENVAS_PID_DIR "/openvasmd.pid");
  FILE *pidfile = g_fopen (pidfile_name, "w");
  if (pidfile == NULL)
    {
      g_critical ("%s: failed to open pidfile: %s\n",
                  __FUNCTION__,
                  strerror (errno));
      exit (EXIT_FAILURE);
    }
  else
    {
      g_fprintf (pidfile, "%d\n", getpid());
      fclose (pidfile);
      g_free (pidfile_name);
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
          if (errno == EINTR) continue;
          g_critical ("%s: select failed: %s\n",
                      __FUNCTION__,
                      strerror (errno));
          exit (EXIT_FAILURE);
        }
      if (ret > 0)
        {
          if (FD_ISSET (manager_socket, &exceptfds))
            {
              g_critical ("%s: exception in select\n", __FUNCTION__);
              exit (EXIT_FAILURE);
            }
          if (FD_ISSET (manager_socket, &readfds))
            accept_and_maybe_fork ();
        }
    }

  return EXIT_SUCCESS;
}
