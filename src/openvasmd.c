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
 * This file defines the OpenVAS Manager daemon.  The Manager serves the OpenVAS
 * Management Protocol (OMP) to clients such as OpenVAS-Client.  The Manager
 * and OMP give clients full access to an OpenVAS Scanner.
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
 * src/\ref openvasmd.c.  The manager can run as an OTP port forwarder or an
 * OMP server.
 *
 * The OTP port forwarder is defined in src/\ref otpd.c.
 *
 * The OMP server is defined in src/\ref ompd.c.  It uses the OTP library
 * to handle the OTP server and the OMP library to handle the OMP client.
 * The OTP library is defined in src/\ref otp.c.  The OMP library is defined
 * in src/\ref omp.c.  Both the OMP and OTP libraries use the Manage library
 * to manage credentials and tasks.  The manage
 * library is defined in src/\ref manage.c and src/\ref tasks_sql.h.
 *
 * The OTP and Manage libraries both use the Comm library to communication
 * with the OTP server (src/\ref ovas-mngr-comm.c).
 *
 * The Manager tests share some code in src/tests/\ref common.c.
 *
 * \subsection Forking
 *
 * The main daemon manager process will fork for every incoming connection and
 * for every scheduled task.
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

#include <openvas_logging.h>
#include <openvas_server.h>
#include <openvas/base/pidfile.h>

#include "logf.h"
#include "manage.h"
#include "oxpd.h"
#include "ompd.h"
#include "otpd.h"
#include "ovas-mngr-comm.h"
#include "tracef.h"

#ifdef S_SPLINT_S
#include "splint.h"
#endif

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
 * @brief Scanner (openvassd) address.
 */
#define OPENVASSD_ADDRESS "127.0.0.1"

/**
 * @brief Location of scanner certificate.
 */
#ifndef SCANNERCERT
#define SCANNERCERT "/var/lib/openvas/CA/servercert.pem"
#endif

/**
 * @brief Location of scanner certificate private key.
 */
#ifndef SCANNERKEY
#define SCANNERKEY  "/var/lib/openvas/private/CA/serverkey.pem"
#endif

/**
 * @brief Location of Certificate Authority certificate.
 */
#ifndef CACERT
#define CACERT     "/var/lib/openvas/CA/cacert.pem"
#endif

/**
 * @brief Location of client certificate.
 */
#ifndef CLIENTCERT
#define CLIENTCERT "/var/lib/openvas/CA/clientcert.pem"
#endif

/**
 * @brief Location of client certificate private key.
 */
#ifndef CLIENTKEY
#define CLIENTKEY  "/var/lib/openvas/private/CA/clientkey.pem"
#endif

/**
 * @brief Scanner port.
 *
 * Used if /etc/services "otp" and --port missing.
 */
#define OPENVASSD_PORT 9391

/**
 * @brief Manager port.
 *
 * Used if /etc/services "omp" and --sport are missing.
 */
#define OPENVASMD_PORT 9390

/**
 * @brief Second argument to `listen'.
 */
#define MAX_CONNECTIONS 512

/**
 * @brief Seconds between calls to manage_schedule.
 */
#define SCHEDULE_PERIOD 10

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
 * @brief The client session.
 */
gnutls_session_t client_session;

/**
 * @brief The client credentials.
 */
gnutls_certificate_credentials_t client_credentials;

/**
 * @brief Location of the manage database.
 */
static gchar *database = NULL;

/**
 * @brief Is this process parent or child?
 */
int is_parent = 1;

/**
 * @brief Whether to serve OTP.
 */
gboolean otp = FALSE;


/* Forking, serving the client. */

/**
 * @brief Serve the client.
 *
 * Connect to the openvassd scanner, then call either \ref serve_otp or \ref
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
  int scanner_socket;
  gnutls_session_t scanner_session;
  gnutls_certificate_credentials_t scanner_credentials;

  /* Make the scanner socket. */
  scanner_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (scanner_socket == -1)
    {
      g_warning ("%s: failed to create scanner socket: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      openvas_server_free (client_socket,
                           client_session,
                           client_credentials);
      return EXIT_FAILURE;
    }

  if (openvas_server_new (GNUTLS_CLIENT,
                          CACERT,
                          CLIENTCERT,
                          CLIENTKEY,
                          &scanner_session,
                          &scanner_credentials))
    {
      openvas_server_free (client_socket,
                           client_session,
                           client_credentials);
      return EXIT_FAILURE;
    }

  if (openvas_server_attach (client_socket, &client_session))
    {
      g_critical ("%s: failed to attach client session to socket %i\n",
                  __FUNCTION__,
                  client_socket);
      goto fail;
    }

  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (scanner_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to set scanner socket flag: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      goto fail;
    }

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
  switch (read_protocol (&client_session, client_socket))
    {
      case PROTOCOL_OTP:
        if (otp == FALSE)
          goto fail;
        /* It's up to serve_otp to openvas_server_free client_*. */
        if (serve_otp (&client_session, &scanner_session,
                       &client_credentials,
                       client_socket, scanner_socket))
          goto server_fail;
        break;
      case PROTOCOL_OMP:
        /* It's up to serve_omp to openvas_server_free client_*. */
        if (serve_omp (&client_session, &scanner_session,
                       &client_credentials, &scanner_credentials,
                       client_socket, &scanner_socket,
                       database))
          goto server_fail;
        break;
      case PROTOCOL_CLOSE:
        g_message ("   EOF while trying to read protocol\n");
        goto fail;
      case PROTOCOL_TIMEOUT:
        openvas_server_free (client_socket,
                             client_session,
                             client_credentials);
        break;
      default:
        g_warning ("%s: Failed to determine protocol\n", __FUNCTION__);
        goto fail;
    }

  openvas_server_free (scanner_socket,
                       scanner_session,
                       scanner_credentials);
  return EXIT_SUCCESS;

 fail:
  openvas_server_free (client_socket,
                       client_session,
                       client_credentials);
 server_fail:
  openvas_server_free (scanner_socket,
                       scanner_session,
                       scanner_credentials);
  return EXIT_FAILURE;
}

/**
 * @brief Accept and fork.
 *
 * Accept the client connection and fork a child process to serve the client.
 * The child calls \ref serve_client to do the rest of the work.
 */
static void
accept_and_maybe_fork ()
{
  /* Accept the client connection. */
  pid_t pid;
  struct sockaddr_in client_address;
  socklen_t size = sizeof (client_address);
  int client_socket;
  client_address.sin_family = AF_INET;
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

  /* Fork a child to serve the client. */
  pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child. */
        {
          int ret;

          is_parent = 0;

          /* RATS: ignore, this is SIG_DFL damnit. */
          if (signal (SIGCHLD, SIG_DFL) == SIG_ERR)
            {
              g_critical ("%s: failed to set client SIGCHLD handler: %s\n",
                          __FUNCTION__,
                          strerror (errno));
              shutdown (client_socket, SHUT_RDWR);
              close (client_socket);
              exit (EXIT_FAILURE);
            }

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
          /* Reopen the database (required after fork). */
          cleanup_manage_process (FALSE);
          ret = serve_client (client_socket);
          /** @todo This should be done through libomp. */
          save_tasks ();
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
        close (client_socket);
        break;
    }
}


/* Connection forker for schedular. */

/**
 * @brief Fork a child connected to the Manager.
 *
 * @return 0 parent on success, 1 child on success, -1 error.
 */
static int
fork_connection_for_schedular (int *client_socket,
                               gnutls_session_t *client_session,
                               gnutls_certificate_credentials_t
                               *client_credentials)
{
  int pid, parent_client_socket, ret;
  int sockets[2];

  /* Fork a child to use as schedular client and server. */

  pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child. */
        cleanup_manage_process (FALSE);
        break;

      case -1:
        /* Parent when error. */
        g_warning ("%s: fork: %s\n", __FUNCTION__, strerror (errno));
        return -1;
        break;

      default:
        /* Parent.  Return to caller. */
        return 0;
        break;
    }

  /* This is now a child of the main Manager process.  It forks again.  The
   * only case that returns is the child after a connection is successfully
   * set up.  The caller must exit this child.
   *
   * Create a connected pair of sockets. */

  if (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets))
    {
      g_warning ("%s: socketpair: %s\n", __FUNCTION__, strerror (errno));
      exit (EXIT_FAILURE);
    }

  /* Split into a Manager client for the schedular, and a Manager serving
   * OMP to that client. */

  is_parent = 0;

  pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child.  */

        /* FIX Give the parent time to prepare. */
        sleep (5);

        *client_socket = sockets[1];

        if (openvas_server_new (GNUTLS_CLIENT, NULL, NULL, NULL,
                                client_session, client_credentials))
          exit (EXIT_FAILURE);

        if (openvas_server_attach (*client_socket, client_session))
          exit (EXIT_FAILURE);

        return 1;
        break;

      case -1:
        /* Parent when error. */

        g_warning ("%s: fork: %s\n", __FUNCTION__, strerror (errno));
        exit (EXIT_FAILURE);
        break;

      default:
        /* Parent.  Serve the schedular OMP, then exit. */

        parent_client_socket = sockets[0];

        /* RATS: ignore, this is SIG_DFL damnit. */
        if (signal (SIGCHLD, SIG_DFL) == SIG_ERR)
          {
            g_critical ("%s: failed to set client SIGCHLD handler: %s\n",
                        __FUNCTION__,
                        strerror (errno));
            shutdown (parent_client_socket, SHUT_RDWR);
            close (parent_client_socket);
            exit (EXIT_FAILURE);
          }

        // FIX get flags first
        /* The socket must have O_NONBLOCK set, in case an "asynchronous
         * network error" removes the data between `select' and `read'.
         */
        if (fcntl (parent_client_socket, F_SETFL, O_NONBLOCK) == -1)
          {
            g_critical ("%s: failed to set client socket flag: %s\n",
                        __FUNCTION__,
                        strerror (errno));
            shutdown (parent_client_socket, SHUT_RDWR);
            close (parent_client_socket);
            exit (EXIT_FAILURE);
          }

        init_ompd_process (database);

        /* Make any further authentications to this process succeed.  This
         * enables the schedular to login as the owner of the scheduled
         * task. */
        manage_auth_allow_all ();

        ret = serve_client (parent_client_socket);
        /** @todo This should be done through libomp. */
        save_tasks ();
        exit (ret);
        break;
    }

  exit (EXIT_FAILURE);
  /*@notreached@*/
  return -1;
}


/* Maintenance functions. */

/**
 * @brief Clean up for exit.
 *
 * Close sockets and streams.
 */
static void
cleanup ()
{
  tracef ("   Cleaning up.\n");
  // FIX should be via omp, maybe cleanup_omp ();
  cleanup_manage_process (TRUE);
  if (manager_socket > -1) close (manager_socket);
#if LOG
  if (log_stream != NULL)
    {
      if (fclose (log_stream))
        g_critical ("%s: failed to close log stream: %s\n",
                    __FUNCTION__,
                    strerror (errno));
    }
#endif /* LOG */
  tracef ("   Exiting.\n");
  if (log_config) free_log_configuration (log_config);

  /* Tear down authentication system conf, if any. */
  openvas_auth_tear_down ();

  /* Delete pidfile if this process is the parent. */
  if (is_parent == 1) pidfile_remove ("openvasmd");
}

/**
 * @brief Handle a SIGABRT signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
void
handle_sigabrt (/*@unused@*/ int signal)
{
  static int in_sigabrt = 0;
  if (in_sigabrt) _exit (EXIT_FAILURE);
  in_sigabrt = 1;
  manage_cleanup_process_error (signal);
  g_critical ("%s: abort\n", __FUNCTION__);
  exit (EXIT_FAILURE);
}

/**
 * @brief Handle a SIGTERM signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
void
handle_sigterm (/*@unused@*/ int signal)
{
  cleanup_manage_process (TRUE);
  exit (EXIT_SUCCESS);
}

/**
 * @brief Handle a SIGHUP signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
void
handle_sighup (/*@unused@*/ int signal)
{
  cleanup_manage_process (TRUE);
  exit (EXIT_SUCCESS);
}

/**
 * @brief Handle a SIGINT signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
void
handle_sigint (/*@unused@*/ int signal)
{
  cleanup_manage_process (TRUE);
  exit (EXIT_SUCCESS);
}

/**
 * @brief Handle a SIGSEGV signal.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
void
handle_sigsegv (/*@unused@*/ int signal)
{
  manage_cleanup_process_error (signal);
  g_critical ("%s: segmentation fault\n", __FUNCTION__);
  exit (EXIT_FAILURE);
}



/**
 * @brief Updates or rebuilds the NVT Cache and exits or returns exit code.
 *
 * @param[in]  update_nvt_cache        Whether the nvt cache should be updated
 *                                     (1) or rebuilt (0).
 * @param[in]  scanner_address_string  Adress of the scanner as string.
 * @param[in]  port                    Port of the scanner.
 *
 * @return If this function did not exit itself, returns exit code.
 */
static int
update_or_rebuild_nvt_cache (int update_nvt_cache,
                             gchar* scanner_address_string, int scanner_port)
{
  int scanner_socket;
  gnutls_session_t scanner_session;
  gnutls_certificate_credentials_t scanner_credentials;

  /* Initialise OMP daemon. */

  switch (init_ompd (log_config,
                      update_nvt_cache ? -1 : -2,
                      database))
    {
      case 0:
        break;
      case -2:
        g_critical ("%s: database is wrong version\n", __FUNCTION__);
        free_log_configuration (log_config);
        exit (EXIT_FAILURE);
        break;
      case -3:
        assert (0);
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

  /** @todo Use sigaction. */
  /* Warning from RATS heeded (signals now use small, separate handlers)
    * hence annotations. */
  if (signal (SIGTERM, handle_sigterm) == SIG_ERR    /* RATS: ignore */
      || signal (SIGABRT, handle_sigabrt) == SIG_ERR /* RATS: ignore */
      || signal (SIGINT, handle_sigint) == SIG_ERR   /* RATS: ignore */
      || signal (SIGHUP, handle_sighup) == SIG_ERR   /* RATS: ignore */
      || signal (SIGSEGV, handle_sigsegv) == SIG_ERR /* RATS: ignore */
      || signal (SIGCHLD, SIG_IGN) == SIG_ERR)       /* RATS: ignore */
    {
      g_critical ("%s: failed to register signal handler\n", __FUNCTION__);
      exit (EXIT_FAILURE);
    }

  /* Setup the scanner address. */

  scanner_address.sin_family = AF_INET;
  scanner_address.sin_port = scanner_port;
  if (!inet_aton (scanner_address_string, &scanner_address.sin_addr))
    {
      g_critical ("%s: failed to create scanner address %s\n",
                  __FUNCTION__,
                  scanner_address_string);
      exit (EXIT_FAILURE);
    }

  /* Setup security. */

  tracef ("   Set to connect to address %s port %i\n",
          scanner_address_string,
          ntohs (scanner_address.sin_port));

  /* Make the scanner socket. */
  scanner_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (scanner_socket == -1)
    {
      g_warning ("%s: failed to create scanner socket: %s\n",
                  __FUNCTION__,
                  strerror (errno));
      return EXIT_FAILURE;
    }

  if (openvas_server_new (GNUTLS_CLIENT,
                          CACERT,
                          CLIENTCERT,
                          CLIENTKEY,
                          &scanner_session,
                          &scanner_credentials))
    return EXIT_FAILURE;

  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
    * error" removes the data between `select' and `read'. */
  if (fcntl (scanner_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to set scanner socket flag: %s\n",
                  __FUNCTION__,
                  strerror (errno));
      return EXIT_FAILURE;
    }

  /* Call the OMP client serving function with a special client socket
    * value.  This invokes a scanner-only manager loop which will
    * request and cache the plugins, then exit. */

  if (serve_omp (NULL, &scanner_session,
                  NULL, &scanner_credentials,
                  update_nvt_cache ? -1 : -2,
                  &scanner_socket,
                  database))
    {
      openvas_server_free (scanner_socket,
                            scanner_session,
                            scanner_credentials);
      return EXIT_FAILURE;
    }
  else
    {
      openvas_server_free (scanner_socket,
                            scanner_session,
                            scanner_credentials);
      return EXIT_SUCCESS;
    }
}

/**
 * @brief Enter an infinite loop, waiting for connections and passing the 
 * @brief work to `accept_and_maybe_fork'.
 *
 * Periodically, call the manage schedular to start and stop scheduled tasks.
 */
static void
main_loop ()
{
  time_t last_schedule_time = 0;

  while (1)
    {
      int ret, nfds;
      fd_set readfds, exceptfds;
      struct timeval timeout;

      FD_ZERO (&readfds);
      FD_SET (manager_socket, &readfds);
      FD_ZERO (&exceptfds);
      FD_SET (manager_socket, &exceptfds);
      nfds = manager_socket + 1;

      if ((time (NULL) - last_schedule_time) > SCHEDULE_PERIOD)
        {
          if (manage_schedule (fork_connection_for_schedular))
            exit (EXIT_FAILURE);
          last_schedule_time = time (NULL);
        }

      timeout.tv_sec = SCHEDULE_PERIOD;
      timeout.tv_usec = 0;
      ret = select (nfds, &readfds, NULL, &exceptfds, &timeout);

      /* Error while selecting socket occurred. */
      if (ret == -1)
        {
          if (errno == EINTR)
            continue;
          g_critical ("%s: select failed: %s\n",
                      __FUNCTION__,
                      strerror (errno));
          exit (EXIT_FAILURE);
        }
      /* Have an incoming connection. */
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

      if (manage_schedule (fork_connection_for_schedular))
        exit (EXIT_FAILURE);
      last_schedule_time = time (NULL);
    }
  // unreachable
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
  int scanner_port, manager_port;

  /* Process options. */

  static gboolean migrate_database = FALSE;
  static gboolean update_nvt_cache = FALSE;
  static gboolean rebuild_nvt_cache = FALSE;
  static gboolean foreground = FALSE;
  static gboolean print_version = FALSE;
  static gchar *manager_address_string = NULL;
  static gchar *manager_port_string = NULL;
  static gchar *scanner_address_string = NULL;
  static gchar *scanner_port_string = NULL;
  static gchar *rc_name = NULL;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry option_entries[]
    = {
        { "database", 'd', 0, G_OPTION_ARG_STRING, &database, "Use <file> as database.", "<file>" },
        { "foreground", 'f', 0, G_OPTION_ARG_NONE, &foreground, "Run in foreground.", NULL },
        { "listen", 'a', 0, G_OPTION_ARG_STRING, &manager_address_string, "Listen on <address>.", "<address>" },
        { "migrate", 'm', 0, G_OPTION_ARG_NONE, &migrate_database, "Migrate the database and exit.", NULL },
        { "otp", '\0', 0, G_OPTION_ARG_NONE, &otp, "Serve OTP too.", NULL },
        { "port", 'p', 0, G_OPTION_ARG_STRING, &manager_port_string, "Use port number <number>.", "<number>" },
        { "rebuild", '\0', 0, G_OPTION_ARG_NONE, &rebuild_nvt_cache, "Rebuild the NVT cache and exit.", NULL },
        { "slisten", 'l', 0, G_OPTION_ARG_STRING, &scanner_address_string, "Scanner (openvassd) address.", "<address>" },
        { "sport", 's', 0, G_OPTION_ARG_STRING, &scanner_port_string, "Scanner (openvassd) port number.", "<number>" },
        { "update", 'u', 0, G_OPTION_ARG_NONE, &update_nvt_cache, "Update the NVT cache and exit.", NULL },
        { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Print progress messages.", NULL },
        { "version", '\0', 0, G_OPTION_ARG_NONE, &print_version, "Print version and exit.", NULL },
        { NULL }
      };

  option_context = g_option_context_new ("- OpenVAS security scanner manager");
  g_option_context_add_main_entries (option_context, option_entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      g_option_context_free (option_context);
      g_critical ("%s: %s\n\n", __FUNCTION__, error->message);
      exit (EXIT_FAILURE);
    }
  g_option_context_free (option_context);

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

  /* Switch to UTC for scheduling. */

  if (setenv ("TZ", "utc 0", 1) == -1)
    {
      g_critical ("%s: failed to set timezone\n", __FUNCTION__);
      exit (EXIT_FAILURE);
    }
  tzset ();

  /* Setup logging. */

  rc_name = g_build_filename (OPENVAS_SYSCONF_DIR,
                              "openvasmd_log.conf",
                              NULL);
  if (g_file_test (rc_name, G_FILE_TEST_EXISTS))
    log_config = load_log_configuration (rc_name);
  g_free (rc_name);
  setup_log_handlers (log_config);

  tracef ("   OpenVAS Manager\n");

  if (migrate_database)
    {
      tracef ("   Migrating database.\n");

      /* Migrate the database to the version supported by this manager. */
      switch (manage_migrate (log_config, database))
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

  if (scanner_address_string == NULL)
    scanner_address_string = OPENVASSD_ADDRESS;

  if (scanner_port_string)
    {
      scanner_port = atoi (scanner_port_string);
      if (scanner_port <= 0 || scanner_port >= 65536)
        {
          g_critical ("%s: Scanner port must be a number between 0 and 65536\n",
                      __FUNCTION__);
          free_log_configuration (log_config);
          exit (EXIT_FAILURE);
        }
      scanner_port = htons (scanner_port);
    }
  else
    {
      struct servent *servent = getservbyname ("omp", "tcp");
      if (servent)
        // FIX free servent?
        scanner_port = servent->s_port;
      else
        scanner_port = htons (OPENVASSD_PORT);
    }

  if (update_nvt_cache || rebuild_nvt_cache)
    {
      /* Run the NVT caching manager: update NVT cache and then exit. */

      return update_or_rebuild_nvt_cache (update_nvt_cache,
                                          scanner_address_string,
                                          scanner_port);
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
      struct servent *servent = getservbyname ("otp", "tcp");
      if (servent)
        // FIX free servent?
        manager_port = servent->s_port;
      else
        manager_port = htons (OPENVASMD_PORT);
    }

#if 0
  /* Initialise scanner information needed by `cleanup'. */

  scanner.preferences = NULL;
  scanner.rules = NULL;
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

  switch (init_ompd (log_config, 0, database))
    {
      case 0:
        break;
      case -2:
        g_critical ("%s: database is wrong version\n", __FUNCTION__);
        free_log_configuration (log_config);
        exit (EXIT_FAILURE);
        break;
      case -3:
        g_critical ("%s: database must be initialised"
                    " (with --update or --rebuild)\n",
                    __FUNCTION__);
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
  if (signal (SIGTERM, handle_sigterm) == SIG_ERR   /* RATS: ignore */
      || signal (SIGABRT, handle_sigabrt) == SIG_ERR /* RATS: ignore */
      || signal (SIGINT, handle_sigint) == SIG_ERR  /* RATS: ignore */
      || signal (SIGHUP, handle_sighup) == SIG_ERR  /* RATS: ignore */
      || signal (SIGSEGV, handle_sigsegv) == SIG_ERR /* RATS: ignore */
      || signal (SIGCHLD, SIG_IGN) == SIG_ERR)      /* RATS: ignore */
    {
      g_critical ("%s: failed to register signal handler\n", __FUNCTION__);
      exit (EXIT_FAILURE);
    }

  /* Setup the scanner address. */

  scanner_address.sin_family = AF_INET;
  scanner_address.sin_port = scanner_port;
  if (!inet_aton (scanner_address_string, &scanner_address.sin_addr))
    {
      g_critical ("%s: failed to create scanner address %s\n",
                  __FUNCTION__,
                  scanner_address_string);
      exit (EXIT_FAILURE);
    }

  /* Setup security. */

  if (openvas_server_new (GNUTLS_SERVER,
                          CACERT,
                          SCANNERCERT,
                          SCANNERKEY,
                          &client_session,
                          &client_credentials))
    {
      g_critical ("%s: client server initialisation failed\n",
                  __FUNCTION__);
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

  {
    int optval = 1;
    if (setsockopt (manager_socket,
                    SOL_SOCKET, SO_REUSEADDR,
                    &optval, sizeof (int)))
      {
        g_critical ("%s: failed to set SO_REUSEADDR on manager socket: %s\n",
                    __FUNCTION__,
                    strerror (errno));
        exit (EXIT_FAILURE);
      }
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
          scanner_address_string,
          ntohs (scanner_address.sin_port));

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

  if (pidfile_create ("openvasmd")) exit (EXIT_FAILURE);

  /* Initialize the authentication system. */
  openvas_auth_init ();

  /* Initialise the process for manage_schedule. */

  init_manage_process (0, database);

  /* Enter the main forever-loop. */

  main_loop ();

  return EXIT_SUCCESS;
}
