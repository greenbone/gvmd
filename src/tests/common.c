/* Common test utilities.
 * $Id$
 * Description: Common utilities for tests.
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
 * @file common.c
 * @brief Common utilities for tests.
 *
 * Here there are lower level facilities for communicating with the
 * manager, and a function to setup a test.
 *
 * The functions are
 * \ref connect_to_manager_host_port,
 * \ref connect_to_manager,
 * \ref close_manager_connection, and
 * \ref setup_test.
 */

/**
 * @brief Manager (openvasmd) port.
 */
#define OPENVASMD_PORT 9390

/**
 * @brief Manager (openvasmd) address.
 */
#define OPENVASMD_ADDRESS "127.0.0.1"

/**
 * @brief Verbose output flag.
 *
 * Only consulted if compiled with TRACE non-zero.
 */
int verbose = 0;

#include "common.h"

#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

#include <openvas/openvas_server.h>
#include <openvas/openvas_logging.h>

/**
 * @brief Manager address.
 */
struct sockaddr_in address;

/**
 * @brief The log stream, for ovas-mngr-comm.
 */
FILE* log_stream = NULL;


/* Low level manager communication. */

/**
 * @brief Connect to the manager using a given host and port.
 *
 * If environment variable OPENVAS_TEST_WAIT is set then read a character
 * after connecting.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 * @param[in]  host     Host to connect to.
 * @param[in]  port     Port to connect to.
 *
 * @return 0 on success, -1 on error.
 */
int
connect_to_manager_host_port (gnutls_session_t * session,
                              const char *host, int port)
{
  int ret = openvas_server_open (session, host, port);
  if (getenv ("OPENVAS_TEST_WAIT")
      && strcmp (getenv ("OPENVAS_TEST_WAIT"), "0"))
    {
      fprintf (stdout, "Connected, press a key when ready.\n");
      getchar ();
    }
  return ret;
}

/**
 * @brief Connect to the manager.
 *
 * If the environment variables OPENVAS_TEST_HOST is set then connect to
 * that host, otherwise connect to host 127.0.0.1.
 *
 * If the environment variables OPENVAS_TEST_PORT is set then connect to
 * that port, otherwise connect to port 1242.
 *
 * @param[in]  session  Pointer to GNUTLS session.
 *
 * @return 0 on success, -1 on error.
 */
int
connect_to_manager (gnutls_session_t * session)
{
  char* env_host = getenv ("OPENVAS_TEST_HOST");
  char* env_port = getenv ("OPENVAS_TEST_PORT");
  return connect_to_manager_host_port (session,
                                       env_host ? env_host
                                                : OPENVASMD_ADDRESS,
                                       env_port ? atoi (env_port)
                                                : OPENVASMD_PORT);
}

/**
 * @brief Close the connection to the manager.
 *
 * @param[in]  socket   Socket connected to manager (from \ref connect_to_manager).
 * @param[in]  session  GNUTLS session with manager.
 *
 * @return 0 on success, -1 on error.
 */
int
close_manager_connection (int socket, gnutls_session_t session)
{
  return openvas_server_close (socket, session);
}


/* Setup. */

/**
 * @brief Setup a test.
 *
 * Set up the verbosity flag according to the OPENVAS_TEST_VERBOSE
 * environment variable, prepare signal handling and setup the log handler.
 *
 * Each test should call this at the very beginning of the test.
 */
void
setup_test ()
{
  char* env_verbose = getenv ("OPENVAS_TEST_VERBOSE");
  if (env_verbose) verbose = strcmp (env_verbose, "0");
  signal (SIGPIPE, SIG_IGN);
  g_log_set_default_handler ((GLogFunc) openvas_log_func,
                             NULL);
}
