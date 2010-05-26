/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OMP daemon.
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
 * @file  ompd.c
 * @brief The OpenVAS Manager OMP daemon.
 *
 * This file defines the OpenVAS Manager daemon.  The Manager serves the OpenVAS
 * Management Protocol (OMP) to clients such as OpenVAS-Client.  The Manager
 * and OMP give clients full access to an OpenVAS Scanner.
 *
 * The library provides two functions: \ref init_ompd and \ref serve_omp.
 * \ref init_ompd initialises the daemon.
 * \ref serve_omp serves OMP to a single client socket until end of file is
 * reached on the socket.
 */

#include "ompd.h"
#include "oxpd.h"
#include "logf.h"
#include "omp.h"
#include "otp.h" // FIX for scanner_init_state
#include "ovas-mngr-comm.h"
#include "tracef.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openvas_server.h>

#ifdef S_SPLINT_S
/* FIX Weird that these are missing. */
/*@-exportheader@*/
int socket(int domain, int type, int protocol);
/*@=exportheader@*/
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
 * @brief Seconds of client idleness before manager closes client connection.
 */
#define CLIENT_TIMEOUT 900

/**
 * @brief File descriptor set mask: selecting on client read.
 */
#define FD_CLIENT_READ  1
/**
 * @brief File descriptor set mask: selecting on client write.
 */
#define FD_CLIENT_WRITE 2
/**
 * @brief File descriptor set mask: selecting on scanner read.
 */
#define FD_SCANNER_READ  4
/**
 * @brief File descriptor set mask: selecting on scanner write.
 */
#define FD_SCANNER_WRITE 8

/**
 * @brief Flag for running in NVT cache mode.
 */
static int ompd_nvt_cache_mode = 0;

/**
 * @brief Initialise the OMP library for the OMP daemon.
 *
 * @param[in]  log_config      Log configuration
 * @param[in]  nvt_cache_mode  0 operate normally, -1 just update NVT cache,
 *                             -2 just rebuild NVT cache.
 * @param[in]  database        Location of manage database.
 *
 * @return 0 success, -1 error, -2 database is wrong version, -3 database
 *         needs to be initialized from server.
 */
int
init_ompd (GSList *log_config, int nvt_cache_mode, const gchar *database)
{
  return init_omp (log_config, nvt_cache_mode, database);
}

/**
 * @brief Initialise a process forked within the OMP daemon.
 *
 * @param[in]  database  Location of manage database.
 */
void
init_ompd_process (const gchar *database)
{
  init_omp_process (0, database);
}

/**
 * @brief Read as much from the client as the \ref from_client buffer will hold.
 *
 * @param[in]  client_session  The TLS session with the client.
 * @param[in]  client_socket   The socket connected to the client.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_client buffer is full or -3 on reaching end of file.
 */
static int
read_from_client (gnutls_session_t* client_session,
                  /*@unused@*/ int client_socket)
{
  while (from_client_end < from_buffer_size)
    {
      ssize_t count;
      count = gnutls_record_recv (*client_session,
                                  from_client + from_client_end,
                                  from_buffer_size - from_client_end);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Got everything available, return to `select'. */
            return 0;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try read again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            {
              /* \todo Rehandshake. */
              tracef ("   FIX should rehandshake\n");
              continue;
            }
          if (gnutls_error_is_fatal ((int) count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*client_session);
              /*@dependent@*/
              const char* alert_name = gnutls_alert_get_name (alert);
              g_warning ("%s: TLS Alert %d: %s\n",
                         __FUNCTION__, alert, alert_name);
            }
          g_warning ("%s: failed to read from client: %s\n",
                     __FUNCTION__, gnutls_strerror ((int) count));
          return -1;
        }
      if (count == 0)
        /* End of file. */
        return -3;
      from_client_end += count;
    }

  /* Buffer full. */
  return -2;
}

// FIX combine with read_from_client
/**
 * @brief Read as much from the server as the \ref from_server buffer will hold.
 *
 * @param[in]  server_session  The TLS session with the server.
 * @param[in]  server_socket   The socket connected to the server.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_scanner buffer is full or -3 on reaching end of file.
 */
static int
read_from_server (gnutls_session_t* server_session,
                  /*@unused@*/ int server_socket)
{
  while (from_scanner_end < from_buffer_size)
    {
      ssize_t count;
      count = gnutls_record_recv (*server_session,
                                  from_scanner + from_scanner_end,
                                  from_buffer_size - from_scanner_end);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Got everything available, return to `select'. */
            return 0;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try read again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            {
              /* \todo Rehandshake. */
              tracef ("   FIX should rehandshake\n");
              continue;
            }
          if (gnutls_error_is_fatal (count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*server_session);
              /*@dependent@*/
              const char* alert_name = gnutls_alert_get_name (alert);
              g_warning ("%s: TLS Alert %d: %s\n",
                         __FUNCTION__, alert, alert_name);
            }
          g_warning ("%s: failed to read from server: %s\n",
                     __FUNCTION__,
                     gnutls_strerror (count));
          return -1;
        }
      if (count == 0)
        /* End of file. */
        return -3;
      assert (count > 0);
      from_scanner_end += count;
    }

  /* Buffer full. */
  return -2;
}

// @todo libs?
/**
 * @brief Write as much as possible from \ref to_client to the client.
 *
 * @param[in]  client_session  The client session.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as client accepted.
 */
static int
write_to_client (gnutls_session_t* client_session)
{
  while (to_client_start < to_client_end)
    {
      ssize_t count;
      count = gnutls_record_send (*client_session,
                                  to_client + to_client_start,
                                  to_client_end - to_client_start);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Wrote as much as client would accept. */
            return -2;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* \todo Rehandshake. */
            continue;
          g_warning ("%s: failed to write to client: %s\n",
                     __FUNCTION__,
                     gnutls_strerror ((int) count));
          return -1;
        }
      logf ("=> client %.*s\n",
            to_client_end - to_client_start,
            to_client + to_client_start);
      to_client_start += count;
      tracef ("=> client  %u bytes\n", (unsigned int) count);
    }
  tracef ("=> client  done\n");
  to_client_start = to_client_end = 0;

  /* Wrote everything. */
  return 0;
}

/**
 * @brief Write as much as possible from \ref to_scanner to the scanner.
 *
 * @param[in]  server_socket   The server socket.
 * @param[in]  server_session  The server session.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as scanner accepted,
 *         -3 did an initialisation step.
 */
static int
write_to_scanner (int scanner_socket, gnutls_session_t* scanner_session)
{
  switch (scanner_init_state)
    {
      case SCANNER_INIT_CONNECT_INTR:
      case SCANNER_INIT_TOP:
        switch (openvas_server_connect (scanner_socket,
                                        &scanner_address,
                                        scanner_session,
                                        scanner_init_state
                                        == SCANNER_INIT_CONNECT_INTR))
          {
            case 0:
              set_scanner_init_state (SCANNER_INIT_CONNECTED);
              /* Fall through to SCANNER_INIT_CONNECTED case below, to write
               * version string. */
              break;
            case -2:
              set_scanner_init_state (SCANNER_INIT_CONNECT_INTR);
              return -3;
            default:
              return -1;
          }
        /*@fallthrough@*/
      case SCANNER_INIT_CONNECTED:
        {
          char* string = "< OTP/1.0 >\n";
          scanner_init_offset = write_string_to_server (scanner_session,
                                                        string
                                                        + scanner_init_offset);
          if (scanner_init_offset == 0)
            set_scanner_init_state (SCANNER_INIT_SENT_VERSION);
          else
            {
              if (scanner_init_offset == -1)
                {
                  scanner_init_offset = 0;
                  return -1;
                }
            }
          break;
        }
      case SCANNER_INIT_SENT_VERSION:
      case SCANNER_INIT_GOT_VERSION:
        assert (0);
        break;
      case SCANNER_INIT_GOT_USER:
        {
          char* const user = "om\n";
          scanner_init_offset = write_string_to_server (scanner_session,
                                                        user + scanner_init_offset);
          if (scanner_init_offset == 0)
            set_scanner_init_state (SCANNER_INIT_SENT_USER);
          else if (scanner_init_offset == -1)
            {
              scanner_init_offset = 0;
              return -1;
            }
          break;
        }
      case SCANNER_INIT_SENT_USER:
        assert (0);
        break;
      case SCANNER_INIT_GOT_PASSWORD:
        {
          /* We don't use password based authentication, but have to send
           * something to stay compatible with OTP. */
          char* const password = "*\n";
          scanner_init_offset = write_string_to_server (scanner_session,
                                                        password + scanner_init_offset);
          if (scanner_init_offset == 0)
            set_scanner_init_state (SCANNER_INIT_SENT_PASSWORD);
            /* Fall through to send any available output. */
          else if (scanner_init_offset == -1)
            {
              scanner_init_offset = 0;
              return -1;
            }
        }
        break;
      case SCANNER_INIT_SENT_PASSWORD:
        assert (0);
        break;
      case SCANNER_INIT_SENT_COMPLETE_LIST:
      case SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE:
        assert (0);
        break;
      case SCANNER_INIT_GOT_MD5SUM:
        if (ompd_nvt_cache_mode)
          {
            static char* const ack = "CLIENT <|> COMPLETE_LIST <|> CLIENT\n";
            scanner_init_offset = write_string_to_server
                                   (scanner_session,
                                    ack + scanner_init_offset);
            if (scanner_init_offset == 0)
              set_scanner_init_state (ompd_nvt_cache_mode == -1
                                      ? SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE
                                      : SCANNER_INIT_SENT_COMPLETE_LIST);
            else if (scanner_init_offset == -1)
              {
                scanner_init_offset = 0;
                return -1;
              }
            break;
          }
        /*@fallthrough@*/
      case SCANNER_INIT_GOT_PLUGINS:
        {
          static char* const ack = "CLIENT <|> GO ON <|> CLIENT\n"
                                   "CLIENT <|> CERTIFICATES <|> CLIENT\n";
          scanner_init_offset = write_string_to_server
                                 (scanner_session,
                                  ack + scanner_init_offset);
          if (scanner_init_offset == 0)
            {
              if (ompd_nvt_cache_mode == -1)
                set_scanner_init_state (SCANNER_INIT_DONE_CACHE_MODE_UPDATE);
              else if (ompd_nvt_cache_mode == -2)
                set_scanner_init_state (SCANNER_INIT_DONE_CACHE_MODE);
              else
                set_scanner_init_state (SCANNER_INIT_DONE);
            }
          else if (scanner_init_offset == -1)
            {
              scanner_init_offset = 0;
              return -1;
            }
          else
            break;
        }
        /*@fallthrough@*/
      case SCANNER_INIT_DONE:
      case SCANNER_INIT_DONE_CACHE_MODE:
      case SCANNER_INIT_DONE_CACHE_MODE_UPDATE:
        while (1)
          switch (write_to_server_buffer (scanner_session))
            {
              case  0: return 0;
              case -1: return -1;
              case -2: return -2;
              case -3: continue;  /* Interrupted. */
            }
    }
  return -3;
}

/**
 * @brief Recreate a server session.
 *
 * @param  server_socket       Server socket.  0 to skip freeing
 * @param  server_session      Server session.
 * @param  server_credentials  Server credentials.
 *
 * @return New server socket, or -1 on error.
 */
int
recreate_session (int server_socket,
                  gnutls_session_t* server_session,
                  gnutls_certificate_credentials_t* server_credentials)
{
  if (server_socket
      && openvas_server_free (server_socket,
                              *server_session,
                              *server_credentials))
    return -1;
  /* Make the server socket. */
  server_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (server_socket == -1)
    {
      g_warning ("%s: failed to create server socket: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }
  if (openvas_server_new (GNUTLS_CLIENT,
                          CACERT,
                          CLIENTCERT,
                          CLIENTKEY,
                          server_session,
                          server_credentials))
    return -1;
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (server_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to set scanner socket flag: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      openvas_server_free (server_socket,
                           *server_session,
                           *server_credentials);
      return -1;
    }
  return server_socket;
}

/**
 * @brief Serve the OpenVAS Management Protocol (OMP).
 *
 * Loop reading input from the sockets, processing
 * the input, and writing any results to the appropriate socket.
 * Exit the loop on reaching end of file on the client socket.
 *
 * Read input from the client and scanner.
 * Process the input with \ref process_omp_client_input and
 * \ref process_otp_scanner_input.  Write the results to the client.
 *
 * \if STATIC
 *
 * Read input with \ref read_from_client and \ref read_from_server.
 * Write the results with \ref write_to_client.  Write to the server
 * with \ref write_to_scanner.
 *
 * \endif
 *
 * If compiled with logging (\ref LOG) then log all input and output
 * with \ref logf.
 *
 * If client_socket is 0 or less, then update the NVT cache and exit.
 *
 * @param[in]  client_session       The TLS session with the client.
 * @param[in]  scanner_session      The TLS session with the scanner.
 * @param[in]  client_credentials   The TSL client credentials.
 * @param[in]  scanner_credentials  The TSL server credentials.
 * @param[in]  client_socket        The socket connected to the client, if any.
 * @param[in]  scanner_socket_addr  The socket connected to the scanner.
 * @param[in]  database             Location of manage database.
 *
 * @return 0 on success, -1 on error.
 */
int
serve_omp (gnutls_session_t* client_session,
           gnutls_session_t* scanner_session,
           gnutls_certificate_credentials_t* client_credentials,
           gnutls_certificate_credentials_t* scanner_credentials,
           int client_socket, int* scanner_socket_addr,
           const gchar* database)
{
  int nfds, ret;
  time_t last_client_activity_time;
  fd_set readfds, exceptfds, writefds;
  int scanner_socket = *scanner_socket_addr;
  /* True if processing of the client input is waiting for space in the
   * to_scanner or to_client buffer. */
  short client_input_stalled;
  /* True if processing of the scanner input is waiting for space in the
   * to_client buffer. */
  gboolean scanner_input_stalled = FALSE;
  /* Client status flag.  Set to 0 when the client closes the connection
   * while the scanner is active. */
  short client_active = client_socket > 0;

  if (client_socket < 0)
    ompd_nvt_cache_mode = client_socket;

  if (ompd_nvt_cache_mode)
    tracef ("   Updating NVT cache.\n");
  else
    tracef ("   Serving OMP.\n");

  /* Initialise scanner information. */
  init_otp_data ();

  /* Initialise the XML parser and the manage library. */
  init_omp_process (ompd_nvt_cache_mode, database);
#if 0
  // FIX consider free_omp_data (); on return
  if (tasks) free_tasks ();
  if (current_scanner_preference) free (current_scanner_preference);
  free_credentials (&current_credentials);
  maybe_free_current_scanner_plugin_dependency ();
  maybe_free_scanner_preferences (); // old
  maybe_free_scanner_rules ();
  maybe_free_scanner_plugins_dependencies (); // old
#endif

  /* Initiate connection (to_scanner is empty so this will just init). */
  write_to_scanner (scanner_socket, scanner_session);

  if (client_active)
    {
      /* Process any client input already read.  This is necessary because the
       * caller may have called read_protocol, which may have read an entire OMP
       * command.  If only one command was sent and the manager selected here,
       * then the manager would sit waiting for more input from the client
       * before processing the one command.
       */
      ret = process_omp_client_input ();
      if (ret == 0)
        /* Processed all input. */
        client_input_stalled = 0;
      else if (ret == 3)
        {
          /* In the parent after a start_task fork.  Create a new
           * server session, leaving the existing session as it is
           * so that the child can continue using it. */
          // FIX probably need to close and free some of the existing
          //     session
          set_scanner_init_state (SCANNER_INIT_TOP);
          scanner_socket = recreate_session (0,
                                             scanner_session,
                                             scanner_credentials);
          if (scanner_socket == -1)
            {
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
          *scanner_socket_addr = scanner_socket;
          client_input_stalled = 0;
        }
      else if (ret == 2)
        {
          /* Now in a process forked to run a task, which has
           * successfully started the task.  Close the client
           * connection, as the parent process has continued the
           * session with the client. */
#if 0
          // FIX seems to close parent connections, maybe just do part of this
          openvas_server_free (client_socket,
                               *client_session,
                               *client_credentials);
#endif
          client_active = 0;
          client_input_stalled = 0;
        }
      else if (ret == -10)
        {
          /* Now in a process forked to run a task, which has
           * failed in starting the task. */
#if 0
          // FIX as above
          openvas_server_free (client_socket,
                               *client_session,
                               *client_credentials);
#endif
          return -1;
        }
      else if (ret == -1 || ret == -4)
        {
          /* Error.  Write rest of to_client to client, so that the
           * client gets any buffered output and the response to the
           * error. */
          write_to_client (client_session);
          openvas_server_free (client_socket,
                               *client_session,
                               *client_credentials);
          return -1;
        }
      else if (ret == -2)
        {
          /* to_scanner buffer full. */
          tracef ("   client input stalled 0\n");
          client_input_stalled = 1;
        }
      else if (ret == -3)
        {
          /* to_client buffer full. */
          tracef ("   client input stalled 0\n");
          client_input_stalled = 2;
        }
      else
        {
          /* Programming error. */
          assert (0);
          client_input_stalled = 0;
        }

      /* Record the start time. */
      if (time (&last_client_activity_time) == -1)
        {
          g_warning ("%s: failed to get current time: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          openvas_server_free (client_socket,
                               *client_session,
                               *client_credentials);
          return -1;
        }
    }
  else
    client_input_stalled = 0;

  /* Loop handling input from the sockets.
   *
   * That is, select on all the socket fds and then, as necessary
   *   - read from the client into buffer from_client
   *   - write to the scanner from buffer to_scanner
   *   - read from the scanner into buffer from_scanner
   *   - write to the client from buffer to_client.
   *
   * On reading from an fd, immediately try react to the input.  On reading
   * from the client call process_omp_client_input, which parses OMP
   * commands and may write to to_scanner and to_client.  On reading from
   * the scanner call process_otp_scanner_input, which updates information
   * kept about the scanner.
   *
   * There are a few complications here
   *   - the program must read from or write to an fd returned by select
   *     before selecting on the fd again,
   *   - the program need only select on the fds for writing if there is
   *     something to write,
   *   - similarly, the program need only select on the fds for reading
   *     if there is buffer space available,
   *   - the buffers from_client and from_scanner can become full during
   *     reading
   *   - a read from the client can be stalled by the to_scanner buffer
   *     filling up, or the to_client buffer filling up,
   *   - FIX a read from the scanner can, theoretically, be stalled by the
   *     to_scanner buffer filling up (during initialisation).
   */

  nfds = 1 + (client_socket > scanner_socket
              ? client_socket : scanner_socket);
  while (1)
    {
      int ret;
      struct timeval timeout;
      uint8_t fds;  /* What `select' is going to watch. */

      /* Setup for select. */

      /** @todo nfds must only include a socket if it's in >= one set. */

      fds = 0;
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_SET (scanner_socket, &exceptfds);

      // FIX shutdown if any eg read fails

      if (client_active)
        {
          // FIX time check error
          if ((CLIENT_TIMEOUT - (time (NULL) - last_client_activity_time))
              <= 0)
            {
              tracef ("client timeout (1)\n");
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              if (scanner_is_active ())
                {
                  client_active = 0;
                }
              else
                return 0;
            }
          else
            {
              FD_SET (client_socket, &exceptfds);
              if (from_client_end < from_buffer_size)
                {
                  FD_SET (client_socket, &readfds);
                  fds |= FD_CLIENT_READ;
                }
              if (to_client_start < to_client_end)
                {
                  FD_SET (client_socket, &writefds);
                  fds |= FD_CLIENT_WRITE;
                }
            }
        }

      if ((scanner_init_state == SCANNER_INIT_DONE
           || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE
           || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE_UPDATE
           || scanner_init_state == SCANNER_INIT_GOT_VERSION
           || scanner_init_state == SCANNER_INIT_SENT_COMPLETE_LIST
           || scanner_init_state == SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE
           || scanner_init_state == SCANNER_INIT_SENT_PASSWORD
           || scanner_init_state == SCANNER_INIT_SENT_USER
           || scanner_init_state == SCANNER_INIT_SENT_VERSION)
          && from_scanner_end < from_buffer_size)
        {
          FD_SET (scanner_socket, &readfds);
          fds |= FD_SCANNER_READ;
        }

      if (((scanner_init_state == SCANNER_INIT_TOP
            || scanner_init_state == SCANNER_INIT_DONE
            || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE
            || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE_UPDATE)
           && to_server_buffer_space () > 0)
          || scanner_init_state == SCANNER_INIT_CONNECT_INTR
          || scanner_init_state == SCANNER_INIT_CONNECTED
          || scanner_init_state == SCANNER_INIT_GOT_MD5SUM
          || scanner_init_state == SCANNER_INIT_GOT_PASSWORD
          || scanner_init_state == SCANNER_INIT_GOT_PLUGINS
          || scanner_init_state == SCANNER_INIT_GOT_USER)
        {
          FD_SET (scanner_socket, &writefds);
          fds |= FD_SCANNER_WRITE;
        }

      /* Select, then handle result. */

      /* Timeout periodically, so that process_omp_change runs periodically. */
      timeout.tv_usec = 0;
      timeout.tv_sec = 1;
      ret = select (nfds, &readfds, &writefds, &exceptfds, &timeout);
      if (ret < 0)
        {
          if (errno == EINTR)
            {
              if (process_omp_change () == -1)
                {
                  if (client_active)
                    openvas_server_free (client_socket,
                                         *client_session,
                                         *client_credentials);
                  return -1;
                }
              continue;
            }
          g_warning ("%s: child select failed: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          openvas_server_free (client_socket,
                               *client_session,
                               *client_credentials);
          return -1;
        }
      if (ret == 0)
        {
          if (process_omp_change () == -1)
            {
              if (client_active)
                openvas_server_free (client_socket,
                                     *client_session,
                                     *client_credentials);
              return -1;
            }
          continue;
        }

      if (client_active && FD_ISSET (client_socket, &exceptfds))
        {
          char ch;
          if (recv (client_socket, &ch, 1, MSG_OOB) < 1)
            {
              g_warning ("%s: after exception on client in child select:"
                         " recv failed\n",
                         __FUNCTION__);
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
          g_warning ("%s: after exception on client in child select:"
                     " recv: %c\n",
                     __FUNCTION__,
                     ch);
        }

      if (FD_ISSET (scanner_socket, &exceptfds))
        {
          char ch;
          if (recv (scanner_socket, &ch, 1, MSG_OOB) < 1)
            {
              g_warning ("%s: after exception on scanner in child select:"
                         " recv failed\n",
                         __FUNCTION__);
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
          g_warning ("%s: after exception on scanner in child select:"
                     " recv: %c\n",
                     __FUNCTION__,
                     ch);
        }

      if ((fds & FD_CLIENT_READ) == FD_CLIENT_READ
          && FD_ISSET (client_socket, &readfds))
        {
#if TRACE || LOG
          buffer_size_t initial_start = from_client_end;
#endif
          tracef ("   FD_CLIENT_READ\n");

          switch (read_from_client (client_session, client_socket))
            {
              case  0:       /* Read everything. */
                break;
              case -1:       /* Error. */
                openvas_server_free (client_socket,
                                     *client_session,
                                     *client_credentials);
                return -1;
              case -2:       /* from_client buffer full. */
                /* There may be more to read. */
                break;
              case -3:       /* End of file. */
                tracef ("   EOF reading from client.\n");
                openvas_server_free (client_socket,
                                     *client_session,
                                     *client_credentials);
                if (scanner_is_active ())
                  client_active = 0;
                else
                  return 0;
                break;
              default:       /* Programming error. */
                assert (0);
            }

          if (time (&last_client_activity_time) == -1)
            {
              g_warning ("%s: failed to get current time (1): %s\n",
                         __FUNCTION__,
                         strerror (errno));
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }

#if TRACE || LOG
          /* This check prevents output in the "asynchronous network
           * error" case. */
          if (from_client_end > initial_start)
            {
              logf ("<= client %.*s\n",
                    from_client_end - initial_start,
                    from_client + initial_start);
#if TRACE_TEXT
              if (g_strstr_len (from_client + initial_start,
                                from_client_end - initial_start,
                                "<password>"))
                tracef ("<= client  Input may contain password, suppressed.\n");
              else
                tracef ("<= client  \"%.*s\"\n",
                        from_client_end - initial_start,
                        from_client + initial_start);
#else
              tracef ("<= client  %i bytes\n",
                      from_client_end - initial_start);
#endif
            }
#endif /* TRACE || LOG */

          ret = process_omp_client_input ();
          if (ret == 0)
            /* Processed all input. */
            client_input_stalled = 0;
          else if (ret == 3)
            {
              /* In the parent after a start_task fork.  Create a new
               * server session, leaving the existing session as it is
               * so that the child can continue using it. */
              // FIX probably need to close and free some of the existing
              //     session
              set_scanner_init_state (SCANNER_INIT_TOP);
              scanner_socket = recreate_session (0,
                                                 scanner_session,
                                                 scanner_credentials);
              if (scanner_socket == -1)
                {
                  openvas_server_free (client_socket,
                                       *client_session,
                                       *client_credentials);
                  return -1;
                }
              nfds = 1 + (client_socket > scanner_socket
                          ? client_socket : scanner_socket);
              *scanner_socket_addr = scanner_socket;
              client_input_stalled = 0;
              /* Skip the rest of the loop because the scanner socket is
               * a new socket.  This is asking for select trouble, really. */
              continue;
            }
          else if (ret == 2)
            {
              /* Now in a process forked to run a task, which has
               * successfully started the task.  Close the client
               * connection, as the parent process has continued the
               * session with the client. */
#if 0
              // FIX seems to close parent connections, maybe just do part of this
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
#endif
              client_active = 0;
              client_input_stalled = 0;
            }
          else if (ret == -10)
            {
              /* Now in a process forked to run a task, which has
               * failed in starting the task. */
#if 0
              // FIX as above
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
#endif
              return -1;
            }
          else if (ret == -1 || ret == -4)
            {
              /* Error.  Write rest of to_client to client, so that the
               * client gets any buffered output and the response to the
               * error. */
              write_to_client (client_session);
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
          else if (ret == -2)
            {
              /* to_scanner buffer full. */
              tracef ("   client input stalled 1\n");
              client_input_stalled = 1;
              /* Break to write to_scanner. */
              break;
            }
          else if (ret == -3)
            {
              /* to_client buffer full. */
              tracef ("   client input stalled 2\n");
              client_input_stalled = 2;
              /* Break to write to_client. */
              break;
            }
          else
            {
              /* Programming error. */
              assert (0);
              client_input_stalled = 0;
            }
        }

      if ((fds & FD_SCANNER_READ) == FD_SCANNER_READ
          && FD_ISSET (scanner_socket, &readfds))
        {
#if TRACE || LOG
          buffer_size_t initial_start = from_scanner_end;
#endif
          tracef ("   FD_SCANNER_READ\n");

          switch (read_from_server (scanner_session, scanner_socket))
            {
              case  0:       /* Read everything. */
                break;
              case -1:       /* Error. */
                /* This may be because the scanner closed the connection
                 * at the end of a command. */ // FIX then should get eof (-3)
                set_scanner_init_state (SCANNER_INIT_TOP);
                break;
              case -2:       /* from_scanner buffer full. */
                /* There may be more to read. */
                break;
              case -3:       /* End of file. */
                set_scanner_init_state (SCANNER_INIT_TOP);
                if (client_active == 0)
                  /* The client has closed the connection, so exit. */
                  return 0;
                break;
              default:       /* Programming error. */
                assert (0);
            }

#if TRACE || LOG
          /* This check prevents output in the "asynchronous network
           * error" case. */
          if (from_scanner_end > initial_start)
            {
              /* Convert to UTF-8. */
              gsize size_dummy;
              gchar *utf8 = g_convert (from_scanner,
                                       from_scanner_end - initial_start,
                                       "UTF-8", "ISO_8859-1",
                                       NULL, &size_dummy, NULL);
              if (utf8 == NULL) return -1;

              logf ("<= scanner %s\n", utf8);
#if TRACE_TEXT
              tracef ("<= scanner %s\n", utf8);
#else
              tracef ("<= scanner  %i bytes\n",
                      from_scanner_end - initial_start);
#endif
              g_free (utf8);
            }
#endif /* TRACE || LOG */

          ret = process_otp_scanner_input ();
          if (ret == 0)
            /* Processed all input. */
            scanner_input_stalled = FALSE;
          else if (ret == 1)
            {
              /* Received scanner BYE.  Write out the rest of to_scanner (the
               * BYE ACK).  If the client is still connected then recreate the
               * scanner session, else exit. */
              write_to_scanner (scanner_socket, scanner_session);
              set_scanner_init_state (SCANNER_INIT_TOP);
              if (client_active == 0)
                return 0;
              scanner_socket = recreate_session (scanner_socket,
                                                 scanner_session,
                                                 scanner_credentials);
              if (scanner_socket == -1)
                {
                  openvas_server_free (client_socket,
                                       *client_session,
                                       *client_credentials);
                  return -1;
                }
              nfds = 1 + (client_socket > scanner_socket
                          ? client_socket : scanner_socket);
              *scanner_socket_addr = scanner_socket;
            }
          else if (ret == 2)
            {
              /* Bad login to scanner. */
              if (client_active == 0)
                return 0;
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
          else if (ret == -1)
           {
             /* Error. */
             openvas_server_free (client_socket,
                                  *client_session,
                                  *client_credentials);
             return -1;
           }
          else if (ret == -3)
            {
              /* to_scanner buffer full. */
              tracef ("   scanner input stalled\n");
              scanner_input_stalled = TRUE;
              /* Break to write to scanner. */
              break;
            }
          else
            /* Programming error. */
            assert (0);
        }

      if ((fds & FD_SCANNER_WRITE) == FD_SCANNER_WRITE
          && FD_ISSET (scanner_socket, &writefds))
        {
          /* Write as much as possible to the scanner. */

          switch (write_to_scanner (scanner_socket, scanner_session))
            {
              case  0:      /* Wrote everything in to_scanner. */
                break;
              case -1:      /* Error. */
                /* FIX This may be because the scanner closed the connection
                 * at the end of a command? */
                if (client_active)
                  openvas_server_free (client_socket,
                                       *client_session,
                                       *client_credentials);
                return -1;
              case -2:      /* Wrote as much as scanner was willing to accept. */
                break;
              case -3:      /* Did an initialisation step. */
                break;
              default:      /* Programming error. */
                assert (0);
            }
        }

      if ((fds & FD_CLIENT_WRITE) == FD_CLIENT_WRITE
          && FD_ISSET (client_socket, &writefds))
        {
          /* Write as much as possible to the client. */

          switch (write_to_client (client_session))
            {
              case  0:      /* Wrote everything in to_client. */
                break;
              case -1:      /* Error. */
                openvas_server_free (client_socket,
                                     *client_session,
                                     *client_credentials);
                return -1;
              case -2:      /* Wrote as much as client was willing to accept. */
                break;
              default:      /* Programming error. */
                assert (0);
            }

          if (time (&last_client_activity_time) == -1)
            {
              g_warning ("%s: failed to get current time (2): %s\n",
                         __FUNCTION__,
                         strerror (errno));
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
        }

      if (client_input_stalled)
        {
          /* Try process the client input, in case writing to the scanner
           * or client has freed some space in to_scanner or to_client. */

          ret = process_omp_client_input ();
          if (ret == 0)
            /* Processed all input. */
            client_input_stalled = 0;
          else if (ret == 3)
            {
              /* In the parent after a start_task fork.  Create a new
               * server session, leaving the existing session as it is
               * so that the child can continue using it. */
              // FIX probably need to close and free some of the existing
              //     session
              set_scanner_init_state (SCANNER_INIT_TOP);
              scanner_socket = recreate_session (0,
                                                 scanner_session,
                                                 scanner_credentials);
              if (scanner_socket == -1)
                {
                  openvas_server_free (client_socket,
                                       *client_session,
                                       *client_credentials);
                  return -1;
                }
              nfds = 1 + (client_socket > scanner_socket
                          ? client_socket : scanner_socket);
              *scanner_socket_addr = scanner_socket;
              /* Skip the rest of the loop because the scanner socket is
               * a new socket.  This is asking for select trouble, really. */
              continue;
            }
          else if (ret == 2)
            {
              /* Now in a process forked to run a task, which has
               * successfully started the task.  Close the client
               * connection, as the parent process has continued the
               * session with the client. */
#if 0
              // FIX seems to close parent connections, maybe just do part of this
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
#endif
              client_active = 0;
            }
          else if (ret == -10)
            {
              /* Now in a process forked to run a task, which has
               * failed in starting the task. */
#if 0
              // FIX as above
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
#endif
              return -1;
            }
          else if (ret == -1)
            {
              /* Error.  Write rest of to_client to client, so that the
               * client gets any buffered output and the response to the
               * error. */
              write_to_client (client_session);
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
          else if (ret == -2)
            {
              /* to_scanner buffer full. */
              tracef ("   client input still stalled (1)\n");
              client_input_stalled = 1;
            }
          else if (ret == -3)
            {
              /* to_client buffer full. */
              tracef ("   client input still stalled (2)\n");
              client_input_stalled = 2;
            }
          else
            {
              /* Programming error. */
              assert (0);
              client_input_stalled = 0;
            }
        }

      if (scanner_input_stalled)
        {
          /* Try process the scanner input, in case writing to the scanner
           * has freed some space in to_scanner. */

          ret = process_otp_scanner_input ();
          if (ret == 0)
            /* Processed all input. */
            scanner_input_stalled = FALSE;
          else if (ret == 1)
            {
              /* Received scanner BYE.  Write out the rest of to_scanner (the
               * BYE ACK).  If the client is still connected then recreate the
               * scanner session, else exit. */
              write_to_scanner (scanner_socket, scanner_session);
              set_scanner_init_state (SCANNER_INIT_TOP);
              if (client_active == 0)
                return 0;
              scanner_socket = recreate_session (scanner_socket,
                                                 scanner_session,
                                                 scanner_credentials);
              if (scanner_socket == -1)
                {
                  openvas_server_free (client_socket,
                                       *client_session,
                                       *client_credentials);
                  return -1;
                }
              nfds = 1 + (client_socket > scanner_socket
                          ? client_socket : scanner_socket);
              *scanner_socket_addr = scanner_socket;
            }
          else if (ret == 2)
            {
              /* Bad login to scanner. */
              if (client_active == 0)
                return 0;
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
          else if (ret == -1)
            {
              /* Error. */
              if (client_active)
                openvas_server_free (client_socket,
                                     *client_session,
                                     *client_credentials);
              return -1;
            }
          else if (ret == -3)
            /* to_scanner buffer still full. */
            tracef ("   scanner input stalled\n");
          else
            /* Programming error. */
            assert (0);
        }

      if (process_omp_change () == -1)
        {
          if (client_active)
            openvas_server_free (client_socket,
                                 *client_session,
                                 *client_credentials);
          return -1;
        }

      if (client_active)
        {
          /* Check if client connection is out of time. */
          time_t current_time;
          if (time (&current_time) == -1)
            {
              g_warning ("%s: failed to get current time (3): %s\n",
                         __FUNCTION__,
                         strerror (errno));
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
          if (last_client_activity_time - current_time >= CLIENT_TIMEOUT)
            {
              tracef ("client timeout (1)\n");
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              if (scanner_is_active ())
                client_active = 0;
              else
                return 0;
            }
        }

    } /* while (1) */

  openvas_server_free (client_socket,
                       *client_session,
                       *client_credentials);
  return 0;
}
