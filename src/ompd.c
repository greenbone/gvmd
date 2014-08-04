/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OMP daemon.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009, 2013 Greenbone Networks GmbH
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
#include "logf.h"
#include "omp.h"
/** @todo For scanner_init_state. */
#include "otp.h"
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

#include <openvas/misc/openvas_server.h>

#ifdef S_SPLINT_S
/** @todo Weird that these are missing. */
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

#ifndef S_SPLINT_S
#if FROM_BUFFER_SIZE > SSIZE_MAX
#error FROM_BUFFER_SIZE too big for "read"
#endif
#endif

/**
 * @brief Buffer of input from the client.
 */
char from_client[FROM_BUFFER_SIZE];

/**
 * @brief Buffer of input from the scanner.
 */
char from_scanner[FROM_BUFFER_SIZE];

/**
 * @brief Size of \ref from_client and \ref from_scanner data buffers, in bytes.
 */
buffer_size_t from_buffer_size = FROM_BUFFER_SIZE;

/**
 * @brief The start of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_start = 0;

/**
 * @brief The start of the data in the \ref from_scanner buffer.
 */
buffer_size_t from_scanner_start = 0;

/**
 * @brief The end of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_end = 0;

/**
 * @brief The end of the data in the \ref from_scanner buffer.
 */
buffer_size_t from_scanner_end = 0;

/**
 * @brief The IP address of openvassd, the "scanner".
 */
struct sockaddr_in scanner_address;

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
 * @param[in]  max_ips_per_target  Max number of IPs per target.
 * @param[in]  max_email_attachment_size  Max size of email attachments.
 * @param[in]  max_email_include_size     Max size of email inclusions.
 * @param[in]  progress        Function to update progress, or NULL.
 *
 * @return 0 success, -1 error, -2 database is wrong version, -3 database
 *         needs to be initialized from server, -4 max_ips_per_target out of
 *         range.
 */
int
init_ompd (GSList *log_config, int nvt_cache_mode, const gchar *database,
           int max_ips_per_target, int max_email_attachment_size,
           int max_email_include_size, void (*progress) ())
{
  return init_omp (log_config, nvt_cache_mode, database, max_ips_per_target,
                   max_email_attachment_size, max_email_include_size,
                   progress);
}

/**
 * @brief Initialise a process forked within the OMP daemon.
 *
 * @param[in]  database  Location of manage database.
 * @param[in]  disable   Commands to disable.
 */
void
init_ompd_process (const gchar *database, gchar **disable)
{
  init_omp_process (0, database, NULL, NULL, disable);
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
              /** @todo Rehandshake. */
              tracef ("   should rehandshake\n");
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

/** @todo Consider combining with read_from_client. */
/**
 * @brief Read as much from the server as the \ref from_scanner buffer will
 * @brief hold.
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
              /** @todo Rehandshake. */
              tracef ("   should rehandshake\n");
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

/** @todo Move to openvas-libraries? */
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
            /** @todo Rehandshake. */
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
 * @brief Send a response message to the client.
 *
 * Queue a message in \ref to_client.
 *
 * @param[in]  msg                   The message, a string.
 * @param[in]  write_to_client_data  Argument to \p write_to_client.
 *
 * @return TRUE if write to client failed, else FALSE.
 */
gboolean
ompd_send_to_client (const char* msg, void* write_to_client_data)
{
  assert (to_client_end <= TO_CLIENT_BUFFER_SIZE);
  assert (msg);

  while (((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end
         < strlen (msg))
    {
      buffer_size_t length;

      /* Too little space in to_client buffer for message. */

      switch (write_to_client (write_to_client_data))
        {
          case  0:      /* Wrote everything in to_client. */
            break;
          case -1:      /* Error. */
            tracef ("   %s full (%i < %zu); client write failed\n",
                    __FUNCTION__,
                    ((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end,
                    strlen (msg));
            return TRUE;
          case -2:      /* Wrote as much as client was willing to accept. */
            break;
          default:      /* Programming error. */
            assert (0);
        }

      length = ((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end;

      if (length > strlen (msg))
        break;

      memmove (to_client + to_client_end, msg, length);
      tracef ("-> client: %.*s\n", (int) length, msg);
      to_client_end += length;
      msg += length;
    }

  if (strlen (msg))
    {
      assert (strlen (msg)
              <= (((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end));
      memmove (to_client + to_client_end, msg, strlen (msg));
      tracef ("-> client: %s\n", msg);
      to_client_end += strlen (msg);
    }

  return FALSE;
}

/**
 * @brief Write as much as possible from the to_scanner buffer to the scanner.
 *
 * @param[in]  scanner_socket   The server socket.
 * @param[in]  scanner_session  The server session.
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
              switch (openvas_server_verify (*scanner_session))
                {
                  case 0:
                    break;
                  default:
                    return -1;
                }
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
          char* string = "< OTP/2.0 >\n";

          scanner_init_offset = write_string_to_server (scanner_session,
                                                        string
                                                        + scanner_init_offset);
          if (scanner_init_offset == 0)
            set_scanner_init_state (SCANNER_INIT_SENT_VERSION);
          else if (scanner_init_offset == -1)
            {
              scanner_init_offset = 0;
              return -1;
            }
          if (ompd_nvt_cache_mode)
            {
              string = "CLIENT <|> NVT_INFO <|> CLIENT\n";
              scanner_init_offset = write_string_to_server
                                     (scanner_session,
                                      string + scanner_init_offset);
              if (scanner_init_offset == -1)
                {
                  scanner_init_offset = 0;
                  return -1;
                }
            }
          break;
        }
      case SCANNER_INIT_SENT_VERSION:
        assert (0);
        break;
      case SCANNER_INIT_SENT_COMPLETE_LIST:
      case SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE:
        assert (0);
        break;
      case SCANNER_INIT_GOT_FEED_VERSION:
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
 * @param[in]  scanner_socket  Socket.
 *
 * @return 0 on success, -1 on error.
 */
int
wait_for_connection (int scanner_socket)
{
  while (1)
    {
      char ch;
      int ret;
      struct timeval timeout;
      fd_set exceptfds, writefds;

      timeout.tv_usec = 0;
      timeout.tv_sec = 1;
      FD_ZERO (&writefds);
      FD_ZERO (&exceptfds);
      FD_SET (scanner_socket, &writefds);
      FD_SET (scanner_socket, &exceptfds);

      ret = select (1 + scanner_socket, NULL, &writefds, &exceptfds, &timeout);
      if (ret < 0)
        {
          if (errno == EINTR)
            continue;
          g_warning ("%s: select failed (connect): %s\n",
                     __FUNCTION__,
                     strerror (errno));
          return -1;
        }

      /* Check for exception.  */
      if (FD_ISSET (scanner_socket, &exceptfds))
        {
          while (recv (scanner_socket, &ch, 1, MSG_OOB) < 1)
            {
              if (errno == EINTR)
                continue;
              g_warning ("%s: after exception on scanner in child select:"
                         " recv failed (connect)\n",
                         __FUNCTION__);
              return -1;
            }
          g_warning ("%s: after exception on scanner in child select:"
                     " recv (connect): %c\n",
                     __FUNCTION__,
                     ch);
        }

      if (FD_ISSET (scanner_socket, &writefds))
        break;
    }
  return 0;
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
 * @param[in]  disable              Commands to disable.
 * @param[in]  progress             Function to mark progress, or NULL.
 *
 * @return 0 on success, 1 failed to connect to scanner for cache
 *         update/rebuild, 2 scanner still loading, -1 on error.
 */
int
serve_omp (gnutls_session_t* client_session,
           gnutls_session_t* scanner_session,
           gnutls_certificate_credentials_t* client_credentials,
           gnutls_certificate_credentials_t* scanner_credentials,
           int client_socket, int* scanner_socket_addr,
           const gchar* database, gchar **disable, void (*progress) ())
{
  int nfds, ret;
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
    infof ("   Updating NVT cache.\n");
  else
    tracef ("   Serving OMP.\n");

  /* Initialise scanner information. */
  init_otp_data ();

  /* Initialise the XML parser and the manage library. */
  init_omp_process (ompd_nvt_cache_mode,
                    database,
                    (int (*) (const char*, void*)) ompd_send_to_client,
                    (void*) client_session,
                    disable);
#if 0
  /** @todo Consider free_omp_data (); on return. */
  if (tasks) free_tasks ();
  if (current_scanner_preference) free (current_scanner_preference);
  free_credentials (&current_credentials);
  maybe_free_scanner_preferences (); // old
#endif

  /* Initiate connection (to_scanner is empty so this will just init). */
  while ((ret = write_to_scanner (scanner_socket, scanner_session)) == -3
         && scanner_init_state == SCANNER_INIT_CONNECT_INTR)
    if (wait_for_connection (scanner_socket))
      {
        if (client_socket > 0)
          openvas_server_free (client_socket,
                               *client_session,
                               *client_credentials);
        return -1;
      }
  if (ret == -1)
    {
      if (ompd_nvt_cache_mode)
        return 1;
      scanner_up = 0;
    }

  client_input_stalled = 0;

  /** @todo Confirm and clarify complications, especially last one. */
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
   *     filling up, or the to_client buffer filling up (in which case
   *     process_omp_client_input will try to write the to_client buffer
   *     itself),
   *   - a read from the scanner can, theoretically, be stalled by the
   *     to_scanner buffer filling up (during initialisation).
   */

  nfds = 1 + (client_socket > scanner_socket
              ? client_socket : scanner_socket);
  while (1)
    {
      int ret;
      uint8_t fd_info;  /* What `select' is going to watch. */
      char recv_ch;

      /* Setup for select. */

      /** @todo nfds must only include a socket if it's in >= one set. */

      fd_info = 0;
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      if (scanner_is_up ())
        FD_SET (scanner_socket, &exceptfds);

      /** @todo Shutdown on failure (for example, if a read fails). */

      if (client_active)
        {
          FD_SET (client_socket, &exceptfds);
          /* See whether to read from the client.  */
          if (from_client_end < from_buffer_size)
            {
              FD_SET (client_socket, &readfds);
              fd_info |= FD_CLIENT_READ;
            }
          /* See whether to write to the client.  */
          if (to_client_start < to_client_end)
            {
              FD_SET (client_socket, &writefds);
              fd_info |= FD_CLIENT_WRITE;
            }
        }

      /* See whether we need to read from the scannner.  */
      if (scanner_is_up ()
          && (scanner_init_state == SCANNER_INIT_DONE
              || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE
              || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE_UPDATE
              || scanner_init_state == SCANNER_INIT_SENT_COMPLETE_LIST
              || scanner_init_state == SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE
              || scanner_init_state == SCANNER_INIT_SENT_VERSION)
          && from_scanner_end < from_buffer_size)
        {
          FD_SET (scanner_socket, &readfds);
          fd_info |= FD_SCANNER_READ;
        }

      /* See whether we need to write to the scanner.  */
      if (scanner_is_up ()
          && (((scanner_init_state == SCANNER_INIT_TOP
                || scanner_init_state == SCANNER_INIT_DONE
                || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE
                || scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE_UPDATE)
               && to_server_buffer_space () > 0)
              || scanner_init_state == SCANNER_INIT_CONNECT_INTR
              || scanner_init_state == SCANNER_INIT_CONNECTED
              || scanner_init_state == SCANNER_INIT_GOT_FEED_VERSION
              || scanner_init_state == SCANNER_INIT_GOT_PLUGINS))
        {
          FD_SET (scanner_socket, &writefds);
          fd_info |= FD_SCANNER_WRITE;
        }

      tracef ("   SELECT ON:%s%s%s%s",
              (fd_info & FD_CLIENT_READ)? " read-client":"",
              (fd_info & FD_CLIENT_WRITE)? " write-client":"",
              (fd_info & FD_SCANNER_READ)? " read-scanner":"",
              (fd_info & FD_SCANNER_WRITE)? " write-scanner":"");

      /* Select, then handle result.  Due to GNUTLS internal buffering
       * we test for pending records first and emulate a select call
       * in that case.  Note, that GNUTLS guarantees that writes are
       * not buffered.  Note also that GNUTLS versions < 3 did not
       * exhibit a problem in OpenVAS due to a different buffering
       * strategy.  */
      ret = 0;
      if ((fd_info & FD_CLIENT_READ)
          && gnutls_record_check_pending (*client_session))
        {
          FD_ZERO (&exceptfds);
          FD_ZERO (&readfds);
          FD_ZERO (&writefds);
          ret++;
          FD_SET (client_socket, &readfds);
        }
      if (fd_info & FD_SCANNER_READ)
        {
          if (gnutls_record_check_pending (*scanner_session))
            {
              if (!ret)
                {
                  FD_ZERO (&exceptfds);
                  FD_ZERO (&readfds);
                  FD_ZERO (&writefds);
                }
              ret++;
              FD_SET (scanner_socket, &readfds);
            }
          else if (recv (scanner_socket, &recv_ch, 1, MSG_PEEK) == 0)
            {
              /* Scanner has gone down.  Exit. */
              if (client_active)
                openvas_server_free (client_socket,
                                     *client_session,
                                     *client_credentials);
              return -1;
            }
        }

      if (!ret)
        {
          /* Timeout periodically, so that process_omp_change runs
           * periodically. */
          struct timeval timeout;

          timeout.tv_usec = 0;
          timeout.tv_sec = 1;
          ret = select (nfds, &readfds, &writefds, &exceptfds, &timeout);
        }
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
          if (client_active)
            openvas_server_free (client_socket,
                                 *client_session,
                                 *client_credentials);
          return -1;
        }


      /* When using the Scanner, check if the socket has closed. */
      if (scanner_is_up ()
          && (((fd_info & FD_SCANNER_READ) == FD_SCANNER_READ)
              || ((fd_info & FD_SCANNER_WRITE) == FD_SCANNER_WRITE))
          && (((fd_info & FD_SCANNER_READ) == FD_SCANNER_READ)
               ? FD_ISSET (scanner_socket, &readfds) == 0
               : 1)
          && (((fd_info & FD_SCANNER_WRITE) == FD_SCANNER_WRITE)
               ? FD_ISSET (scanner_socket, &writefds) == 0
               : 1)
          && (recv (scanner_socket, &recv_ch, 1, MSG_PEEK) == 0))
        {
          /* Scanner has gone down.  Exit. */
          if (client_active)
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

      /* Check for exceptions on the client socket. */
      if (client_active && FD_ISSET (client_socket, &exceptfds))
        {
          char ch;
          while (recv (client_socket, &ch, 1, MSG_OOB) < 1)
            {
              if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
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

      /* Check for exceptions on the scanner socket. */
      if (scanner_is_up () && FD_ISSET (scanner_socket, &exceptfds))
        {
          char ch;
          while (recv (scanner_socket, &ch, 1, MSG_OOB) < 1)
            {
              if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
              g_warning ("%s: after exception on scanner in child select:"
                         " recv failed\n",
                         __FUNCTION__);
              if (client_active)
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

      /* Read any data from the client. */
      if ((fd_info & FD_CLIENT_READ) == FD_CLIENT_READ
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
              /** @todo Probably need to close and free some of the existing
               *        session. */
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
              /** @todo This seems to close the parent connections.  Maybe just do
               *        part of this? */
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
#endif
              client_active = 0;
              client_input_stalled = 0;
            }
          else if (ret == 4)
            {
              /* Now in a process forked for some operation which has
               * successfully completed.  Close the client connection,
               * and exit, as the parent process has continued the
               * session with the client. */
#if 0
              /** @todo This seems to close the parent connections.  Maybe just do
               *        part of this? */
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
#endif
              return 0;
            }
          else if (ret == -10)
            {
              /* Now in a process forked to run a task, which has
               * failed in starting the task. */
#if 0
              /** @todo This seems to close the parent connections.  Maybe just do
               *        part of this? */
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

      /* Read any data from the scanner. */
      if (scanner_is_up ()
          && ((fd_info & FD_SCANNER_READ) == FD_SCANNER_READ)
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
                 * at the end of a command. */
                /** @todo Then should get EOF (-3). */
                set_scanner_init_state (SCANNER_INIT_TOP);
                if (client_active)
                  openvas_server_free (client_socket,
                                       *client_session,
                                       *client_credentials);
                return -1;
                break;
              case -2:       /* from_scanner buffer full. */
                /* There may be more to read. */
                break;
              case -3:       /* End of file. */
                set_scanner_init_state (SCANNER_INIT_TOP);
                if (client_active == 0)
                  /* The client has closed the connection, so exit. */
                  return 0;
                /* Scanner went down, exit. */
                if (client_active)
                  openvas_server_free (client_socket,
                                       *client_session,
                                       *client_credentials);
                return -1;
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

          ret = process_otp_scanner_input (progress);
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
          else if (ret == 3)
            {
              /* Calls via serve_client() should continue. */
              scanner_up = 0;
              if (ompd_nvt_cache_mode)
                return 2;
              scanner_input_stalled = FALSE;
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

      /* Write any data to the scanner. */
      if (scanner_is_up ()
          && ((fd_info & FD_SCANNER_WRITE) == FD_SCANNER_WRITE)
          && FD_ISSET (scanner_socket, &writefds))
        {
          /* Write as much as possible to the scanner. */

          switch (write_to_scanner (scanner_socket, scanner_session))
            {
              case  0:      /* Wrote everything in to_scanner. */
                break;
              case -1:      /* Error. */
                /** @todo This may be because the scanner closed the connection
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

      /* Write any data to the client. */
      if ((fd_info & FD_CLIENT_WRITE) == FD_CLIENT_WRITE
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
              /** @todo Probably need to close and free some of the existing
               *        session. */
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
              /** @todo This seems to close the parent connections.  Maybe just do
               *        part of this? */
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
#endif
              client_active = 0;
            }
          else if (ret == 4)
            {
              /* Now in a process forked for some operation which has
               * successfully completed.  Close the client connection,
               * and exit, as the parent process has continued the
               * session with the client. */
#if 0
              /** @todo This seems to close the parent connections.  Maybe just do
               *        part of this? */
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
#endif
              return 0;
            }
          else if (ret == -10)
            {
              /* Now in a process forked to run a task, which has
               * failed in starting the task. */
#if 0
              /** @todo This seems to close the parent connections.  Maybe just do
               *        part of this? */
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

      if (scanner_is_up () && scanner_input_stalled)
        {
          /* Try process the scanner input, in case writing to the scanner
           * has freed some space in to_scanner. */

          ret = process_otp_scanner_input (progress);
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

    } /* while (1) */

  if (client_active)
    openvas_server_free (client_socket,
                         *client_session,
                         *client_credentials);
  return 0;
}
