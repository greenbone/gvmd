/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: common OMP and OTP code.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
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
 * @file  oxpd.c
 * @brief Globals shared between the OpenVAS Manager OMP and OTP daemons.
 */

#include "oxpd.h"
#include "tracef.h"
#include "logf.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
 * @brief The OTP initialisation string.
 */
#define OTP_INIT_STRING "< OTP/1.0 >\n"

/**
 * @brief The OTP initialisation string.
 */
#define OTP_INIT_STRING_2 "< OTP/1.1 >\n"

/**
 * @brief Read and return the type of protocol from the client.
 *
 * For OMP, this may read in OMP commands while determining the protocol,
 * so the client must be sure to process the input before selecting
 * on client_socket again.
 *
 * @param[in]  client_session  The TLS session with the client.
 * @param[in]  client_socket   The socket connected to the client.
 *
 * @return PROTOCOL_FAIL, PROTOCOL_CLOSE, PROTOCOL_OTP, PROTOCOL_OMP or
 *         PROTOCOL_TIMEOUT.
 */
protocol_read_t
read_protocol (gnutls_session_t* client_session, int client_socket)
{
  protocol_read_t ret;
  time_t start_time;
  int left;

  /** @todo Ensure that the blocking state is left at its original
   *        value, in case the callers has set it. */

  /* Turn on blocking. */
  if (fcntl (client_socket, F_SETFL, 0L) == -1)
    {
      g_warning ("%s: failed to set client socket flag: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return PROTOCOL_FAIL;
    }

  /* Read from the client, checking for the OTP initialisation string.
   * Fail if reading the protocol takes too long.
   *
   * Read only up to the first '>' and only as many characters as there
   * are in OTP_INIT_STRING.
   */
  if (time (&start_time) == -1)
    {
      g_warning ("%s: failed to get current time: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return PROTOCOL_FAIL;
    }
  ret = PROTOCOL_FAIL;
  left = strlen (OTP_INIT_STRING);
  while (from_client_end < FROM_BUFFER_SIZE)
    {
      int select_ret;
      int nfds;
      fd_set readfds, exceptfds;
      struct timeval timeout;
      time_t now;

      FD_ZERO (&readfds);
      FD_SET (client_socket, &readfds);
      FD_ZERO (&exceptfds);
      FD_SET (client_socket, &exceptfds);
      nfds = client_socket + 1;

      if (time (&now) == -1)
        {
          g_warning ("%s: failed to get now (0): %s\n",
                     __FUNCTION__,
                     strerror (errno));
          ret = PROTOCOL_FAIL;
          break;
        }
      timeout.tv_usec = 0;
      timeout.tv_sec = READ_PROTOCOL_TIMEOUT - (now - start_time);
      if (timeout.tv_sec <= 0)
        {
          tracef ("protocol timeout (1)\n");
          ret = PROTOCOL_TIMEOUT;
          break;
        }

      select_ret = select (nfds, &readfds, NULL, &exceptfds, &timeout);

      if (select_ret == -1)
        {
          if (errno == EINTR) continue;
          g_warning ("%s: select failed: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          break;
        }
      if (select_ret > 0)
        {
          if (FD_ISSET (client_socket, &exceptfds))
            {
              g_warning ("%s: exception in select\n", __FUNCTION__);
              break;
            }
          if (FD_ISSET (client_socket, &readfds))
            {
              ssize_t count;

              while (1)
                {
                  if (from_client_end == FROM_BUFFER_SIZE)
                    {
                      tracef ("read_protocol out of space in from_client\n");
                      return PROTOCOL_FAIL;
                    }

                  count = gnutls_record_recv (*client_session,
                                              from_client + from_client_end,
                                              left);
                  if (count == GNUTLS_E_INTERRUPTED)
                    /* Interrupted, try read again. */
                    continue;
                  if (count == GNUTLS_E_REHANDSHAKE)
                    /** @todo Rehandshake. */
                    /* Try again. */
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
                      g_warning ("%s: tls Alert %d: %s\n",
                                 __FUNCTION__,
                                 alert,
                                 gnutls_alert_get_name (alert));
                    }
                  g_warning ("%s: failed to read from client: %s\n",
                             __FUNCTION__,
                             gnutls_strerror (count));
                  break;
                }
              if (count == 0)
                {
                  /* End of file. */
                  ret = PROTOCOL_CLOSE;
                  break;
                }

#if TRACE || LOG
              logf ("<= client %.*s\n",
                    /* Cast is safe because count is bounded by from_client
                     * size. */
                    (int) count,
                    from_client + from_client_end);
#if TRACE_TEXT
              if (g_strstr_len (from_client + from_client_end,
                                count,
                                "<password>"))
                tracef ("<= client  Input may contain password, suppressed.\n");
              else
                tracef ("<= client  \"%.*s\"\n",
                        /* Cast is safe because count is bounded by
                         * from_client size. */
                        (int) count,
                        from_client + from_client_end);
#else
              tracef ("<= client  %i bytes\n", count);
#endif
#endif /* TRACE || LOG */

              from_client_end += count;
              left -= count;

              if (left == 0)
                {
                  if (strstr (from_client, OTP_INIT_STRING))
                    ret = PROTOCOL_OTP;
                  else if (strstr (from_client, OTP_INIT_STRING_2))
                    ret = PROTOCOL_OTP;
                  else
                    ret = PROTOCOL_OMP;
                  break;
                }
              else if (memchr (from_client,
                               '>',
                               strlen (OTP_INIT_STRING) - left))
                {
                  ret = PROTOCOL_OMP;
                  break;
                }
            }
        }

      if (time (&now) == -1)
        {
          g_warning ("%s: failed to get now (0): %s\n",
                     __FUNCTION__,
                     strerror (errno));
          ret = PROTOCOL_FAIL;
          break;
        }
      if ((now - start_time) >= READ_PROTOCOL_TIMEOUT)
        {
          tracef ("protocol timeout (2)\n");
          ret = PROTOCOL_TIMEOUT;
          break;
        }
    }

  /* Turn blocking back off. */
  if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      g_warning ("%s: failed to reset client socket flag: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return PROTOCOL_FAIL;
    }

  return ret;
}
