/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: common OMP and OTP code.
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
 * @file  oxpd.c
 * @brief Globals shared between the OpenVAS Manager OMP and OTP daemons.
 */

#include "oxpd.h"
#include "tracef.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if FROM_BUFFER_SIZE > SSIZE_MAX
#error FROM_BUFFER_SIZE too big for `read'
#endif

/**
 * @brief Buffer of input from the client.
 */
char from_client[FROM_BUFFER_SIZE];

/**
 * @brief Buffer of input from the server.
 */
char from_server[FROM_BUFFER_SIZE];

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

/**
 * @brief The IP address of openvasd, "the server".
 */
struct sockaddr_in server_address;

/**
 * @brief Read and return the type of protocol from the client.
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
  char* from_client_current;
  time_t start_time;

  /* Turn on blocking. */
  // FIX get flags first
  if (fcntl (client_socket, F_SETFL, 0L) == -1)
    {
      perror ("Failed to set client socket flag (read_protocol)");
      return PROTOCOL_FAIL;
    }

  /* Read from the client, checking the protocol when a newline or return
   * is read.  Fail if reading the protocol takes too long. */
  if (time (&start_time) == -1)
    {
      perror ("Failed to get current time");
      return PROTOCOL_FAIL;
    }
  ret = PROTOCOL_FAIL;
  from_client_current = from_client + from_client_end;
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
          perror ("Failed to get now (0)");
          return PROTOCOL_FAIL;
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
          perror ("Select (read_protocol) failed");
          break;
        }
      if (select_ret > 0)
        {
          if (FD_ISSET (client_socket, &exceptfds))
            {
              fprintf (stderr, "Exception in select.\n");
              break;
            }
          if (FD_ISSET (client_socket, &readfds))
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
        }

      if (time (&now) == -1)
        {
          perror ("Failed to get now (0)");
          return PROTOCOL_FAIL;
        }
      if ((now - start_time) >= READ_PROTOCOL_TIMEOUT)
        {
          tracef ("protocol timeout (2)\n");
          ret = PROTOCOL_TIMEOUT;
          break;
        }
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
