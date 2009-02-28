/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the Comm Library.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2009 Intevation GmbH
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
 * @file ovas-mngr-comm.c
 * @brief API for communication between openvas-manager and openvas-server
 *
 * This file contains an API for communicating with an openvas-server
 * which uses OTP as protocol.
 */

/**
 * @brief Trace flag.
 *
 * 0 to turn off all tracing messages.
 */
#define TRACE 1

#include <errno.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "tracef.h"

/**
 * @brief The size of the \ref to_server data buffer.
 */
#define TO_SERVER_BUFFER_SIZE 8192

/**
 * @brief Buffer of output to the server.
 */
char to_server[TO_SERVER_BUFFER_SIZE];

/**
 * @brief The end of the data in the \ref to_server buffer.
 */
int to_server_end = 0;

/**
 * @brief The start of the data in the \ref to_server buffer.
 */
int to_server_start = 0;

/**
 * @brief Get the number of characters free in the \ref to_server buffer.
 *
 * @return Number of characters free in \ref to_server.  0 when full.
 */
unsigned int
to_server_buffer_space ()
{
  return to_server_end - to_server_start;
}

/**
 * @brief Send a message to the server.
 *
 * @param[in]  msg  The message, a string.
 *
 * @return 0 for success, for any other values a failure happened.
 */
int
send_to_server (char * msg)
{
  if (TO_SERVER_BUFFER_SIZE - to_server_end < strlen (msg))
    return 1;

  memcpy (to_server + to_server_end, msg, strlen (msg));
  tracef ("-> server: %s\n", msg);
  to_server_end += strlen (msg);

  return 0;
}

/**
 * @brief Connect to the server.
 *
 * @param[in]  server_socket   Socket to connect to server.
 * @param[in]  server_address  Server address.
 * @param[in]  server_session  Session to connect to server.
 * @param[in]  interrupted     0 if first connect attempt, else retrying after
 *                             an interrupted connect.
 *
 * @return 0 on success, -1 on error, -2 on connect interrupt.
 */
int
connect_to_server (int server_socket,
                   struct sockaddr_in* server_address,
                   gnutls_session_t* server_session,
                   int interrupted)
{
  int ret;
  socklen_t ret_len = sizeof (ret);
  if (interrupted)
    {
      if (getsockopt (server_socket, SOL_SOCKET, SO_ERROR, &ret, &ret_len)
          == -1)
        {
          perror ("Failed to get socket option");
          return -1;
        }
      if (ret_len != sizeof (ret))
        {
          fprintf (stderr, "Weird option length from getsockopt: %i.\n",
                   ret_len);
          return -1;
        }
      if (ret)
        {
          if (errno == EINPROGRESS) return -2;
          perror ("Failed to connect to server");
          return -1;
        }
    }
  else if (connect (server_socket,
                    (struct sockaddr *) server_address,
                    sizeof (struct sockaddr_in))
           == -1)
    {
      if (errno == EINPROGRESS) return -2;
      perror ("Failed to connect to server");
      return -1;
    }
  tracef ("   Connected to server on socket %i.\n", server_socket);

  /* Complete setup of server session. */

  gnutls_transport_set_ptr (*server_session,
                            (gnutls_transport_ptr_t) server_socket);

  while (1)
    {
      int ret = gnutls_handshake (*server_session);
      if (ret >= 0)
        break;
      if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
        continue;
      fprintf (stderr, "Failed to shake hands with server.\n");
      gnutls_perror (ret);
      if (shutdown (server_socket, SHUT_RDWR) == -1)
        perror ("Failed to shutdown server socket");
      return -1;
    }

  return 0;
}

/**
 * @brief Write as much as possible from a string to the server.
 *
 * @param[in]  server_session  The server session.
 * @param[in]  string          The string.
 *
 * @return 0 wrote everything, -1 error, or the number of bytes written
 *         when the server accepted fewer bytes than given in string.
 */
int
write_string_to_server (gnutls_session_t* server_session, char* const string)
{
  char* point = string;
  char* end = string + strlen (string);
  while (point < end)
    {
      ssize_t count;
      count = gnutls_record_send (*server_session,
                                  point,
                                  end - point);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Wrote as much as server accepted. */
            return point - string;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* \todo Rehandshake. */
            continue;
          fprintf (stderr, "Failed to write to server.\n");
          gnutls_perror (count);
          return -1;
        }
      point += count;
      tracef ("=> server  (string) %i bytes\n", count);
    }
  tracef ("=> server  (string) done\n");
  /* Wrote everything. */
  return 0;
}


/**
 * @brief Write as much as possible from the internal buffer to the server.
 *
 * @param[in]  server_session  The server session.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as server accepted,
 *         -3 interrupted.
 */
int
write_to_server_buffer (gnutls_session_t* server_session)
{
  while (to_server_start < to_server_end)
    {
      ssize_t count;
      count = gnutls_record_send (*server_session,
                                  to_server + to_server_start,
                                  to_server_end - to_server_start);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Wrote as much as server accepted. */
            return -2;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            return -3;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* \todo Rehandshake. */
            continue;
          fprintf (stderr, "Failed to write to server.\n");
          gnutls_perror (count);
          return -1;
        }
      to_server_start += count;
      tracef ("=> server  %i bytes\n", count);
    }
  tracef ("=> server  done\n");
  to_server_start = to_server_end = 0;
  /* Wrote everything. */
  return 0;
}
