/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the Comm Library.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
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
#include <fcntl.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "tracef.h"

#ifdef S_SPLINT_S
#include "splint.h"
#endif

/**
 * @brief The size of the \ref to_server data buffer.
 */
#define TO_SERVER_BUFFER_SIZE 26214400

// FIX This is the definition for the entire module.
/**
 * @brief Verbose output flag.
 *
 * Only consulted if compiled with TRACE non-zero.
 */
int verbose = 0;

/**
 * @brief Buffer of output to the server.
 */
static char to_server[TO_SERVER_BUFFER_SIZE];

/**
 * @brief The end of the data in the \ref to_server buffer.
 */
static int to_server_end = 0;

/**
 * @brief The start of the data in the \ref to_server buffer.
 */
static int to_server_start = 0;

/**
 * @brief Make a session for connecting to the server.
 *
 * @param[out]  server_socket       The socket connected to the server.
 * @param[out]  server_session      The session with the server.
 * @param[out]  server_credentials  Credentials.
 *
 * @return 0 on success, -1 on error.
 */
int
make_session (int server_socket,
              gnutls_session_t* server_session,
              gnutls_certificate_credentials_t* server_credentials)
{
  /* Setup server session. */

  const int protocol_priority[] = { GNUTLS_TLS1,
                                    0 };
  const int cipher_priority[] = { GNUTLS_CIPHER_AES_128_CBC,
                                  GNUTLS_CIPHER_3DES_CBC,
                                  GNUTLS_CIPHER_AES_256_CBC,
                                  GNUTLS_CIPHER_ARCFOUR_128,
                                  0 };
  const int comp_priority[] = { GNUTLS_COMP_ZLIB,
                                GNUTLS_COMP_NULL,
                                0 };
  const int kx_priority[] = { GNUTLS_KX_DHE_RSA,
                              GNUTLS_KX_RSA,
                              GNUTLS_KX_DHE_DSS,
                              0 };
  const int mac_priority[] = { GNUTLS_MAC_SHA1,
                               GNUTLS_MAC_MD5,
                               0 };

  if (gnutls_certificate_allocate_credentials (server_credentials))
    {
      fprintf (stderr, "Failed to allocate server credentials.\n");
      goto close_fail;
    }

  if (gnutls_init (server_session, GNUTLS_CLIENT))
    {
      fprintf (stderr, "Failed to initialise server session.\n");
      goto server_free_fail;
    }

  if (gnutls_protocol_set_priority (*server_session, protocol_priority))
    {
      fprintf (stderr, "Failed to set protocol priority.\n");
      goto server_fail;
    }

  if (gnutls_cipher_set_priority (*server_session, cipher_priority))
    {
      fprintf (stderr, "Failed to set cipher priority.\n");
      goto server_fail;
    }

  if (gnutls_compression_set_priority (*server_session, comp_priority))
    {
      fprintf (stderr, "Failed to set compression priority.\n");
      goto server_fail;
    }

  if (gnutls_kx_set_priority (*server_session, kx_priority))
    {
      fprintf (stderr, "Failed to set server key exchange priority.\n");
      goto server_fail;
    }

  if (gnutls_mac_set_priority (*server_session, mac_priority))
    {
      fprintf (stderr, "Failed to set mac priority.\n");
      goto server_fail;
    }

  if (gnutls_credentials_set (*server_session,
                              GNUTLS_CRD_CERTIFICATE,
                              *server_credentials))
    {
      fprintf (stderr, "Failed to set server credentials.\n");
      goto server_fail;
    }

  // FIX get flags first
  // FIX after read_protocol
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (server_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set server socket flag");
      goto fail;
    }

  return 0;

 fail:
  (void) gnutls_bye (*server_session, GNUTLS_SHUT_RDWR);
 server_fail:
  (void) gnutls_deinit (*server_session);

 server_free_fail:
  gnutls_certificate_free_credentials (*server_credentials);

 close_fail:
  (void) close (server_socket);

  return -1;
}

/**
 * @brief Cleanup a server session.
 *
 * @param[in]  server_socket       The socket connected to the server.
 * @param[in]  server_session      The session with the server.
 * @param[in]  server_credentials  Credentials.
 *
 * @return 0 success, -1 error.
 */
int
end_session (int server_socket,
             gnutls_session_t server_session,
             gnutls_certificate_credentials_t server_credentials)
{
  int count;

#if 0
  /* Turn on blocking. */
  // FIX get flags first
  if (fcntl (server_socket, F_SETFL, 0L) == -1)
    {
      perror ("Failed to set server socket flag (end_session)");
      return -1;
    }
#endif
#if 1
  /* Turn off blocking. */
  // FIX get flags first
  if (fcntl (server_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set server socket flag (end_session)");
      return -1;
    }
#endif

  count = 100;
  while (count--)
    {
      int ret = gnutls_bye (server_session, GNUTLS_SHUT_RDWR);
      if (ret == GNUTLS_E_AGAIN) continue;
      if (ret == GNUTLS_E_INTERRUPTED) continue;
      if (ret)
        {
          fprintf (stderr, "Failed to gnutls_bye.\n");
          gnutls_perror ((int) ret);
          /* Carry on successfully anyway, as this often fails, perhaps
           * because the server is closing the connection first. */
          break;
        }
    }

  gnutls_deinit (server_session);

  gnutls_certificate_free_credentials (server_credentials);

  if (shutdown (server_socket, SHUT_RDWR) == -1)
    {
      if (errno == ENOTCONN) return 0;
      perror ("Failed to shutdown server socket");
      return -1;
    }

#if 0
  if (close (server_socket) == -1)
    {
      perror ("Failed to close server socket.");
      return -1;
    }
#endif

  return 0;
}

/**
 * @brief Get the number of characters free in the \ref to_server buffer.
 *
 * @return Number of characters free in \ref to_server.  0 when full.
 */
unsigned int
to_server_buffer_space ()
{
  if (to_server_end < to_server_start) abort ();
  return (unsigned int) (to_server_end - to_server_start);
}

/**
 * @brief Send a number of bytes to the server.
 *
 * @param[in]  msg  The message, a string.
 * @param[in]  n    The number of bytes from msg to send.
 *
 * @return 0 for success, any other value for failure.
 */
int
sendn_to_server (char * msg, size_t n)
{
  if (TO_SERVER_BUFFER_SIZE - to_server_end < n)
    {
      tracef ("   sendn_to_server: available space (%i) < n (%i)\n",
              TO_SERVER_BUFFER_SIZE - to_server_end, n);
      return 1;
    }

  memmove (to_server + to_server_end, msg, n);
  tracef ("-> server: %.*s\n", n, msg);
  to_server_end += n;

  return 0;
}

/**
 * @brief Send a message to the server.
 *
 * @param[in]  msg  The message, a string.
 *
 * @return 0 for success, any other value for failure.
 */
int
send_to_server (char * msg)
{
  return sendn_to_server (msg, strlen (msg));
}

/**
 * @brief Format and send a message to the server.
 *
 * @param[in]  format  printf-style format string for message.
 *
 * @return 0 for success, any other value for failure.
 */
int
sendf_to_server (const char* format, ...)
{
  va_list args;
  va_start (args, format);
  gchar* msg = g_strdup_vprintf (format, args);
  int ret = send_to_server (msg);
  g_free (msg);
  va_end (args);
  return ret;
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
                   gboolean interrupted)
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
      if (ret_len != (socklen_t) sizeof (ret))
        {
          fprintf (stderr, "Weird option length from getsockopt: %i.\n",
                   /* socklen_t is an int, according to getsockopt(2). */
                   (int) ret_len);
          return -1;
        }
      if (ret)
        {
          if (ret == EINPROGRESS) return -2;
          perror ("Failed to connect to server (interrupted)");
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
      ret = gnutls_handshake (*server_session);
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
                                  (size_t) (end - point));
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
          gnutls_perror ((int) count);
          return -1;
        }
      point += count;
      tracef ("=> server  (string) %zi bytes\n", count);
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
                                  (size_t) to_server_end - to_server_start);
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
          gnutls_perror ((int) count);
          return -1;
        }
      to_server_start += count;
      tracef ("=> server  %zi bytes\n", count);
    }
  tracef ("=> server  done\n");
  to_server_start = to_server_end = 0;
  /* Wrote everything. */
  return 0;
}
