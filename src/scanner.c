/* Copyright (C) 2014-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
 * @file  scanner.c
 * @brief GVM management layer: Scanner connection handling
 *
 * This file provides facilities for working with scanner connections.
 */

#include "scanner.h"
#include "gmpd.h"
#include "utils.h"

#include <dirent.h>
#include <assert.h>
#include <errno.h>  /* for errno */
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>

#include <gvm/util/serverutils.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/**
 * @brief Current OpenVAS Scanner session.
 */
static gnutls_session_t openvas_scanner_session = NULL;

/**
 * @brief Current OpenVAS Scanner credentials.
 */
static gnutls_certificate_credentials_t openvas_scanner_credentials = NULL;

/**
 * @brief Current OpenVAS Scanner socket.
 */
static int openvas_scanner_socket = -1;

/**
 * @brief Current OpenVAS Scanner address.
 */
static struct sockaddr_in openvas_scanner_address;

/**
 * @brief Current OpenVAS Scanner CA Cert.
 */
static char *openvas_scanner_ca_pub = NULL;

/**
 * @brief Current OpenVAS Scanner public key.
 */
static char *openvas_scanner_key_pub = NULL;

/**
 * @brief Current OpenVAS Scanner private key.
 */
static char *openvas_scanner_key_priv = NULL;

/**
 * @brief Current OpenVAS Scanner UNIX path.
 */
static char *openvas_scanner_unix_path = NULL;

/**
 * @brief Buffer of input from the scanner.
 */
char *from_scanner = NULL;

/**
 * @brief The start of the data in the \ref from_scanner buffer.
 */
buffer_size_t from_scanner_start = 0;

/**
 * @brief The end of the data in the \ref from_scanner buffer.
 */
buffer_size_t from_scanner_end = 0;

/**
 * @brief The current size of the \ref from_scanner buffer.
 */
static buffer_size_t from_scanner_size = 1048576;

/**
 * @brief The max size of the \ref from_scanner buffer.
 */
static buffer_size_t from_scanner_max_size = 1073741824;

/**
 * @brief Read as much from the server as the \ref from_scanner buffer will
 * @brief hold.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_scanner buffer is full or -3 on reaching end of file.
 */
int
openvas_scanner_read ()
{
  if (openvas_scanner_socket == -1)
    return -1;

  while (!openvas_scanner_full ())
    {
      ssize_t count;

      if (openvas_scanner_unix_path)
        {
          count = recv (openvas_scanner_socket, from_scanner + from_scanner_end,
                        from_scanner_size - from_scanner_end, 0);
          if (count < 0)
            {
              if (errno == EINTR)
                continue;
              else if (errno == EAGAIN)
                return 0;
              else
                {
                  g_warning ("%s: Failed to read from scanner: %s", __FUNCTION__,
                             strerror (errno));
                  return -1;
                }
            }
        }
      else
        {
          count = gnutls_record_recv (openvas_scanner_session,
                                      from_scanner + from_scanner_end,
                                      from_scanner_size - from_scanner_end);
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
                  g_debug ("   should rehandshake");
                  continue;
                }
              if (gnutls_error_is_fatal (count) == 0
                  && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                      || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
                {
                  int alert = gnutls_alert_get (openvas_scanner_session);
                  const char* alert_name = gnutls_alert_get_name (alert);
                  g_warning ("%s: TLS Alert %d: %s", __FUNCTION__, alert,
                             alert_name);
                }
              g_warning ("%s: failed to read from server: %s", __FUNCTION__,
                         gnutls_strerror (count));
              return -1;
            }
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

/**
 * @brief Check whether the buffer for data from Scanner is full.
 *
 * @return 1 if full, 0 otherwise.
 */
int
openvas_scanner_full ()
{
  return !(from_scanner_end < from_scanner_size);
}

/**
 * @brief Reallocates the from_scanner buffer to a higher size.
 *
 * @return 1 if max size reached, 0 otherwise.
 */
int
openvas_scanner_realloc ()
{
  if (from_scanner_size >= from_scanner_max_size)
    return 1;
  from_scanner_size *= 2;
  g_warning ("Reallocing to %d", from_scanner_size);
  from_scanner = g_realloc (from_scanner, from_scanner_size);
  return 0;
}

/**
 * @brief Write as much as possible from the to_scanner buffer to the scanner.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as scanner accepted,
 *         -3 did an initialisation step.
 */
int
openvas_scanner_write ()
{
  if (openvas_scanner_socket == -1)
    return -1;
  return -3;
}

/**
 * @brief Finish the connection to the Scanner and free internal buffers.
 *
 * @return -1 if error, 0 if success.
 */
int
openvas_scanner_close ()
{
  int rc = 0;
  if (openvas_scanner_socket == -1)
    return -1;
  if (openvas_scanner_unix_path)
    close (openvas_scanner_socket);
  else
    rc = gvm_server_free (openvas_scanner_socket, openvas_scanner_session,
                          openvas_scanner_credentials);
  openvas_scanner_socket = -1;
  openvas_scanner_session = NULL;
  openvas_scanner_credentials = NULL;
  g_free (from_scanner);
  from_scanner = NULL;
  return rc;
}

/**
 * @brief Reset Scanner variables after a fork.
 *
 * This other side of the fork will do the actual cleanup.
 */
void
openvas_scanner_fork ()
{
  openvas_scanner_socket = -1;
  openvas_scanner_session = NULL;
  openvas_scanner_credentials = NULL;
  from_scanner_start = 0;
  from_scanner_end = 0;
}

/**
 * @brief Free the scanner allocated data. Doesn't close socket and terminate
 *        the session.
 */
void
openvas_scanner_free ()
{
  close (openvas_scanner_socket);
  openvas_scanner_socket = -1;
  if (openvas_scanner_session)
    gnutls_deinit (openvas_scanner_session);
  openvas_scanner_session = NULL;
  if (openvas_scanner_credentials)
    gnutls_certificate_free_credentials (openvas_scanner_credentials);
  openvas_scanner_credentials = NULL;
  memset (&openvas_scanner_address, '\0', sizeof (openvas_scanner_address));
  g_free (openvas_scanner_ca_pub);
  g_free (openvas_scanner_key_pub);
  g_free (openvas_scanner_key_priv);
  g_free (openvas_scanner_unix_path);
  openvas_scanner_ca_pub = NULL;
  openvas_scanner_key_pub = NULL;
  openvas_scanner_key_priv = NULL;
  openvas_scanner_unix_path = NULL;
}

/**
 * @brief Check if connected to Scanner is set in an fd_set.
 *
 * @param[in]  fd       File descriptor set.
 *
 * @return 1 if scanner socket in fd_set, 0 if not connected or or not set.
 */
int
openvas_scanner_fd_isset (fd_set *fd)
{
  if (openvas_scanner_socket == -1)
    return 0;
  return FD_ISSET (openvas_scanner_socket, fd);
}

/**
 * @brief Add connected to Scanner's socket to an fd_set.
 *
 * @param[in]  fd   File Descriptor set.
 */
void
openvas_scanner_fd_set (fd_set *fd)
{
  if (openvas_scanner_socket == -1)
    return;
  FD_SET (openvas_scanner_socket, fd);
}

/**
 * @brief Check if there is any data to receive from connected Scanner socket.
 *
 * @return 1 if there is data in socket buffer, 0 if no data or not connected
 *         to a scanner.
 */
int
openvas_scanner_peek ()
{
  char chr;
  if (openvas_scanner_socket == -1)
    return 0;
  return recv (openvas_scanner_socket, &chr, 1, MSG_PEEK);
}

/**
 * @brief Get the nfds value to use for a select() call.
 *
 * @param[in]  socket       Socket to compare to.
 *
 * @return socket + 1 if socket value is higher then scanner's or not
 *         connected to a scanner, scanner socket + 1 otherwise.
 */
int
openvas_scanner_get_nfds (int socket)
{
  if (socket > openvas_scanner_socket)
    return 1 + socket;
  else
    return 1 + openvas_scanner_socket;
}

/**
 * @brief Check if there is any data to receive from connected Scanner session.
 *
 * @return 1 if there is data in session buffer, 0 if no data or not connected
 *         to a scanner.
 */
int
openvas_scanner_session_peek ()
{
  if (openvas_scanner_socket == -1)
    return 0;
  if (openvas_scanner_unix_path)
    return 0;
  else
    return !!gnutls_record_check_pending (openvas_scanner_session);
}

/**
 * @brief Whether we have started a connection to the Scanner using
 *        openvas_scanner_connect().
 *
 * @return 1 if connected, 0 otherwise.
 */
int
openvas_scanner_connected ()
{
  return openvas_scanner_socket == -1 ? 0 : 1;
}

/**
 * @brief Set the scanner's address and port. Will try to resolve addr if it is
 *        a hostname.
 *
 * @param[in]  addr     Scanner address string.
 * @param[in]  port     Scanner port.
 *
 * @return 0 success, -1 error.
 */
int
openvas_scanner_set_address (const char *addr, int port)
{
  if (openvas_scanner_unix_path)
    {
      g_free (openvas_scanner_unix_path);
      openvas_scanner_unix_path = NULL;
    }
  if (port < 1 || port > 65535)
    return -1;
  memset (&openvas_scanner_address, '\0', sizeof (openvas_scanner_address));
  openvas_scanner_address.sin_family = AF_INET;
  openvas_scanner_address.sin_port = htons (port);
  if (gvm_resolve (addr, &openvas_scanner_address.sin_addr, AF_INET))
    return -1;

  return 0;
}

/**
 * @brief Set the scanner's unix socket path.
 *
 * @param[in]  path     Path to scanner unix socket.
 *
 * @return 0 success, -1 error.
 */
int
openvas_scanner_set_unix (const char *path)
{
  if (!path)
    return -1;

  openvas_scanner_free ();
  memset (&openvas_scanner_address, '\0', sizeof (openvas_scanner_address));
  openvas_scanner_unix_path = g_strdup (path);

  return 0;
}

/**
 * @brief Set the scanner's CA Certificate, and public/private key pair.
 *
 * @param[in]  ca_pub       CA Certificate.
 * @param[in]  key_pub      Scanner Certificate.
 * @param[in]  key_priv     Scanner private key.
 */
void
openvas_scanner_set_certs (const char *ca_pub, const char *key_pub,
                           const char *key_priv)
{
  if (openvas_scanner_unix_path)
    {
      g_free (openvas_scanner_unix_path);
      openvas_scanner_unix_path = NULL;
    }
  if (ca_pub)
    openvas_scanner_ca_pub = g_strdup (ca_pub);
  if (key_pub)
    openvas_scanner_key_pub = g_strdup (key_pub);
  if (key_priv)
    openvas_scanner_key_priv = g_strdup (key_priv);
}
