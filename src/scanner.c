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
