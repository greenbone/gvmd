/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the Comm Library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
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
#include "logf.h"

#ifdef S_SPLINT_S
#include "splint.h"
#endif

/** @todo Consider moving to libs (so please leave "server" in the names). */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   comm"

/** @cond STATIC */

/**
 * @brief The size of the \ref to_server data buffer.
 */
#define TO_SERVER_BUFFER_SIZE 26214400

/** @endcond */

/** @todo This is the definition for the entire module. */
/**
 * @brief Verbose output flag.
 *
 * Only consulted if compiled with TRACE non-zero.
 */
int verbose = 0;

/** @todo This is the definition for the entire module. */
/**
 * @brief Logging parameters, as passed to setup_log_handlers.
 */
GSList *log_config = NULL;

/** @cond STATIC */

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

/** @endcond */

/**
 * @brief Get the number of characters free in the server output buffer.
 *
 * @return Number of characters free in server output buffer.  0 when full.
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
 * @param[in]  msg  The message, a sequence of bytes.
 * @param[in]  n    The number of bytes from msg to send.
 *
 * @return 0 for success, any other value for failure.
 */
int
sendn_to_server (const void * msg, size_t n)
{
  if (TO_SERVER_BUFFER_SIZE - to_server_end < n)
    {
      tracef ("   sendn_to_server: available space (%i) < n (%zu)\n",
              TO_SERVER_BUFFER_SIZE - to_server_end, n);
      return 1;
    }

  memmove (to_server + to_server_end, msg, n);
  tracef ("s> server  (string) %.*s\n", (int) n, to_server + to_server_end);
  tracef ("-> server  %zu bytes\n", n);
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
send_to_server (const char * msg)
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
  gchar* msg;
  int ret;
  va_start (args, format);
  msg = g_strdup_vprintf (format, args);
  ret = send_to_server (msg);
  g_free (msg);
  va_end (args);
  return ret;
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
            /** @todo Rehandshake. */
            continue;
          g_warning ("%s: failed to write to server: %s\n",
                     __FUNCTION__,
                     gnutls_strerror ((int) count));
          return -1;
        }
#if LOG
      if (count) logf ("=> server %.*s\n", (int) count, point);
#endif
      tracef ("s> server  (string) %.*s\n", (int) count, point);
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
            /** @todo Rehandshake. */
            continue;
          g_warning ("%s: failed to write to server: %s\n",
                     __FUNCTION__,
                     gnutls_strerror ((int) count));
          return -1;
        }
#if LOG
      if (count) logf ("=> server %.*s\n",
                       (int) count,
                       to_server + to_server_start);
#endif
      tracef ("s> server  %.*s\n", (int) count, to_server + to_server_start);
      to_server_start += count;
      tracef ("=> server  %zi bytes\n", count);
    }
  tracef ("=> server  done\n");
  to_server_start = to_server_end = 0;
  /* Wrote everything. */
  return 0;
}
