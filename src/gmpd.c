/* Copyright (C) 2009-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file  gmpd.c
 * @brief The Greenbone Vulnerability Manager GMP daemon.
 *
 * This file defines the Greenbone Vulnerability Manager daemon.  The Manager
 * serves the Greenbone Management Protocol (GMP) to clients such as the
 * Greenbone Security Assistant (GSA). The Manager and GMP give clients full
 * access to an OpenVAS Scanner.
 *
 * The library provides two functions: \ref init_gmpd and \ref serve_gmp.
 * \ref init_gmpd initialises the daemon.
 * \ref serve_gmp serves GMP to a single client socket until end of file is
 * reached on the socket.
 */

#include "gmpd.h"
#include "gmp.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gvm/util/serverutils.h>

#if FROM_BUFFER_SIZE > SSIZE_MAX
#error FROM_BUFFER_SIZE too big for "read"
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/**
 * @brief Buffer of input from the client.
 */
char from_client[FROM_BUFFER_SIZE];

/**
 * @brief Size of \ref from_client data buffer, in bytes.
 */
buffer_size_t from_buffer_size = FROM_BUFFER_SIZE;

/**
 * @brief The start of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_start = 0;

/**
 * @brief The end of the data in the \ref from_client buffer.
 */
buffer_size_t from_client_end = 0;

/**
 * @brief Initialise the GMP library for the GMP daemon.
 *
 * @param[in]  log_config      Log configuration
 * @param[in]  database        Location of manage database.
 * @param[in]  max_ips_per_target  Max number of IPs per target.
 * @param[in]  max_email_attachment_size  Max size of email attachments.
 * @param[in]  max_email_include_size     Max size of email inclusions.
 * @param[in]  max_email_message_size     Max size of email user message text.
 * @param[in]  fork_connection  Function to fork a connection to the GMP
 *                              daemon layer, or NULL.
 * @param[in]  skip_db_check    Skip DB check.
 *
 * @return 0 success, -1 error, -2 database is wrong version,
 *         -4 max_ips_per_target out of range.
 */
int
init_gmpd (GSList *log_config, const db_conn_info_t *database,
           int max_ips_per_target, int max_email_attachment_size,
           int max_email_include_size, int max_email_message_size,
           manage_connection_forker_t fork_connection, int skip_db_check)
{
  return init_gmp (log_config, database, max_ips_per_target,
                   max_email_attachment_size, max_email_include_size,
                   max_email_message_size,
                   fork_connection, skip_db_check);
}

/**
 * @brief Initialise a process forked within the GMP daemon.
 *
 * @param[in]  database  Location of manage database.
 * @param[in]  disable   Commands to disable.
 */
void
init_gmpd_process (const db_conn_info_t *database, gchar **disable)
{
  from_client_start = 0;
  from_client_end = 0;
  init_gmp_process (database, NULL, NULL, disable);
}

/**
 * @brief Read as much from the client as the \ref from_client buffer will hold.
 *
 * @param[in]  client_socket  The socket.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 *         from_client buffer is full or -3 on reaching end of file.
 */
static int
read_from_client_unix (int client_socket)
{
  while (from_client_end < from_buffer_size)
    {
      int count;
      count = read (client_socket,
                    from_client + from_client_end,
                    from_buffer_size - from_client_end);
      if (count < 0)
        {
          if (errno == EAGAIN)
            /* Got everything available, return to `select'. */
            return 0;
          if (errno == EINTR)
            /* Interrupted, try read again. */
            continue;
          g_warning ("%s: failed to read from client: %s",
                     __func__, strerror (errno));
          return -1;
        }
      if (count == 0)
        {
          /* End of file. */

          if (from_client_end)
            /* There's still client input to process, so pretend we read
             * something, to prevent serve_gmp from exiting.
             *
             * This should instead be dealt with in serve_gmp, but that function
             * has got quite complex. */
            return 0;

          return -3;
        }
      from_client_end += count;
    }

  /* Buffer full. */
  return -2;
}

/**
 * @brief Read as much from the client as the \ref from_client buffer will hold.
 *
 * @param[in]  client_session  The TLS session with the client.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_client buffer is full or -3 on reaching end of file.
 */
static int
read_from_client_tls (gnutls_session_t* client_session)
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
              g_debug ("   should rehandshake");
              continue;
            }
          if (gnutls_error_is_fatal ((int) count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*client_session);
              const char* alert_name = gnutls_alert_get_name (alert);
              g_warning ("%s: TLS Alert %d: %s",
                         __func__, alert, alert_name);
            }
          g_warning ("%s: failed to read from client: %s",
                     __func__, gnutls_strerror ((int) count));
          return -1;
        }
      if (count == 0)
        {
          /* End of file. */

          if (from_client_end)
            /* There's still client input to process, so pretend we read
             * something, to prevent serve_gmp from exiting.
             *
             * This should instead be dealt with in serve_gmp, but that function
             * has got quite complex. */
            return 0;

          return -3;
        }
      from_client_end += count;
    }

  /* Buffer full. */
  return -2;
}

/**
 * @brief Read as much from the client as the \ref from_client buffer will hold.
 *
 * @param[in]  client_connection  The connection with the client.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_client buffer is full or -3 on reaching end of file.
 */
static int
read_from_client (gvm_connection_t *client_connection)
{
  if (client_connection->tls)
    return read_from_client_tls (&client_connection->session);
  return read_from_client_unix (client_connection->socket);
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
write_to_client_tls (gnutls_session_t* client_session)
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
          g_warning ("%s: failed to write to client: %s",
                     __func__,
                     gnutls_strerror ((int) count));
          return -1;
        }
      to_client_start += count;
      g_debug ("=> client  %u bytes", (unsigned int) count);
    }
  g_debug ("=> client  done");
  to_client_start = to_client_end = 0;

  /* Wrote everything. */
  return 0;
}

/**
 * @brief Write as much as possible from \ref to_client to the client.
 *
 * @param[in]  client_socket  The client socket.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as client accepted.
 */
static int
write_to_client_unix (int client_socket)
{
  while (to_client_start < to_client_end)
    {
      ssize_t count;
      count = write (client_socket,
                     to_client + to_client_start,
                     to_client_end - to_client_start);
      if (count < 0)
        {
          if (errno == EAGAIN)
            /* Wrote as much as client would accept. */
            return -2;
          if (errno == EINTR)
            /* Interrupted, try write again. */
            continue;
          g_warning ("%s: failed to write to client: %s",
                     __func__,
                     strerror (errno));
          return -1;
        }
      to_client_start += count;
      g_debug ("=> client  %u bytes", (unsigned int) count);
    }
  g_debug ("=> client  done");
  to_client_start = to_client_end = 0;

  /* Wrote everything. */
  return 0;
}

/**
 * @brief Write as much as possible from \ref to_client to the client.
 *
 * @param[in]  client_connection  The client connection.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as client accepted.
 */
static int
write_to_client (gvm_connection_t *client_connection)
{
  if (client_connection->tls)
    return write_to_client_tls (&client_connection->session);
  return write_to_client_unix (client_connection->socket);
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
static gboolean
gmpd_send_to_client (const char* msg, void* write_to_client_data)
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
            g_debug ("   %s full (%i < %zu); client write failed",
                    __func__,
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

      /* length can be 0 if write_to_client returns -2. */

      if (length > 0)
        {
          memmove (to_client + to_client_end, msg, length);
          g_debug ("-> client: %.*s", (int) length, msg);
          to_client_end += length;
          msg += length;
        }
    }

  if (strlen (msg))
    {
      assert (strlen (msg)
              <= (((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end));
      memmove (to_client + to_client_end, msg, strlen (msg));
      g_debug ("-> client: %s", msg);
      to_client_end += strlen (msg);
    }

  return FALSE;
}

/**
 * @brief Get nfds value.
 *
 * @param[in]  socket  Highest socket number.
 *
 * @return nfds value for select.
 */
static int
get_nfds (int socket)
{
  return 1 + socket;
}

/**
 * @brief Serve the Greenbone Management Protocol (GMP).
 *
 * Loop reading input from the sockets, processing
 * the input, and writing any results to the appropriate socket.
 * Exit the loop on reaching end of file on the client socket.
 *
 * Read input from the client.
 * Process the input with \ref process_gmp_client_input.  Write the results
 * to the client.
 *
 * \if STATIC
 *
 * Read input with \ref read_from_client.
 * Write the results with \ref write_to_client.
 *
 * \endif
 *
 * @param[in]  client_connection    Connection.
 * @param[in]  database             Location of manage database.
 * @param[in]  disable              Commands to disable.
 *
 * @return 0 success, -1 error.
 */
int
serve_gmp (gvm_connection_t *client_connection, const db_conn_info_t *database,
           gchar **disable)
{
  int nfds, rc = 0;

  g_debug ("   Serving GMP");

  /* Initialise the XML parser and the manage library. */
  init_gmp_process (database,
                    (int (*) (const char*, void*)) gmpd_send_to_client,
                    (void*) client_connection,
                    disable);

  /** @todo Confirm and clarify complications, especially last one. */
  /* Loop handling input from the sockets.
   *
   * That is, select on all the socket fds and then, as necessary
   *   - read from the client into buffer from_client
   *   - write to the client from buffer to_client.
   *
   * On reading from an fd, immediately try react to the input.  On reading
   * from the client call process_gmp_client_input, which parses GMP
   * commands and may write to to_client.
   *
   * There are a few complications here
   *   - the program must read from or write to an fd returned by select
   *     before selecting on the fd again,
   *   - the program need only select on the fds for writing if there is
   *     something to write,
   *   - similarly, the program need only select on the fds for reading
   *     if there is buffer space available,
   *   - the buffer from_client can become full during reading
   *   - a read from the client can be stalled by the to_client buffer
   *     filling up (in which case process_gmp_client_input will try to
   *     write the to_client buffer itself),
   */

  nfds = get_nfds (client_connection->socket);
  while (1)
    {
      int ret;
      fd_set readfds, writefds;

      /* Setup for select. */

      /** @todo nfds must only include a socket if it's in >= one set. */

      FD_ZERO (&readfds);
      FD_ZERO (&writefds);

      /** @todo Shutdown on failure (for example, if a read fails). */

      /* See whether to read from the client.  */
      if (from_client_end < from_buffer_size)
        FD_SET (client_connection->socket, &readfds);
      /* See whether to write to the client.  */
      if (to_client_start < to_client_end)
        FD_SET (client_connection->socket, &writefds);

      /* Select, then handle result.  Due to GNUTLS internal buffering
       * we test for pending records first and emulate a select call
       * in that case.  Note, that GNUTLS guarantees that writes are
       * not buffered.  Note also that GNUTLS versions < 3 did not
       * exhibit a problem in Scanner due to a different buffering
       * strategy.  */
      ret = 0;
      if (client_connection->socket > 0
          && client_connection->tls
          && FD_ISSET (client_connection->socket, &readfds)
          && gnutls_record_check_pending (client_connection->session))
        {
          FD_ZERO (&readfds);
          FD_ZERO (&writefds);
          ret++;
          FD_SET (client_connection->socket, &readfds);
        }

      if (!ret)
        ret = select (nfds, &readfds, &writefds, NULL, NULL);
      if ((ret < 0 && errno == EINTR) || ret == 0)
        continue;
      if (ret < 0)
        {
          g_warning ("%s: child select failed: %s", __func__,
                     strerror (errno));
          rc = -1;
          goto client_free;
        }

      /* Read any data from the client. */
      if (client_connection->socket > 0
          && FD_ISSET (client_connection->socket, &readfds))
        {
          buffer_size_t initial_start = from_client_end;

          switch (read_from_client (client_connection))
            {
              case  0:       /* Read everything. */
                break;
              case -1:       /* Error. */
                rc = -1;
                goto client_free;
              case -2:       /* from_client buffer full. */
                /* There may be more to read. */
                break;
              case -3:       /* End of file. */
                g_debug ("   EOF reading from client");
                if (client_connection->socket > 0
                    && FD_ISSET (client_connection->socket, &writefds))
                  /* Write rest of to_client to client, so that the client gets
                   * any buffered output and the response to the error. */
                  write_to_client (client_connection);
                rc = 0;
                goto client_free;
              default:       /* Programming error. */
                assert (0);
            }

          /* This check prevents output in the "asynchronous network
           * error" case. */
          if (from_client_end > initial_start)
            {
              if (g_strstr_len (from_client + initial_start,
                                from_client_end - initial_start,
                                "<password>"))
                g_debug ("<= client  Input may contain password, suppressed");
              else
                g_debug ("<= client  \"%.*s\"",
                        from_client_end - initial_start,
                        from_client + initial_start);
            }

          ret = process_gmp_client_input ();
          if (ret == 0)
            /* Processed all input. */
            ;
          else if (ret == -1 || ret == -4)
            {
              /* Error.  Write rest of to_client to client, so that the
               * client gets any buffered output and the response to the
               * error. */
              write_to_client (client_connection);
              rc = -1;
              goto client_free;
            }
          else
            {
              /* Programming error. */
              assert (0);
            }
        }

      /* Write any data to the client. */
      if (client_connection->socket > 0
          && FD_ISSET (client_connection->socket, &writefds))
        {
          /* Write as much as possible to the client. */

          switch (write_to_client (client_connection))
            {
              case  0:      /* Wrote everything in to_client. */
                break;
              case -1:      /* Error. */
                rc = -1;
                goto client_free;
              case -2:      /* Wrote as much as client was willing to accept. */
                break;
              default:      /* Programming error. */
                assert (0);
            }
        }
    } /* while (1) */

client_free:
  gvm_connection_free (client_connection);
  return rc;
}
