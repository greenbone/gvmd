/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OTP daemon.
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
 * @file  otpd.c
 * @brief The OpenVAS Manager OTP daemon.
 *
 * This file defines an OpenVAS Transfer Protocol (OTP) gateway server for
 * the OpenVAS Manager, a daemon that is layered between the real OpenVAS
 * Server (openvasd) and a client (such as OpenVAS-Client).
 *
 * The library provides a single function, \ref serve_otp.
 * This function serves OTP from a real OTP server to a single client.
 * If compiled with \ref LOG, the daemon logs all communication between
 * client and server.
 */

#include "otpd.h"
#include "logf.h"
#include "tracef.h"

#include <errno.h>
#include <gnutls/gnutls.h>

/**
 * @brief File descriptor set mask: selecting on client read.
 */
#define FD_CLIENT_READ  1
/**
 * @brief File descriptor set mask: selecting on client write.
 */
#define FD_CLIENT_WRITE 2
/**
 * @brief File descriptor set mask: selecting on server read.
 */
#define FD_SERVER_READ  4
/**
 * @brief File descriptor set mask: selecting on server write.
 */
#define FD_SERVER_WRITE 8

// FIX Should probably be passed into serve_otp.
extern size_t from_buffer_size;

// FIX mv these here when read_protocol sorted out in openvasmd.c
// FIX how to share these buffers with ompd.c?
extern char from_client[];
extern int from_client_start;
extern int from_client_end;
extern char from_server[];
extern int from_server_start;
extern int from_server_end;

/**
 * @brief Serve the OpenVAS Transfer Protocol (OTP).
 *
 * Loop reading input from the sockets, and writing client input to the
 * server socket and server input to the client socket.  Exit the loop
 * on reaching end of file on either of the sockets.
 *
 * If compiled with logging (\ref LOG) then log all output with \ref logf.
 *
 * @param[in]  client_session  The TLS session with the client.
 * @param[in]  server_session  The TLS session with the server.
 * @param[in]  client_socket   The socket connected to the client.
 * @param[in]  server_socket   The socket connected to the server.
 *
 * @return 0 on success, -1 on error.
 */
int
serve_otp (gnutls_session_t* client_session,
           gnutls_session_t* server_session,
           int client_socket, int server_socket)
{
  int nfds;
  fd_set readfds, exceptfds, writefds;

  /* Handle the first client input, which was read by `read_protocol'. */
#if TRACE || LOG
  logf ("<= %.*s\n", from_client_end, from_client);
#if TRACE_TEXT
  tracef ("<= client  \"%.*s\"\n", from_client_end, from_client);
#else
  tracef ("<= client  %i bytes\n", from_client_end - initial_start);
#endif
#endif /* TRACE || LOG */

  /* Loop handling input from the sockets. */
  nfds = 1 + (client_socket > server_socket
              ? client_socket : server_socket);
  while (1)
    {
      int ret;

      /* Setup for select. */
      unsigned short fds = 0; /* What `select' is going to watch. */
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_SET (client_socket, &exceptfds);
      FD_SET (server_socket, &exceptfds);
      if (from_client_end < from_buffer_size)
        {
          FD_SET (client_socket, &readfds);
          fds |= FD_CLIENT_READ;
        }
      if (from_server_end < from_buffer_size)
        {
          FD_SET (server_socket, &readfds);
          fds |= FD_SERVER_READ;
        }
      if (from_server_start < from_server_end)
        {
          FD_SET (client_socket, &writefds);
          fds |= FD_CLIENT_WRITE;
        }
      if (from_client_start < from_client_end)
        {
          FD_SET (server_socket, &writefds);
          fds |= FD_SERVER_WRITE;
        }

      /* Select, then handle result. */
      ret = select (nfds, &readfds, &writefds, &exceptfds, NULL);
      if (ret < 0)
        {
          if (errno == EINTR) continue;
          perror ("Child select failed");
          return -1;
        }
      if (ret > 0)
        {
          if (FD_ISSET (client_socket, &exceptfds))
            {
              fprintf (stderr, "Exception on client in child select.\n");
              return -1;
            }

          if (FD_ISSET (server_socket, &exceptfds))
            {
              fprintf (stderr, "Exception on server in child select.\n");
              return -1;
            }

          if (fds & FD_CLIENT_READ && FD_ISSET (client_socket, &readfds))
            {
#if TRACE || LOG
              int initial_start = from_client_end;
#endif
              /* Read as much as possible from the client. */
              while (from_client_end < from_buffer_size)
                {
                  ssize_t count;
                  count = gnutls_record_recv (*client_session,
                                              from_client + from_client_end,
                                              from_buffer_size
                                              - from_client_end);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try read again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to read from client.\n");
                      gnutls_perror (count);
                      return -1;
                    }
                  if (count == 0)
                    /* End of file. */
                    return 0;
                  from_client_end += count;
                }
#if TRACE || LOG
              /* This check prevents output in the "asynchronous network
               * error" case. */
              if (from_client_end > initial_start)
                {
                  logf ("<= %.*s\n",
                        from_client_end - initial_start,
                        from_client + initial_start);
#if TRACE_TEXT
                  tracef ("<= client  \"%.*s\"\n",
                          from_client_end - initial_start,
                          from_client + initial_start);
#else
                  tracef ("<= client  %i bytes\n",
                          from_client_end - initial_start);
#endif
                }
#endif /* TRACE || LOG */
            }

          if (fds & FD_SERVER_WRITE && FD_ISSET (server_socket, &writefds))
            {
              int wrote_all = 1;
              /* Write as much as possible to the server. */
              while (from_client_start < from_client_end)
                {
                  ssize_t count;
                  count = gnutls_record_send (*server_session,
                                              from_client + from_client_start,
                                              from_client_end - from_client_start);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        {
                          /* Wrote as much server would accept, return to
                           * `select'. */
                          wrote_all = 0;
                          break;
                        }
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try write again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to write to server.\n");
                      gnutls_perror (count);
                      return -1;
                    }
                  from_client_start += count;
                  tracef ("=> server  %i bytes\n", count);
                }
              if (wrote_all)
                {
                  tracef ("=> server  done\n");
                  from_client_start = from_client_end = 0;
                }
            }

          if (fds & FD_SERVER_READ && FD_ISSET (server_socket, &readfds))
            {
#if TRACE
              int initial_start = from_server_end;
#endif
              /* Read as much as possible from the server. */
              while (from_server_end < from_buffer_size)
                {
                  ssize_t count;
                  count = gnutls_record_recv (*server_session,
                                              from_server + from_server_end,
                                              from_buffer_size
                                              - from_server_end);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try read again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      if (gnutls_error_is_fatal (count) == 0
                          && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                              || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
                        {
                          int alert = gnutls_alert_get (*server_session);
                          fprintf (stderr, "TLS Alert %d: %s.\n",
                                   alert,
                                   gnutls_alert_get_name (alert));
                        }
                      fprintf (stderr, "Failed to read from server.\n");
                      gnutls_perror (count);
                      return -1;
                    }
                  if (count == 0)
                    /* End of file. */
                    return 0;
                  from_server_end += count;
                }
#if TRACE
              /* This check prevents output in the "asynchronous network
               * error" case. */
              if (from_server_end > initial_start)
                {
#if TRACE_TEXT
                  tracef ("<= server  \"%.*s\"\n",
                          from_server_end - initial_start,
                          from_server + initial_start);
#else
                  tracef ("<= server  %i bytes\n",
                          from_server_end - initial_start);
#endif
                }
#endif /* TRACE */
            }

          if (fds & FD_CLIENT_WRITE && FD_ISSET (client_socket, &writefds))
            {
              int wrote_all = 1;

              /* Write as much as possible to the client. */
              while (from_server_start < from_server_end)
                {
                  ssize_t count;
                  count = gnutls_record_send (*client_session,
                                              from_server + from_server_start,
                                              from_server_end - from_server_start);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        {
                          /* Wrote as much as possible, return to `select'. */
                          wrote_all = 0;
                          break;
                        }
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try write again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to write to client.\n");
                      gnutls_perror (count);
                      return -1;
                    }
                  logf ("=> %.*s\n",
                        from_server_end - from_server_start,
                        from_server + from_server_start);
                  from_server_start += count;
                  tracef ("=> client  %i bytes\n", count);
                }
              if (wrote_all)
                {
                  tracef ("=> client  done\n");
                  from_server_start = from_server_end = 0;
                }
            }
        }
    }
  /*@notreached@*/
}
