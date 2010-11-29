/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OTP daemon.
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
 * @file  otpd.c
 * @brief The OpenVAS Manager OTP daemon.
 *
 * This file defines an OpenVAS Transfer Protocol (OTP) port-forwarding server
 * for the OpenVAS Manager, a daemon that is layered between the OpenVAS
 * Scanner (openvassd) and a client (such as OpenVAS-Client).
 *
 * The library provides a single function, \ref serve_otp.
 * This function serves OTP from an OTP server (a "scanner") to a single client.
 * If compiled with \ref LOG, the daemon logs all communication between
 * client and scanner.
 */

#include "types.h"
#include "ovas-mngr-comm.h"
#include "otpd.h"
#include "oxpd.h"
#include "logf.h"
#include "tracef.h"

#include <errno.h>
#include <gnutls/gnutls.h>
#include <string.h>

#include <openvas/misc/openvas_server.h>

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

/**
 * @brief Serve the OpenVAS Transfer Protocol (OTP).
 *
 * Loop reading input from the sockets, and writing client input to the
 * scanner socket and scanner input to the client socket.  Exit the loop
 * on reaching end of file on either of the sockets.
 *
 * If compiled with logging (\ref LOG) then log all output with \ref logf.
 *
 * @param[in]  client_session      The TLS session with the client.
 * @param[in]  scanner_session     The TLS session with the scanner.
 * @param[in]  client_credentials  The TSL server credentials.
 * @param[in]  client_socket       The socket connected to the client.
 * @param[in]  scanner_socket      The socket connected to the scanner.
 *
 * @return 0 on success, -1 on error.
 */
int
serve_otp (gnutls_session_t* client_session,
           gnutls_session_t* scanner_session,
           gnutls_certificate_credentials_t* client_credentials,
           int client_socket, int scanner_socket)
{
  int nfds, interrupted = 0;
  fd_set readfds, exceptfds, writefds;

  /* Connect to the scanner. */
  nfds = 1 + scanner_socket;
  while (1)
    {
      int ret;

      /* Setup for select. */
      FD_ZERO (&exceptfds);
      FD_ZERO (&writefds);
      FD_SET (scanner_socket, &exceptfds);
      FD_SET (scanner_socket, &writefds);

      /* Select, then handle result. */
      ret = select (nfds, NULL, &writefds, &exceptfds, NULL);
      if (ret < 0)
        {
          if (errno == EINTR) continue;
          g_warning ("%s: child connect select failed: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          openvas_server_free (client_socket,
                               *client_session,
                               *client_credentials);
          return -1;
        }
      if (ret > 0)
        {
          if (FD_ISSET (scanner_socket, &exceptfds))
            {
              g_warning ("%s: exception on scanner in child connect select\n",
                         __FUNCTION__);
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }
          if (FD_ISSET (scanner_socket, &writefds))
            {
              ret = openvas_server_connect (scanner_socket,
                                            &scanner_address,
                                            scanner_session,
                                            interrupted);
              if (ret == 0)
                break;
              if (ret == -2)
                interrupted = 1;
              else
                {
                  openvas_server_free (client_socket,
                                       *client_session,
                                       *client_credentials);
                  return -1;
                }
            }
        }
    }

  /* Loop handling input from the sockets. */
  nfds = 1 + (client_socket > scanner_socket
              ? client_socket : scanner_socket);
  while (1)
    {
      int ret;

      /* Setup for select. */
      unsigned short fds = 0; /* What `select' is going to watch. */
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_SET (client_socket, &exceptfds);
      FD_SET (scanner_socket, &exceptfds);
      if (from_client_end < from_buffer_size)
        {
          FD_SET (client_socket, &readfds);
          fds |= FD_CLIENT_READ;
        }
      if (from_scanner_end < from_buffer_size)
        {
          FD_SET (scanner_socket, &readfds);
          fds |= FD_SCANNER_READ;
        }
      if (from_scanner_start < from_scanner_end)
        {
          FD_SET (client_socket, &writefds);
          fds |= FD_CLIENT_WRITE;
        }
      if (from_client_start < from_client_end)
        {
          FD_SET (scanner_socket, &writefds);
          fds |= FD_SCANNER_WRITE;
        }

      /* Select, then handle result. */
      ret = select (nfds, &readfds, &writefds, &exceptfds, NULL);
      if (ret < 0)
        {
          if (errno == EINTR) continue;
          g_warning ("%s: child select failed: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          openvas_server_free (client_socket,
                               *client_session,
                               *client_credentials);
          return -1;
        }
      if (ret > 0)
        {
          if (FD_ISSET (client_socket, &exceptfds))
            {
              g_warning ("%s: exception on client in child select\n",
                         __FUNCTION__);
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }

          if (FD_ISSET (scanner_socket, &exceptfds))
            {
              g_warning ("%s: exception on scanner in child select\n",
                         __FUNCTION__);
              openvas_server_free (client_socket,
                                   *client_session,
                                   *client_credentials);
              return -1;
            }

          if ((fds & FD_CLIENT_READ) == FD_CLIENT_READ
              && FD_ISSET (client_socket, &readfds))
            {
#if TRACE || LOG
              buffer_size_t initial_start = from_client_end;
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
                        /** @todo Rehandshake. */
                        /* Return to select. */
                        break;
                      g_warning ("%s: failed to read from client: %s\n",
                                 __FUNCTION__,
                                 gnutls_strerror ((int) count));
                      openvas_server_free (client_socket,
                                           *client_session,
                                           *client_credentials);
                      return -1;
                    }
                  if (count == 0)
                    {
                      /* End of file. */
                      openvas_server_free (client_socket,
                                           *client_session,
                                           *client_credentials);
                      return 0;
                    }
                  from_client_end += count;
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
                    tracef ("<= client"
                            "  Input may contain password, suppressed.\n");
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
            }

          if ((fds & FD_SCANNER_WRITE) == FD_SCANNER_WRITE
              && FD_ISSET (scanner_socket, &writefds))
            {
              int wrote_all = 1;
              /* Write as much as possible to the scanner. */
              while (from_client_start < from_client_end)
                {
                  ssize_t count;
                  count = gnutls_record_send (*scanner_session,
                                              from_client + from_client_start,
                                              from_client_end - from_client_start);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        {
                          /* Wrote as much scanner would accept, return to
                           * `select'. */
                          wrote_all = 0;
                          break;
                        }
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try write again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /** @todo Rehandshake. */
                        /* Return to select. */
                        break;
                      g_warning ("%s: failed to write to scanner: %s\n",
                                 __FUNCTION__,
                                 gnutls_strerror ((int) count));
                      openvas_server_free (client_socket,
                                           *client_session,
                                           *client_credentials);
                      return -1;
                    }
                  from_client_start += count;
                  tracef ("=> scanner  %zi bytes\n", count);
                }
              if (wrote_all)
                {
                  tracef ("=> scanner  done\n");
                  from_client_start = from_client_end = 0;
                }
            }

          if ((fds & FD_SCANNER_READ) == FD_SCANNER_READ
              && FD_ISSET (scanner_socket, &readfds))
            {
#if TRACE
              buffer_size_t initial_start = from_scanner_end;
#endif
              /* Read as much as possible from the scanner. */
              while (from_scanner_end < from_buffer_size)
                {
                  ssize_t count;
                  count = gnutls_record_recv (*scanner_session,
                                              from_scanner + from_scanner_end,
                                              from_buffer_size
                                              - from_scanner_end);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try read again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /** @todo Rehandshake. */
                        /* Return to select. */
                        break;
                      if (gnutls_error_is_fatal (count) == 0
                          && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                              || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
                        {
                          int alert = gnutls_alert_get (*scanner_session);
                          g_warning ("%s: tls Alert %d: %s\n",
                                     __FUNCTION__,
                                     alert,
                                     gnutls_alert_get_name (alert));
                        }
                      g_warning ("%s: failed to read from scanner: %s\n",
                                 __FUNCTION__,
                                 gnutls_strerror ((int) count));
                      openvas_server_free (client_socket,
                                           *client_session,
                                           *client_credentials);
                      return -1;
                    }
                  if (count == 0)
                    {
                      /* End of file. */
                      openvas_server_free (client_socket,
                                           *client_session,
                                           *client_credentials);
                      return 0;
                    }
                  from_scanner_end += count;
                }
#if TRACE
              /* This check prevents output in the "asynchronous network
               * error" case. */
              if (from_scanner_end > initial_start)
                {
#if TRACE_TEXT
                  tracef ("<= scanner  \"%.*s\"\n",
                          from_scanner_end - initial_start,
                          from_scanner + initial_start);
#else
                  tracef ("<= scanner  %i bytes\n",
                          from_scanner_end - initial_start);
#endif
                }
#endif /* TRACE */
            }

          if ((fds & FD_CLIENT_WRITE) == FD_CLIENT_WRITE
              && FD_ISSET (client_socket, &writefds))
            {
              int wrote_all = 1;

              /* Write as much as possible to the client. */
              while (from_scanner_start < from_scanner_end)
                {
                  ssize_t count;
                  count = gnutls_record_send (*client_session,
                                              from_scanner + from_scanner_start,
                                              from_scanner_end - from_scanner_start);
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
                        /** @todo Rehandshake. */
                        /* Return to select. */
                        break;
                      g_warning ("%s: failed to write to client: %s\n",
                                 __FUNCTION__,
                                 gnutls_strerror ((int) count));
                      openvas_server_free (client_socket,
                                           *client_session,
                                           *client_credentials);
                      return -1;
                    }
                  logf ("=> client %.*s\n",
                        from_scanner_end - from_scanner_start,
                        from_scanner + from_scanner_start);
                  from_scanner_start += count;
                  tracef ("=> client  %zi bytes\n", count);
                }
              if (wrote_all)
                {
                  tracef ("=> client  done\n");
                  from_scanner_start = from_scanner_end = 0;
                }
            }
        }
    }
  /*@notreached@*/
}
