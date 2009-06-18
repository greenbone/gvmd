/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OMP daemon.
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
 * @file  ompd.c
 * @brief The OpenVAS Manager OMP daemon.
 *
 * This file defines the OpenVAS Manager Protocol (OMP) server for the OpenVAS
 * Manager, a daemon that is layered between the real OpenVAS Server
 * (openvasd) and a client (such as OpenVAS-Client).
 *
 * The library provides two functions: \ref init_ompd and \ref serve_omp.
 * \ref init_ompd initialises the daemon.
 * \ref serve_omp serves OMP to a single client socket until end of file is
 * reached on the socket.
 */

#include "ompd.h"
#include "oxpd.h"
#include "logf.h"
#include "omp.h"
#include "otp.h" // FIX for server_init_state
#include "ovas-mngr-comm.h"
#include "tracef.h"

#include <assert.h>
#include <errno.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <network.h>

#ifdef S_SPLINT_S
/* FIX Weird that these are missing. */
/*@-exportheader@*/
int socket(int domain, int type, int protocol);
/*@=exportheader@*/
#endif

/**
 * @brief Seconds of client idleness before manager closes client connection.
 */
#define CLIENT_TIMEOUT 900

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

/**
 * @brief Initialise the OMP library for the OMP daemon.
 */
int
init_ompd ()
{
  return init_omp ();
}

/**
 * @brief Read as much from the client as the \ref from_client buffer will hold.
 *
 * @param[in]  client_session  The TLS session with the client.
 * @param[in]  client_socket   The socket connected to the client.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_client buffer is full or -3 on reaching end of file.
 */
static int
read_from_client (gnutls_session_t* client_session,
                  /*@unused@*/ int client_socket)
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
              /* \todo Rehandshake. */
              tracef ("   FIX should rehandshake\n");
              continue;
            }
          if (gnutls_error_is_fatal ((int) count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*client_session);
              /*@dependent@*/
              const char* alert_name = gnutls_alert_get_name (alert);
              fprintf (stderr, "TLS Alert %d: %s.\n",
                       alert,
                       alert_name);
            }
          fprintf (stderr, "Failed to read from client.\n");
          gnutls_perror ((int) count);
          return -1;
        }
      if (count == 0)
        /* End of file. */
        return -3;
      from_client_end += count;
    }

  /* Buffer full. */
  return -2;
}

// FIX combine with read_from_client
/**
 * @brief Read as much from the server as the \ref from_server buffer will hold.
 *
 * @param[in]  server_session  The TLS session with the server.
 * @param[in]  server_socket   The socket connected to the server.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_server buffer is full or -3 on reaching end of file.
 */
static int
read_from_server (gnutls_session_t* server_session,
                  /*@unused@*/ int server_socket)
{
  while (from_server_end < from_buffer_size)
    {
      ssize_t count;
      count = gnutls_record_recv (*server_session,
                                  from_server + from_server_end,
                                  from_buffer_size - from_server_end);
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
              /* \todo Rehandshake. */
              tracef ("   FIX should rehandshake\n");
              continue;
            }
          fprintf (stderr, "is_fatal: %i\n", gnutls_error_is_fatal (count));
          if (gnutls_error_is_fatal (count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*server_session);
              /*@dependent@*/
              const char* alert_name = gnutls_alert_get_name (alert);
              fprintf (stderr, "TLS Alert %d: %s.\n",
                       alert,
                       alert_name);
            }
          fprintf (stderr, "Failed to read from server.\n");
          gnutls_perror (count);
          return -1;
        }
      if (count == 0)
        /* End of file. */
        return -3;
      assert (count > 0);
      from_server_end += count;
    }

  /* Buffer full. */
  return -2;
}

/**
 * @brief Write as much as possible from \ref to_client to the client.
 *
 * @param[in]  client_session  The client session.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as server accepted.
 */
static int
write_to_client (gnutls_session_t* client_session)
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
            /* Wrote as much as server would accept. */
            return -2;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* \todo Rehandshake. */
            continue;
          fprintf (stderr, "Failed to write to client.\n");
          gnutls_perror ((int) count);
          return -1;
        }
      logf ("=> %.*s\n",
            to_client_end - to_client_start,
            to_client + to_client_start);
      to_client_start += count;
      tracef ("=> client  %u bytes\n", (unsigned int) count);
    }
  tracef ("=> client  done\n");
  to_client_start = to_client_end = 0;

  /* Wrote everything. */
  return 0;
}

/**
 * @brief Write as much as possible from \ref to_server to the server.
 *
 * @param[in]  server_socket   The server socket.
 * @param[in]  server_session  The server session.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as server accepted,
 *         -3 did an initialisation step.
 */
static int
write_to_server (int server_socket, gnutls_session_t* server_session)
{
  switch (server_init_state)
    {
      case SERVER_INIT_CONNECT_INTR:
      case SERVER_INIT_TOP:
        switch (connect_to_server (server_socket,
                                   &server_address,
                                   server_session,
                                   server_init_state
                                   == SERVER_INIT_CONNECT_INTR))
          {
            case 0:
              set_server_init_state (SERVER_INIT_CONNECTED);
              /* Fall through to SERVER_INIT_CONNECTED case below, to write
               * version string. */
              break;
            case -2:
              set_server_init_state (SERVER_INIT_CONNECT_INTR);
              return -3;
            default:
              return -1;
          }
        /*@fallthrough@*/
      case SERVER_INIT_CONNECTED:
        {
          char* string = "< OTP/1.0 >\n";
          server_init_offset = write_string_to_server (server_session,
                                                       string
                                                       + server_init_offset);
          if (server_init_offset == 0)
            set_server_init_state (SERVER_INIT_SENT_VERSION);
          else
            {
              if (server_init_offset == -1)
                {
                  server_init_offset = 0;
                  return -1;
                }
            }
          break;
        }
      case SERVER_INIT_SENT_VERSION:
      case SERVER_INIT_GOT_VERSION:
        assert (0);
        break;
      case SERVER_INIT_GOT_USER:
        {
          char* const user = "om\n";
          server_init_offset = write_string_to_server (server_session,
                                                       user + server_init_offset);
          if (server_init_offset == 0)
            set_server_init_state (SERVER_INIT_SENT_USER);
          else if (server_init_offset == -1)
            {
              server_init_offset = 0;
              return -1;
            }
          break;
        }
      case SERVER_INIT_SENT_USER:
        assert (0);
        break;
      case SERVER_INIT_GOT_PASSWORD:
        {
          char* const password = "om\n";
          server_init_offset = write_string_to_server (server_session,
                                                       password + server_init_offset);
          if (server_init_offset == 0)
            set_server_init_state (SERVER_INIT_DONE);
            /* Fall through to send any available output. */
          else if (server_init_offset == -1)
            {
              server_init_offset = 0;
              return -1;
            }
          else
            break;
        }
        /*@fallthrough@*/
      case SERVER_INIT_DONE:
        while (1)
          switch (write_to_server_buffer (server_session))
            {
              case  0: return 0;
              case -1: return -1;
              case -2: return -2;
              case -3: continue;  /* Interrupted. */
            }
    }
  return -3;
}

/**
 * @brief Recreate the server session.
 *
 * @param  server_socket       Server socket.
 * @param  server_session      Server session.
 * @param  server_credentials  Server credentials.
 *
 * @return New server socket, or -1 on error.
 */
int
recreate_session (int server_socket,
                  gnutls_session_t* server_session,
                  gnutls_certificate_credentials_t* server_credentials)
{
  if (end_session (server_socket,
                   *server_session,
                   *server_credentials))
    return -1;
  // FIX shutdown?
  if (close (server_socket) == -1)
    {
      perror ("Failed to close server socket.");
      return -1;
    }
  /* Make the server socket. */
  server_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (server_socket == -1)
    {
      perror ("Failed to create server socket");
      return -1;
    }
  if (make_session (server_socket,
                    server_session,
                    server_credentials))
    return -1;
  return server_socket;
}

/**
 * @brief Serve the OpenVAS Management Protocol (OMP).
 *
 * Loop reading input from the sockets, processing
 * the input, and writing any results to the appropriate socket.
 * Exit the loop on reaching end of file on the client socket.
 *
 * Read input with \ref read_from_client and \ref read_from_server.
 * Process the input with \ref process_omp_client_input and
 * \ref process_otp_server_input.  Write the results with
 * \ref write_to_client and \ref write_to_server.
 *
 * If compiled with logging (\ref LOG) then log all input and output
 * with \ref logf.
 *
 * @param[in]  client_session      The TLS session with the client.
 * @param[in]  server_session      The TLS session with the server.
 * @param[in]  server_credentials  The TSL server credentials.
 * @param[in]  client_socket       The socket connected to the client.
 * @param[in]  server_socket_addr  The socket connected to the server.
 *
 * @return 0 on success, -1 on error.
 */
int
serve_omp (gnutls_session_t* client_session,
           gnutls_session_t* server_session,
           gnutls_certificate_credentials_t* server_credentials,
           int client_socket, int* server_socket_addr)
{
  int nfds, ret;
  time_t last_client_activity_time;
  fd_set readfds, exceptfds, writefds;
  int server_socket = *server_socket_addr;
  /* True if processing of the client input is waiting for space in the
   * to_server buffer. */
  short client_input_stalled;
  /* True if processing of the server input is waiting for space in the
   * to_client buffer. */
  gboolean server_input_stalled = FALSE;
  /* Client status flag.  Set to 0 when the client closes the connection
   * while the server is active. */
  short client_active = 1;

  tracef ("   Serving OMP.\n");

  /* Initialise server information. */
  init_otp_data ();

  /* Initialise the XML parser and the manage library. */
  init_omp_process ();
#if 0
  // FIX consider free_omp_data (); on return
  if (tasks) free_tasks ();
  if (current_server_preference) free (current_server_preference);
  free_credentials (&current_credentials);
  maybe_free_current_server_plugin_dependency ();
  maybe_free_server_preferences (); // old
  maybe_free_server_rules ();
  maybe_free_server_plugins_dependencies (); // old
#endif

  /* Handle the first client input, which was read by `read_protocol'. */
#if TRACE || LOG
  logf ("<= %.*s\n", from_client_end, from_client);
#if TRACE_TEXT
  tracef ("<= client  \"%.*s\"\n", from_client_end, from_client);
#else
  tracef ("<= client  %" BUFFER_SIZE_T_FORMAT " bytes\n",
          from_client_end);
#endif
#endif /* TRACE || LOG */
  ret = process_omp_client_input ();
  if (ret == 0)
    /* Processed all input. */
    client_input_stalled = 0;
  else if (ret == -1 || ret == -4)
    {
      /* Error.  Write rest of to_client to client, so that the
       * client gets any buffered output and the response to the
       * error. */
      write_to_client (client_session);
      close_stream_connection (client_socket);
      return -1;
    }
  else if (ret == -2)
    {
      /* to_server buffer full. */
      tracef ("   client input stalled 0\n");
      client_input_stalled = 1;
    }
  else if (ret == -3)
    {
      /* to_client buffer full. */
      tracef ("   client input stalled 0\n");
      client_input_stalled = 2;
    }
  else
    {
      /* Programming error. */
      assert (0);
      client_input_stalled = 0;
    }

  /* Record the start time. */
  if (time (&last_client_activity_time) == -1)
    {
      perror ("Failed to get current time");
      close_stream_connection (client_socket);
      return -1;
    }

  /* Loop handling input from the sockets.
   *
   * That is, select on all the socket fds and then, as necessary
   *   - read from the client into buffer from_client
   *   - write to the server from buffer to_server
   *   - read from the server into buffer from_server
   *   - write to the client from buffer to_client.
   *
   * On reading from an fd, immediately try react to the input.  On reading
   * from the client call process_omp_client_input, which parses OMP
   * commands and may write to to_server and to_client.  On reading from
   * the server call process_otp_server_input, which updates information
   * kept about the server.
   *
   * There are a few complications here
   *   - the program must read from or write to an fd returned by select
   *     before selecting on the fd again,
   *   - the program need only select on the fds for writing if there is
   *     something to write,
   *   - similarly, the program need only select on the fds for reading
   *     if there is buffer space available,
   *   - the buffers from_client and from_server can become full during
   *     reading
   *   - a read from the client can be stalled by the to_server buffer
   *     filling up, or the to_client buffer filling up,
   *   - FIX a read from the server can, theoretically, be stalled by the
   *     to_server buffer filling up (during initialisation).
   */

  nfds = 1 + (client_socket > server_socket
              ? client_socket : server_socket);
  while (1)
    {
      int ret;
      struct timeval timeout;
      /* Setup for select. */
      uint8_t fds = 0; /* What `select' is going to watch. */
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_SET (client_socket, &exceptfds);
      FD_SET (server_socket, &exceptfds);
      // FIX shutdown if any eg read fails
      if (client_active && from_client_end < from_buffer_size)
        {
          FD_SET (client_socket, &readfds);
          fds |= FD_CLIENT_READ;
        }
      if ((server_init_state == SERVER_INIT_DONE
           || server_init_state == SERVER_INIT_GOT_VERSION
           || server_init_state == SERVER_INIT_SENT_USER
           || server_init_state == SERVER_INIT_SENT_VERSION)
          && from_server_end < from_buffer_size)
        {
          FD_SET (server_socket, &readfds);
          fds |= FD_SERVER_READ;
        }
      if (to_client_start < to_client_end)
        {
          FD_SET (client_socket, &writefds);
          fds |= FD_CLIENT_WRITE;
        }
      if (((server_init_state == SERVER_INIT_TOP
            || server_init_state == SERVER_INIT_DONE)
           && to_server_buffer_space () > 0)
          || server_init_state == SERVER_INIT_CONNECT_INTR
          || server_init_state == SERVER_INIT_CONNECTED
          || server_init_state == SERVER_INIT_GOT_PASSWORD
          || server_init_state == SERVER_INIT_GOT_USER)
        {
          FD_SET (server_socket, &writefds);
          fds |= FD_SERVER_WRITE;
        }

      timeout.tv_usec = 0;
      // FIX time check error
      timeout.tv_sec = CLIENT_TIMEOUT
                       - (time (NULL) - last_client_activity_time);
      if (timeout.tv_sec <= 0)
        {
          tracef ("client timeout (1)\n");
          close_stream_connection (client_socket);
          if (server_is_active ())
            client_active = 0;
          else
            return 0;
        }

      /* Select, then handle result. */
      ret = select (nfds, &readfds, &writefds, &exceptfds, &timeout);
      if (ret < 0)
        {
          if (errno == EINTR) continue;
          perror ("Child select failed");
          close_stream_connection (client_socket);
          return -1;
        }
      if (ret == 0) continue;

      if (FD_ISSET (client_socket, &exceptfds))
        {
          fprintf (stderr, "Exception on client in child select.\n");
          close_stream_connection (client_socket);
          return -1;
        }

      if (FD_ISSET (server_socket, &exceptfds))
        {
          fprintf (stderr, "Exception on server in child select.\n");
          close_stream_connection (client_socket);
          return -1;
        }

      if ((fds & FD_CLIENT_READ) == FD_CLIENT_READ
          && FD_ISSET (client_socket, &readfds))
        {
#if TRACE || LOG
          buffer_size_t initial_start = from_client_end;
#endif
          tracef ("   FD_CLIENT_READ\n");

          switch (read_from_client (client_session, client_socket))
            {
              case  0:       /* Read everything. */
                break;
              case -1:       /* Error. */
                close_stream_connection (client_socket);
                return -1;
              case -2:       /* from_client buffer full. */
                /* There may be more to read. */
                break;
              case -3:       /* End of file. */
                tracef ("   EOF reading from client.\n");
                close_stream_connection (client_socket);
                if (server_is_active ())
                  client_active = 0;
                else
                  return 0;
                break;
              default:       /* Programming error. */
                assert (0);
            }

          if (time (&last_client_activity_time) == -1)
            {
              perror ("Failed to get current time (1)");
              close_stream_connection (client_socket);
              return -1;
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

          ret = process_omp_client_input ();
          if (ret == 0)
            /* Processed all input. */
            client_input_stalled = 0;
          else if (ret == -1 || ret == -4)
            {
              /* Error.  Write rest of to_client to client, so that the
               * client gets any buffered output and the response to the
               * error. */
              write_to_client (client_session);
              close_stream_connection (client_socket);
              return -1;
            }
          else if (ret == -2)
            {
              /* to_server buffer full. */
              tracef ("   client input stalled 1\n");
              client_input_stalled = 1;
              /* Break to write to_server. */
              break;
            }
          else if (ret == -3)
            {
              /* to_client buffer full. */
              tracef ("   client input stalled 2\n");
              client_input_stalled = 2;
              /* Break to write to_client. */
              break;
            }
          else
            /* Programming error. */
            assert (0);
        }

      if ((fds & FD_SERVER_READ) == FD_SERVER_READ
          && FD_ISSET (server_socket, &readfds))
        {
#if TRACE || LOG
          buffer_size_t initial_start = from_server_end;
#endif
          tracef ("   FD_SERVER_READ\n");

          switch (read_from_server (server_session, server_socket))
            {
              case  0:       /* Read everything. */
                break;
              case -1:       /* Error. */
                /* This may be because the server closed the connection
                 * at the end of a command. */ // FIX then should get eof (-3)
                set_server_init_state (SERVER_INIT_TOP);
                break;
              case -2:       /* from_server buffer full. */
                /* There may be more to read. */
                break;
              case -3:       /* End of file. */
                set_server_init_state (SERVER_INIT_TOP);
                if (client_active == 0)
                  /* The client has closed the connection, so exit. */
                  return 0;
                break;
              default:       /* Programming error. */
                assert (0);
            }

#if TRACE || LOG
          /* This check prevents output in the "asynchronous network
           * error" case. */
          if (from_server_end > initial_start)
            {
              logf ("<= %.*s\n",
                    from_server_end - initial_start,
                    from_server + initial_start);
#if TRACE_TEXT
              tracef ("<= server  \"%.*s\"\n",
                      from_server_end - initial_start,
                      from_server + initial_start);
#else
              tracef ("<= server  %i bytes\n",
                      from_server_end - initial_start);
#endif
            }
#endif /* TRACE || LOG */

          ret = process_otp_server_input ();
          if (ret == 0)
            /* Processed all input. */
            server_input_stalled = FALSE;
          else if (ret == 1)
            {
              /* Received server BYE.  Write out the rest of to_server (the
               * BYE ACK).  If the client is still connected then recreate the
               * server session, else exit. */
              write_to_server (server_socket, server_session);
              set_server_init_state (SERVER_INIT_TOP);
              if (client_active == 0)
                return 0;
              server_socket = recreate_session (server_socket,
                                                server_session,
                                                server_credentials);
              if (server_socket == -1)
                {
                  close_stream_connection (client_socket);
                  return -1;
                }
              *server_socket_addr = server_socket;
            }
          else if (ret == 2)
            {
              /* Bad login to server. */
              if (client_active == 0)
                return 0;
              close_stream_connection (client_socket);
              return -1;
            }
          else if (ret == -1)
           {
             /* Error. */
             close_stream_connection (client_socket);
             return -1;
           }
          else if (ret == -3)
            {
              /* to_server buffer full. */
              tracef ("   server input stalled\n");
              server_input_stalled = TRUE;
              /* Break to write to server. */
              break;
            }
          else
            /* Programming error. */
            assert (0);
        }

      if ((fds & FD_SERVER_WRITE) == FD_SERVER_WRITE
          && FD_ISSET (server_socket, &writefds))
        {
          /* Write as much as possible to the server. */

          switch (write_to_server (server_socket, server_session))
            {
              case  0:      /* Wrote everything in to_server. */
                break;
              case -1:      /* Error. */
                /* FIX This may be because the server closed the connection
                 * at the end of a command? */
                if (client_active)
                  close_stream_connection (client_socket);
                return -1;
              case -2:      /* Wrote as much as server was willing to accept. */
                break;
              case -3:      /* Did an initialisation step. */
                break;
              default:      /* Programming error. */
                assert (0);
            }
        }

      if ((fds & FD_CLIENT_WRITE) == FD_CLIENT_WRITE
          && FD_ISSET (client_socket, &writefds))
        {
          /* Write as much as possible to the client. */

          switch (write_to_client (client_session))
            {
              case  0:      /* Wrote everything in to_client. */
                break;
              case -1:      /* Error. */
                close_stream_connection (client_socket);
                return -1;
              case -2:      /* Wrote as much as client was willing to accept. */
                break;
              default:      /* Programming error. */
                assert (0);
            }

          if (time (&last_client_activity_time) == -1)
            {
              perror ("Failed to get current time (2)");
              close_stream_connection (client_socket);
              return -1;
            }
        }

      if (client_input_stalled)
        {
          /* Try process the client input, in case writing to the server
           * or client has freed some space in to_server or to_client. */

          ret = process_omp_client_input ();
          if (ret == 0)
            /* Processed all input. */
            client_input_stalled = 0;
          else if (ret == -1)
            {
              /* Error.  Write rest of to_client to client, so that the
               * client gets any buffered output and the response to the
               * error. */
              write_to_client (client_session);
              close_stream_connection (client_socket);
              return -1;
            }
          else if (ret == -2)
            {
              /* to_server buffer full. */
              tracef ("   client input still stalled (1)\n");
              client_input_stalled = 1;
            }
          else if (ret == -3)
            {
              /* to_client buffer full. */
              tracef ("   client input still stalled (2)\n");
              client_input_stalled = 2;
            }
          else
            /* Programming error. */
            assert (0);
        }

      if (server_input_stalled)
        {
          /* Try process the server input, in case writing to the server
           * has freed some space in to_server. */

          ret = process_otp_server_input ();
          if (ret == 0)
            /* Processed all input. */
            server_input_stalled = FALSE;
          else if (ret == 1)
            {
              /* Received server BYE.  Write out the rest of to_server (the
               * BYE ACK).  If the client is still connected then recreate the
               * server session, else exit. */
              write_to_server (server_socket, server_session);
              set_server_init_state (SERVER_INIT_TOP);
              if (client_active == 0)
                return 0;
              server_socket = recreate_session (server_socket,
                                                server_session,
                                                server_credentials);
              if (server_socket == -1)
                {
                  close_stream_connection (client_socket);
                  return -1;
                }
              *server_socket_addr = server_socket;
            }
          else if (ret == 2)
            {
              /* Bad login to server. */
              if (client_active == 0)
                return 0;
              close_stream_connection (client_socket);
              return -1;
            }
          else if (ret == -1)
            {
              /* Error. */
              if (client_active)
                close_stream_connection (client_socket);
              return -1;
            }
          else if (ret == -3)
            /* to_server buffer still full. */
            tracef ("   server input stalled\n");
          else
            /* Programming error. */
            assert (0);
        }

      /* Check if client connection is out of time. */
      {
        time_t current_time;
        if (time (&current_time) == -1)
          {
            perror ("Failed to get current time (3)");
            close_stream_connection (client_socket);
            return -1;
          }
        if (last_client_activity_time - current_time >= CLIENT_TIMEOUT)
          {
            tracef ("client timeout (1)\n");
            close_stream_connection (client_socket);
            if (server_is_active ())
              client_active = 0;
            else
              return 0;
          }
      }

    } /* while (1) */

  close_stream_connection (client_socket);
  return 0;
}
