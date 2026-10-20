/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Client connection watcher helpers.
 */

#include "client_watcher.h"

#include <errno.h>
#include <sys/socket.h>

/**
 * @brief Classify the result of peeking at a client connection.
 *
 * @param[in]  result      Return value from recv.
 * @param[in]  recv_errno  errno captured after recv returned an error.
 *
 * @return State of the client connection.
 */
client_connection_state_t
client_connection_probe_result (ssize_t result, int recv_errno)
{
  if (result > 0)
    return CLIENT_CONNECTION_LIVE;

  if (result == 0)
    return CLIENT_CONNECTION_CLOSED;

  if (recv_errno == EAGAIN || recv_errno == EWOULDBLOCK || recv_errno == EINTR)
    return CLIENT_CONNECTION_LIVE;

  return CLIENT_CONNECTION_ERROR;
}

/**
 * @brief Non-blockingly probe a client connection without consuming data.
 *
 * @param[in]   socket_fd     Client socket descriptor.
 * @param[out]  socket_errno  Error from recv for CLIENT_CONNECTION_ERROR.
 *
 * @return State of the client connection.
 */
client_connection_state_t
client_connection_probe (int socket_fd, int *socket_errno)
{
  char buf[1];
  int recv_errno;
  ssize_t result;
  client_connection_state_t state;

  result = recv (socket_fd, buf, sizeof (buf), MSG_PEEK | MSG_DONTWAIT);
  recv_errno = errno;
  state = client_connection_probe_result (result, recv_errno);

  if (socket_errno)
    *socket_errno = state == CLIENT_CONNECTION_ERROR ? recv_errno : 0;

  return state;
}
