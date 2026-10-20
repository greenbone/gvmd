/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "client_watcher.h"

#include <cgreen/cgreen.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

Describe (client_watcher);

static int sockets[2];

BeforeEach (client_watcher)
{
  sockets[0] = -1;
  sockets[1] = -1;
  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
}

AfterEach (client_watcher)
{
  if (sockets[0] >= 0)
    close (sockets[0]);
  if (sockets[1] >= 0)
    close (sockets[1]);
}

Ensure (client_watcher, keeps_idle_connection_live)
{
  int socket_errno = -1;

  assert_that (client_connection_probe (sockets[0], &socket_errno),
               is_equal_to (CLIENT_CONNECTION_LIVE));
  assert_that (socket_errno, is_equal_to (0));
}

Ensure (client_watcher, keeps_connection_with_pending_input_live_and_unread)
{
  char sent = 'x';
  char received = 0;
  int socket_errno = -1;

  assert_that (send (sockets[1], &sent, sizeof (sent), 0), is_equal_to (1));
  assert_that (client_connection_probe (sockets[0], &socket_errno),
               is_equal_to (CLIENT_CONNECTION_LIVE));
  assert_that (socket_errno, is_equal_to (0));
  assert_that (recv (sockets[0], &received, sizeof (received), MSG_DONTWAIT),
               is_equal_to (1));
  assert_that (received, is_equal_to (sent));
}

Ensure (client_watcher, detects_orderly_peer_close)
{
  int socket_errno = -1;

  close (sockets[1]);
  sockets[1] = -1;

  assert_that (client_connection_probe (sockets[0], &socket_errno),
               is_equal_to (CLIENT_CONNECTION_CLOSED));
  assert_that (socket_errno, is_equal_to (0));
}

Ensure (client_watcher, reports_unrecoverable_socket_error)
{
  int socket_errno = 0;

  assert_that (client_connection_probe (-1, &socket_errno),
               is_equal_to (CLIENT_CONNECTION_ERROR));
  assert_that (socket_errno, is_equal_to (EBADF));
}

Ensure (client_watcher, treats_transient_errors_as_live)
{
  assert_that (client_connection_probe_result (-1, EAGAIN),
               is_equal_to (CLIENT_CONNECTION_LIVE));
  assert_that (client_connection_probe_result (-1, EWOULDBLOCK),
               is_equal_to (CLIENT_CONNECTION_LIVE));
  assert_that (client_connection_probe_result (-1, EINTR),
               is_equal_to (CLIENT_CONNECTION_LIVE));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, client_watcher, keeps_idle_connection_live);
  add_test_with_context (suite, client_watcher,
                         keeps_connection_with_pending_input_live_and_unread);
  add_test_with_context (suite, client_watcher, detects_orderly_peer_close);
  add_test_with_context (suite, client_watcher,
                         reports_unrecoverable_socket_error);
  add_test_with_context (suite, client_watcher,
                         treats_transient_errors_as_live);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
