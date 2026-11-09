/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define WRITE_CLIENT_TIMEOUT 1
#include "gmp.h"
#include "gmpd.h"

#include <cgreen/cgreen.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/wait.h>

static ssize_t
test_record_send (gnutls_session_t, const void *, size_t);
static int test_record_get_direction (gnutls_session_t);
static int
test_poll (struct pollfd *, nfds_t, int);
static gint64
test_monotonic_time (void);
static void
test_init_gmp_process (const db_conn_info_t *, int (*) (const char *, void *),
                       void *, gchar **);
static int
test_process_gmp_client_input (void);
static void
test_connection_free (gvm_connection_t *);

#define gnutls_record_send test_record_send
#define gnutls_record_get_direction test_record_get_direction
#define poll test_poll
#define g_get_monotonic_time test_monotonic_time
#define init_gmp_process test_init_gmp_process
#define process_gmp_client_input test_process_gmp_client_input
#define gvm_connection_free test_connection_free
#include "gmpd.c"
#undef poll
#undef gnutls_record_get_direction
#undef gnutls_record_send
#undef g_get_monotonic_time
#undef init_gmp_process
#undef process_gmp_client_input
#undef gvm_connection_free

Describe (gmpd);

static int sockets[2];
static gvm_connection_t connection;
static int tls_step, poll_step, mock_poll_error, mock_poll_eintr;
static int mock_poll_timeout, mock_poll_failure, mock_tls_failure;
static gint64 mock_clock;
static int connection_freed, callback_failed;
static const void *retry_pointer;
static size_t retry_length;

BeforeEach (gmpd)
{
  int size = 4096;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (
    setsockopt (sockets[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof (size)),
    is_equal_to (0));
  assert_that (fcntl (sockets[0], F_SETFL, O_NONBLOCK), is_equal_to (0));
  memset (&connection, 0, sizeof (connection));
  connection.socket = sockets[0];
  to_client_start = to_client_end = 0;
  tls_step = poll_step = mock_poll_error = mock_poll_eintr = 0;
  mock_poll_timeout = mock_poll_failure = mock_tls_failure = 0;
  mock_clock = 0;
  connection_freed = callback_failed = 0;
  retry_pointer = NULL;
  retry_length = 0;
}

AfterEach (gmpd)
{
  close (sockets[0]);
  close (sockets[1]);
}

static double
cpu_seconds (void)
{
  struct rusage usage;

  getrusage (RUSAGE_SELF, &usage);
  return usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6
         + usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
}

/* Simulate a partial TLS send, then a read retry and a write retry. */
static ssize_t
test_record_send (gnutls_session_t session, const void *buffer, size_t size)
{
  (void) session;
  if (mock_tls_failure)
    return GNUTLS_E_PUSH_ERROR;
  switch (tls_step++)
    {
    case 0:
      assert_that (size, is_equal_to (5));
      assert_that (memcmp (buffer, "bcdef", size), is_equal_to (0));
      return 2;
    case 1:
      retry_pointer = buffer;
      retry_length = size;
      return GNUTLS_E_AGAIN;
    case 2:
      assert_that (buffer == retry_pointer, is_true);
      assert_that (size, is_equal_to (retry_length));
      return GNUTLS_E_AGAIN;
    default:
      assert_that (buffer == retry_pointer, is_true);
      assert_that (size, is_equal_to (retry_length));
      assert_that (memcmp (buffer, "def", size), is_equal_to (0));
      return size;
    }
}

static int
test_record_get_direction (gnutls_session_t session)
{
  (void) session;
  return tls_step == 2 ? 0 : 1;
}

static int
test_poll (struct pollfd *fds, nfds_t count, int timeout)
{
  if (!connection.tls)
    return poll (fds, count, timeout);

  assert_that (count, is_equal_to (1));
  assert_that (fds->fd, is_equal_to (sockets[0]));
  assert_that (timeout > 0, is_true);
  assert_that (fds->events, is_equal_to (tls_step == 2 ? POLLIN : POLLOUT));
  poll_step++;
  if (mock_poll_timeout)
    return 0;
  if (mock_poll_failure)
    {
      errno = EBADF;
      return -1;
    }
  if (mock_poll_eintr)
    {
      mock_poll_eintr--;
      errno = EINTR;
      return -1;
    }
  if (mock_poll_error)
    {
      fds->revents = mock_poll_error;
      return 1;
    }
  fds->revents = fds->events;
  return 1;
}

static gint64
test_monotonic_time (void)
{
  if (mock_clock)
    {
      mock_clock += 10000;
      return mock_clock;
    }
  return g_get_monotonic_time ();
}

static void
test_init_gmp_process (const db_conn_info_t *database,
                       int (*writer) (const char *, void *), void *data,
                       gchar **disable)
{
  (void) database;
  (void) writer;
  (void) data;
  (void) disable;
}

static int
test_process_gmp_client_input (void)
{
  memset (to_client, 'A', TO_CLIENT_BUFFER_SIZE);
  to_client_end = TO_CLIENT_BUFFER_SIZE;
  callback_failed = gmpd_send_to_client ("pending", &connection);
  return callback_failed ? -4 : 0;
}

static void
test_connection_free (gvm_connection_t *client_connection)
{
  assert_that (client_connection == &connection, is_true);
  connection_freed++;
  close (client_connection->socket);
  sockets[0] = -1;
}

static void
queue_tls_output (void)
{
  connection.tls = TRUE;
  memcpy (to_client, "abcdef", 6);
  to_client_start = 1;
  to_client_end = 6;
}

Ensure (gmpd, tls_retries_preserve_arguments_and_wait_in_both_directions)
{
  queue_tls_output ();
  assert_that (flush_to_client (&connection, 1000), is_equal_to (0));
  assert_that (tls_step, is_equal_to (4));
  assert_that (poll_step, is_equal_to (2));
  assert_that (to_client_start, is_equal_to (0));
  assert_that (to_client_end, is_equal_to (0));
}

Ensure (gmpd, interrupted_wait_retries_without_repeating_tls_send)
{
  queue_tls_output ();
  mock_poll_eintr = 1;
  assert_that (flush_to_client (&connection, 1000), is_equal_to (0));
  assert_that (tls_step, is_equal_to (4));
  assert_that (poll_step, is_equal_to (3));
}

Ensure (gmpd, socket_error_preserves_pending_tls_output)
{
  queue_tls_output ();
  mock_poll_error = POLLERR;
  assert_that (flush_to_client (&connection, 1000), is_equal_to (-1));
  assert_that (to_client_start, is_equal_to (3));
  assert_that (to_client_end, is_equal_to (6));
  assert_that (memcmp (to_client + to_client_start, "def", 3), is_equal_to (0));
}

Ensure (gmpd, tls_timeout_and_poll_failure_preserve_offsets)
{
  queue_tls_output ();
  mock_poll_timeout = 1;
  assert_that (flush_to_client (&connection, 1000), is_equal_to (-1));
  assert_that (to_client_start, is_equal_to (3));
  assert_that (to_client_end, is_equal_to (6));

  queue_tls_output ();
  tls_step = 0;
  mock_poll_timeout = 0;
  mock_poll_failure = 1;
  assert_that (flush_to_client (&connection, 1000), is_equal_to (-1));
  assert_that (to_client_start, is_equal_to (3));
  assert_that (to_client_end, is_equal_to (6));
}

Ensure (gmpd, tls_fatal_send_error_is_propagated)
{
  queue_tls_output ();
  mock_tls_failure = 1;
  assert_that (flush_to_client (&connection, 1000), is_equal_to (-1));
  assert_that (poll_step, is_equal_to (0));
  assert_that (to_client_start, is_equal_to (1));
  assert_that (to_client_end, is_equal_to (6));
}

Ensure (gmpd, repeated_readiness_does_not_restart_deadline)
{
  queue_tls_output ();
  mock_clock = 1;
  assert_that (flush_to_client (&connection, 15), is_equal_to (-1));
  assert_that (tls_step, is_equal_to (3));
  assert_that (poll_step, is_equal_to (1));
  assert_that (to_client_start, is_equal_to (3));
  assert_that (to_client_end, is_equal_to (6));
}

Ensure (gmpd, repeated_interruptions_do_not_restart_deadline)
{
  queue_tls_output ();
  mock_clock = 1;
  mock_poll_eintr = 10;
  assert_that (flush_to_client (&connection, 25), is_equal_to (-1));
  assert_that (tls_step, is_equal_to (2));
  assert_that (poll_step, is_equal_to (2));
  assert_that (to_client_start, is_equal_to (3));
  assert_that (to_client_end, is_equal_to (6));
}

Ensure (gmpd, callback_timeout_causes_worker_connection_cleanup)
{
  double cpu = cpu_seconds ();
  gint64 start = g_get_monotonic_time ();

  from_client_start = from_client_end = 0;
  assert_that (write (sockets[1], "<test/>", 7), is_equal_to (7));
  assert_that (serve_gmp (&connection, NULL, NULL), is_equal_to (-1));
  assert_that (callback_failed, is_true);
  assert_that (connection_freed, is_equal_to (1));
  assert_that (to_client_start > 0, is_true);
  assert_that (to_client_start < to_client_end, is_true);
  assert_that (to_client_end, is_equal_to (TO_CLIENT_BUFFER_SIZE));
  assert_that (g_get_monotonic_time () - start >= 900000, is_true);
  assert_that (cpu_seconds () - cpu < 0.2, is_true);
}

Ensure (gmpd, non_reading_client_times_out_with_low_cpu_and_keeps_offsets)
{
  gint64 start;
  double cpu;

  memset (to_client, 'A', TO_CLIENT_BUFFER_SIZE);
  to_client_end = TO_CLIENT_BUFFER_SIZE;
  start = g_get_monotonic_time ();
  cpu = cpu_seconds ();
  assert_that (flush_to_client (&connection, 200), is_equal_to (-1));
  assert_that (g_get_monotonic_time () - start >= 180000, is_true);
  assert_that (g_get_monotonic_time () - start < 2000000, is_true);
  assert_that (cpu_seconds () - cpu < 0.1, is_true);
  g_test_message (
    "Non-reading client: %.3f seconds CPU during %.3f seconds wait",
    cpu_seconds () - cpu, (g_get_monotonic_time () - start) / 1e6);
  assert_that (to_client_start > 0, is_true);
  assert_that (to_client_start < to_client_end, is_true);
  assert_that (to_client_end, is_equal_to (TO_CLIENT_BUFFER_SIZE));
}

Ensure (gmpd, slow_client_receives_large_response_without_loss_or_duplication)
{
  size_t length = 2 * TO_CLIENT_BUFFER_SIZE + 31;
  char *message = g_malloc (length + 1);
  pid_t reader;
  int status;
  double cpu;

  for (size_t i = 0; i < length; i++)
    message[i] = '!' + i % 90;
  message[length] = '\0';
  reader = fork ();
  assert_that (reader >= 0, is_true);
  if (reader == 0)
    {
      char buffer[4093];
      size_t received = 0;
      ssize_t count;

      close (sockets[0]);
      /* Delay the reader to force real socket backpressure. */
      poll (NULL, 0, 200);
      while ((count = read (sockets[1], buffer, sizeof (buffer))) > 0)
        {
          if (received + count > length
              || memcmp (buffer, message + received, count))
            _exit (1);
          received += count;
        }
      _exit (received == length ? 0 : 1);
    }

  cpu = cpu_seconds ();
  assert_that (gmpd_send_to_client (message, &connection), is_false);
  assert_that (flush_to_client (&connection, 2000), is_equal_to (0));
  shutdown (sockets[0], SHUT_WR);
  assert_that (waitpid (reader, &status, 0), is_equal_to (reader));
  assert_that (WIFEXITED (status), is_true);
  assert_that (WEXITSTATUS (status), is_equal_to (0));
  g_test_message ("Large response: %.3f seconds of sender CPU",
                  cpu_seconds () - cpu);
  g_free (message);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();
  int ret;

  add_test_with_context (
    suite, gmpd, tls_retries_preserve_arguments_and_wait_in_both_directions);
  add_test_with_context (suite, gmpd,
                         interrupted_wait_retries_without_repeating_tls_send);
  add_test_with_context (suite, gmpd,
                         socket_error_preserves_pending_tls_output);
  add_test_with_context (suite, gmpd,
                         tls_timeout_and_poll_failure_preserve_offsets);
  add_test_with_context (suite, gmpd, tls_fatal_send_error_is_propagated);
  add_test_with_context (suite, gmpd,
                         repeated_readiness_does_not_restart_deadline);
  add_test_with_context (suite, gmpd,
                         repeated_interruptions_do_not_restart_deadline);
  add_test_with_context (suite, gmpd,
                         callback_timeout_causes_worker_connection_cleanup);
  add_test_with_context (
    suite, gmpd, non_reading_client_times_out_with_low_cpu_and_keeps_offsets);
  add_test_with_context (
    suite, gmpd,
    slow_client_receives_large_response_without_loss_or_duplication);
  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
