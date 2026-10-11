/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmpd.c"

#include <cgreen/cgreen.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>

Describe (gmpd);

BeforeEach (gmpd)
{
  to_client_buffer_size = TO_CLIENT_BUFFER_SIZE;
  to_client_start = 0;
  to_client_end = 0;
  complete_client_deliveries (FALSE);
}

AfterEach (gmpd)
{
  complete_client_deliveries (FALSE);
  to_client_buffer_size = TO_CLIENT_BUFFER_SIZE;
  to_client_start = 0;
  to_client_end = 0;
}

static gboolean
set_nonblocking (int socket)
{
  int flags;

  flags = fcntl (socket, F_GETFL, 0);
  return flags >= 0 && fcntl (socket, F_SETFL, flags | O_NONBLOCK) == 0;
}

static gboolean
read_exact_with_deadline (int socket, GByteArray *output, gsize expected_size,
                          gint64 deadline)
{
  while (output->len < expected_size)
    {
      struct pollfd poll_fd = {socket, POLLIN, 0};
      gint64 remaining = deadline - g_get_monotonic_time ();
      int timeout;
      int ret;

      if (remaining <= 0)
        return FALSE;

      timeout = (remaining + 999) / 1000;
      ret = poll (&poll_fd, 1, timeout);
      if (ret <= 0)
        return FALSE;

      if (poll_fd.revents & POLLIN)
        {
          guchar buffer[37];
          ssize_t count;

          count = read (socket, buffer, sizeof (buffer));
          if (count <= 0)
            return FALSE;
          g_byte_array_append (output, buffer, count);
        }
      else
        return FALSE;
    }

  return TRUE;
}

Ensure (gmpd, send_to_client_covers_effective_buffer_boundaries)
{
  const gsize sizes[] = {127, 128, 129};
  gvm_connection_t connection = {0};
  GByteArray *expected;
  GByteArray *received;
  int sockets[2];
  gsize index;

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (set_nonblocking (sockets[0]), is_true);
  assert_that (set_nonblocking (sockets[1]), is_true);
  connection.socket = sockets[0];
  connection.tls = 0;
  to_client_buffer_size = 128;
  expected = g_byte_array_new ();

  for (index = 0; index < G_N_ELEMENTS (sizes); index++)
    {
      gchar *message = g_malloc (sizes[index] + 1);

      memset (message, 'a' + index, sizes[index]);
      message[sizes[index]] = '\0';
      assert_that (gmpd_send_to_client (message, &connection), is_false);
      g_byte_array_append (expected, (guchar *) message, sizes[index]);
      g_free (message);
    }

  assert_that (write_to_client (&connection), is_equal_to (0));

  received = g_byte_array_new ();
  assert_that (
    read_exact_with_deadline (sockets[1], received, expected->len,
                              g_get_monotonic_time () + 2 * G_TIME_SPAN_SECOND),
    is_true);
  assert_that (received->len, is_equal_to (expected->len));
  assert_that (memcmp (received->data, expected->data, expected->len),
               is_equal_to (0));

  g_byte_array_free (received, TRUE);
  g_byte_array_free (expected, TRUE);
  close (sockets[0]);
  close (sockets[1]);
}

typedef struct
{
  gint result;
} delivery_probe_t;

typedef struct
{
  gvm_connection_t *connection;
  const gchar *response;
  delivery_probe_t *probe;
  GMutex mutex;
  GCond condition;
  gboolean started;
  gboolean finished;
  gboolean send_failed;
  int flush_result;
} send_thread_data_t;

static void
record_delivery (gboolean success, void *data)
{
  delivery_probe_t *probe = data;

  g_atomic_int_set (&probe->result, success ? 1 : -1);
}

static gpointer
send_response_thread (gpointer data)
{
  send_thread_data_t *thread_data = data;
  int ret = -2;

  g_mutex_lock (&thread_data->mutex);
  thread_data->started = TRUE;
  g_cond_signal (&thread_data->condition);
  g_mutex_unlock (&thread_data->mutex);

  thread_data->send_failed =
    gmpd_send_to_client (thread_data->response, thread_data->connection);

  if (thread_data->send_failed == FALSE)
    {
      register_client_delivery (record_delivery, thread_data->probe, NULL);
      while ((ret = write_to_client (thread_data->connection)) == -2)
        ;
      complete_client_deliveries (ret == 0);
    }

  thread_data->flush_result = ret;
  g_mutex_lock (&thread_data->mutex);
  thread_data->finished = TRUE;
  g_cond_signal (&thread_data->condition);
  g_mutex_unlock (&thread_data->mutex);
  return NULL;
}

static gsize
fill_socket_until_eagain (int socket)
{
  guchar fill[256];
  gsize total = 0;

  memset (fill, 0xa5, sizeof (fill));
  while (1)
    {
      ssize_t count = write (socket, fill, sizeof (fill));

      if (count > 0)
        {
          total += count;
          continue;
        }
      if (count < 0 && errno == EINTR)
        continue;
      assert_that (count, is_equal_to (-1));
      assert_that (errno, is_equal_to (EAGAIN));
      break;
    }

  return total;
}

Ensure (gmpd, slow_reader_gets_complete_download_and_connection_reuse)
{
  const gsize fixture_size = 4097;
  const gchar *version_response =
    "<get_version_response status=\"200\" status_text=\"OK\"/>";
  gvm_connection_t connection = {0};
  delivery_probe_t probe = {0};
  send_thread_data_t thread_data = {0};
  GByteArray *received;
  GByteArray *version_received;
  GThread *thread;
  GString *response;
  const gchar *content_start;
  const gchar *content_end;
  guchar *decoded;
  gsize decoded_size;
  guchar *fixture;
  gchar *encoded;
  gchar *received_encoded;
  gchar *received_response;
  gsize prefix_left;
  gint64 deadline;
  int send_buffer_size = 256;
  int sockets[2];
  gsize index;

  fixture = g_malloc (fixture_size);
  for (index = 0; index < fixture_size; index++)
    fixture[index] = (index * 37 + 11) & 0xff;
  encoded = g_base64_encode (fixture, fixture_size);
  response = g_string_new ("<download_report_export_response status=\"200\""
                           " status_text=\"OK\"><report_export>"
                           "<content>");
  g_string_append (response, encoded);
  g_string_append (response, "</content></report_export>"
                             "</download_report_export_response>");

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (setsockopt (sockets[0], SOL_SOCKET, SO_SNDBUF, &send_buffer_size,
                           sizeof (send_buffer_size)),
               is_equal_to (0));
  assert_that (set_nonblocking (sockets[0]), is_true);
  assert_that (set_nonblocking (sockets[1]), is_true);
  connection.socket = sockets[0];
  connection.tls = 0;
  to_client_buffer_size = 128;
  prefix_left = fill_socket_until_eagain (sockets[0]);

  thread_data.connection = &connection;
  thread_data.response = response->str;
  thread_data.probe = &probe;
  g_mutex_init (&thread_data.mutex);
  g_cond_init (&thread_data.condition);
  thread = g_thread_new ("gmpd-send-test", send_response_thread, &thread_data);

  deadline = g_get_monotonic_time () + 3 * G_TIME_SPAN_SECOND;
  g_mutex_lock (&thread_data.mutex);
  while (thread_data.started == FALSE)
    assert_that (
      g_cond_wait_until (&thread_data.condition, &thread_data.mutex, deadline),
      is_true);
  if (thread_data.finished == FALSE)
    g_cond_wait_until (&thread_data.condition, &thread_data.mutex,
                       g_get_monotonic_time () + 20 * G_TIME_SPAN_MILLISECOND);
  assert_that (thread_data.finished, is_false);
  g_mutex_unlock (&thread_data.mutex);

  received = g_byte_array_new ();
  while (received->len < response->len && g_get_monotonic_time () < deadline)
    {
      struct pollfd poll_fd = {sockets[1], POLLIN, 0};
      guchar buffer[37];
      ssize_t count;

      if (poll (&poll_fd, 1, 50) <= 0)
        continue;
      count = read (sockets[1], buffer, sizeof (buffer));
      assert_that (count, is_greater_than (0));

      if (prefix_left >= (gsize) count)
        prefix_left -= count;
      else
        {
          gsize response_offset = prefix_left;
          prefix_left = 0;
          g_byte_array_append (received, buffer + response_offset,
                               count - response_offset);
        }
    }

  if (received->len != response->len)
    close (sockets[1]);
  g_thread_join (thread);

  assert_that (thread_data.send_failed, is_false);
  assert_that (thread_data.flush_result, is_equal_to (0));
  assert_that (g_atomic_int_get (&probe.result), is_equal_to (1));
  assert_that (received->len, is_equal_to (response->len));
  assert_that (memcmp (received->data, response->str, response->len),
               is_equal_to (0));

  received_response = g_strndup ((gchar *) received->data, received->len);
  content_start = strstr (received_response, "<content>");
  assert_that (content_start, is_not_null);
  content_start += strlen ("<content>");
  content_end = strstr (content_start, "</content>");
  assert_that (content_end, is_not_null);
  received_encoded = g_strndup (content_start, content_end - content_start);
  decoded = g_base64_decode (received_encoded, &decoded_size);
  assert_that (decoded_size, is_equal_to (fixture_size));
  assert_that (memcmp (decoded, fixture, fixture_size), is_equal_to (0));
  g_free (decoded);
  g_free (received_encoded);
  g_free (received_response);

  assert_that (gmpd_send_to_client (version_response, &connection), is_false);
  assert_that (write_to_client (&connection), is_equal_to (0));
  version_received = g_byte_array_new ();
  deadline = g_get_monotonic_time () + 2 * G_TIME_SPAN_SECOND;
  assert_that (read_exact_with_deadline (sockets[1], version_received,
                                         strlen (version_response), deadline),
               is_true);
  assert_that (version_received->len, is_equal_to (strlen (version_response)));
  assert_that (memcmp (version_received->data, version_response,
                       strlen (version_response)),
               is_equal_to (0));

  g_byte_array_free (version_received, TRUE);
  g_byte_array_free (received, TRUE);
  g_cond_clear (&thread_data.condition);
  g_mutex_clear (&thread_data.mutex);
  close (sockets[0]);
  close (sockets[1]);
  g_string_free (response, TRUE);
  g_free (encoded);
  g_free (fixture);
}

Ensure (gmpd, disconnected_client_fails_pending_delivery)
{
  gvm_connection_t connection = {0};
  delivery_probe_t probe = {0};
  void (*old_signal_handler) (int);
  int sockets[2];

  assert_that (socketpair (AF_UNIX, SOCK_STREAM, 0, sockets), is_equal_to (0));
  assert_that (set_nonblocking (sockets[0]), is_true);
  connection.socket = sockets[0];
  connection.tls = 0;
  to_client_buffer_size = 128;

  assert_that (gmpd_send_to_client ("response not yet delivered", &connection),
               is_false);
  register_client_delivery (record_delivery, &probe, NULL);
  assert_that (g_atomic_int_get (&probe.result), is_equal_to (0));

  old_signal_handler = signal (SIGPIPE, SIG_IGN);
  close (sockets[1]);
  assert_that (write_to_client (&connection), is_equal_to (-1));
  complete_client_deliveries (FALSE);
  signal (SIGPIPE, old_signal_handler);

  assert_that (g_atomic_int_get (&probe.result), is_equal_to (-1));
  close (sockets[0]);
}

int
main (int argc, char **argv)
{
  TestSuite *suite;
  int ret;

  suite = create_test_suite ();
  add_test_with_context (suite, gmpd,
                         send_to_client_covers_effective_buffer_boundaries);
  add_test_with_context (
    suite, gmpd, slow_reader_gets_complete_download_and_connection_reuse);
  add_test_with_context (suite, gmpd,
                         disconnected_client_fails_pending_delivery);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}
