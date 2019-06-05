/* Copyright (C) 2019 Greenbone Networks GmbH
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

#include "gmp_tickets.c"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/* create_ticket_run */

int
dummy_client_writer (const char *message, void *data)
{
  return 0;
}

void
log_event (const char *type, const char *type_name, const char *id,
           const char *action)
{
  return;
}

gchar *
ticket_uuid (ticket_t ticket)
{
  return g_strdup ("9b5da19e-86b4-11e9-b0d2-28d24461215b");
}

int return_flag = 0;

int
copy_ticket (const char *comment, const char *ticket_id, ticket_t *new_ticket)
{
  return_flag = mock ();
  return 0;
}

int
create_ticket (const char *comment, const char *result_id,
               const char *user_id, const char *open_note,
               ticket_t *ticket)
{
  return_flag = mock ();
  return 0;
}

static void
create_ticket_run_calls_copy_ticket_when_given_copy (void **state)
{
  gmp_parser_t gmp_parser;
  GError *error;
  const gchar *uuid;

  /* Check that create_ticket_run calls only copy_ticket when given COPY. */

  uuid = "9b5da19e-86b4-11e9-b0d2-28d24461215b";
  gmp_parser.client_writer = dummy_client_writer;

  /* <CREATE_TICKET> */
  create_ticket_start (&gmp_parser, NULL, NULL);

  create_ticket_element_start (&gmp_parser, "copy", NULL, NULL);
  create_ticket_element_text (uuid, strlen (uuid));
  create_ticket_element_end (&gmp_parser, &error, "copy");

  create_ticket_element_start (&gmp_parser, "comment", NULL, NULL);
  create_ticket_element_text (uuid, strlen (uuid));
  create_ticket_element_end (&gmp_parser, &error, "comment");

  /* </CREATE_TICKET> */
  xml_handle_end_element (create_ticket_data.context, "create_ticket");
  assert_int_not_equal (create_ticket_data.context->done, 0);

  will_return_always (copy_ticket, 1);
  will_return_maybe (create_ticket, 2);
  create_ticket_run (&gmp_parser, &error);
  assert_int_equal (return_flag, 1);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  const struct CMUnitTest tests[] = { cmocka_unit_test (create_ticket_run_calls_copy_ticket_when_given_copy) };

  return cmocka_run_group_tests (tests, NULL, NULL);
}
