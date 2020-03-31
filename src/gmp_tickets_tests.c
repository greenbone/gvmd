/* Copyright (C) 2019 Greenbone Networks GmbH
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

#include "gmp_tickets.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (gmp_tickets);
BeforeEach (gmp_tickets) {}
AfterEach (gmp_tickets) {}

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

int
copy_ticket (const char *comment, const char *ticket_id, ticket_t *new_ticket)
{
  mock ();
  return 0;
}

int
create_ticket (const char *comment, const char *result_id,
               const char *user_id, const char *open_note,
               ticket_t *ticket)
{
  mock ();
  return 0;
}

Ensure (gmp_tickets, create_ticket_run_calls_copy_ticket_when_given_copy)
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
  assert_that (create_ticket_data.context->done, is_not_equal_to (0));

  expect (copy_ticket);
  never_expect (create_ticket);
  create_ticket_run (&gmp_parser, &error);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, gmp_tickets, create_ticket_run_calls_copy_ticket_when_given_copy);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
