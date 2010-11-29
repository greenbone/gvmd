/* Test 1 of deleting a report.
 * $Id$
 * Description: Test OMP DELETE_REPORT with an empty REPORT_ID.
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

#define TRACE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "../tracef.h"

int
main ()
{
  int socket;
  gnutls_session_t session;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Remove the report. */

  if (omp_authenticate_env (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (openvas_server_send (&session,
                           "<delete_report report_id=\"\"/>")
      == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }
  entity_t entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "delete_report_response", NULL);
  add_attribute (expected, "status", "404");
  add_attribute (expected, "status_text", "Failed to find report ''");

  if (compare_entities (entity, expected))
    {
      free_entity (expected);
      free_entity (entity);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (entity);
  free_entity (expected);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
