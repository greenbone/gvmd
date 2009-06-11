/* Test 1 of OMP DELETE_TASK.
 * $Id$
 * Description: Test OMP DELETE_TASK with a task that has reports.
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
  char* id;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (env_authenticate (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (create_task_from_rc_file (&session,
                                "new_task_small_rc",
                                "Test for omp_delete_task_0",
                                "Simple test scan.",
                                &id))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Start the task. */

  if (start_task (&session, id)) goto delete_fail;

  /* Wait for the task to finish on the server. */

  if (wait_for_task_end (&session, id)) goto delete_fail;

  /* Request the status. */

  if (sendf_to_manager (&session,
                        "<get_status>"
                        "<task_id>%s</task_id>"
                        "</get_status>",
                        id)
      == -1)
    goto delete_fail;

  /* Read the first report ID from the response. */

  entity_t entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      goto delete_fail;
    }
  entity_t task = entity_child (entity, "task");
  if (task == NULL)
    {
      fprintf (stderr, "Failed to find task.\n");
      goto free_fail;
    }
  entity_t report = entity_child (task, "report");
  if (report == NULL)
    {
      fprintf (stderr, "Failed to find report.\n");
      goto free_fail;
    }
  const char* report_id = entity_attribute (report, "id");
  if (report_id == NULL)
    {
      fprintf (stderr, "Failed to find report id.\n");
      goto free_fail;
    }

  /* Remove the task. */

  if (sendf_to_manager (&session,
                        "<delete_task"
                        " task_id=\"%s\">"
                        "</delete_task>",
                        id))
    goto delete_fail;

  entity_t entity2 = NULL;
  if (read_entity (&session, &entity2))
    {
      fprintf (stderr, "Failed to read response.\n");
      goto free_fail;
    }
  free_entity (entity2);

  /* Wait for the server to stop the task. */

  if (wait_for_task_delete (&session, id)) goto free_fail;

  /* Try get the report. */

  if (sendf_to_manager (&session,
                        "<get_report><report_id>%s</report_id></get_report>",
                        report_id)
      == -1)
    goto free_fail;
  free_entity (entity);

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "get_report_response", NULL);
  add_attribute (expected, "status", "404");

  if (compare_entities (entity, expected))
    {
      free_entity (expected);
 free_fail:
      free_entity (entity);
 delete_fail:
      delete_task (&session, id);
      free (id);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (expected);
  free_entity (entity);
  free (id);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
