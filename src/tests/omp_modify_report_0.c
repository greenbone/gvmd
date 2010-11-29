/* Test 0 of modifying a report.
 * $Id$
 * Description: Test setting the comment on report.
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
  char* id;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (omp_authenticate_env (&session)) goto fail;

  if (omp_create_task_rc_file (&session,
                               "new_task_small_rc",
                               "Task for omp_delete_report_0",
                               "Test omp_delete_report_0 task.",
                               &id))
    goto fail;

  /* Start the task. */

  if (omp_start_task (&session, id)) goto delete_fail;

  /* Wait for the task to finish on the scanner. */

  if (omp_wait_for_task_end (&session, id)) goto delete_fail;

  /* Request the status. */

  if (openvas_server_sendf (&session,
                            "<get_status task_id=\"%s\"/>",
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


  /* Set the comment. */

  if (openvas_server_sendf (&session,
                            "<modify_report"
                            " report_id=\"%s\">"
                            "<parameter id=\"comment\">"
                            "Test comment for omp_modify_report_0."
                            "</parameter>"
                            "</modify_report>",
                            report_id)
      == -1)
    goto delete_fail;
  entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      goto delete_fail;
    }

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "modify_report_response", NULL);
  add_attribute (expected, "status", "200");
  add_attribute (expected, "status_text", "OK");

  if (compare_entities (entity, expected))
    {
      free_entity (expected);
 free_fail:
      free_entity (entity);
 delete_fail:
      omp_delete_task (&session, id);
      free (id);
 fail:
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (entity);
  free_entity (expected);
  omp_delete_task (&session, id);
  free (id);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
