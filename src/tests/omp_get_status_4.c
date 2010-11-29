/* Test 4 of OMP GET_STATUS.
 * $Id$
 * Description: Test OMP GET_STATUS with a task id, waiting for the task to end.
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
  entity_t entity, task;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (omp_authenticate_env (&session)) goto fail;

  if (omp_create_task_rc_file (&session,
                               "new_task_small_rc",
                               "Task for omp_get_status_4",
                               "Test omp_get_status_4 task.",
                               &id))
    goto fail;

  /* Start the task. */

  if (omp_start_task (&session, id)) goto delete_fail;

  /* Wait for the task to end on the scanner. */

  if (omp_wait_for_task_end (&session, id))
    {
      goto delete_fail;
    }

  /* Request the status. */

  if (openvas_server_sendf (&session,
                            "<get_status task_id=\"%s\"/>",
                            id)
      == -1)
    goto delete_fail;

  /* Read the response. */

  entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      goto delete_fail;
    }
  if (entity) print_entity (stdout, entity);

  /* Compare to expected response. */

  if (entity
      && entity_attribute (entity, "status")
      && (strcmp (entity_attribute (entity, "status"), "200") == 0)
      && (task = entity_child (entity, "task"))
      && entity_attribute (task, "id")
      && (strcmp (entity_attribute (task, "id"), id) == 0)
      && entity_child (task, "name")
      && (strcmp (entity_text (entity_child (task, "name")),
                 "Task for omp_get_status_4")
          == 0)
      && entity_child (task, "status")
      && (strcmp (entity_text (entity_child (task, "status")), "Done") == 0)
      && entity_child (task, "report_count")
      && (strcmp (entity_text (entity_child (task, "report_count")), "1") == 0))
    {
      free_entity (entity);
      omp_delete_task (&session, id);
      free (id);
      close_manager_connection (socket, session);
      return EXIT_SUCCESS;
    }

  free_entity (entity);
 delete_fail:
  omp_delete_task (&session, id);
  free (id);
 fail:
  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
