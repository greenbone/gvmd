/* Test 3 of OMP GET_STATUS.
 * $Id$
 * Description: Test OMP <get_status/>, waiting for a task to start.
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
  const char* status;
  entity_t entity, task;
  entities_t tasks;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (env_authenticate (&session)) goto fail;

  if (create_task_from_rc_file (&session,
                                "new_task_small_rc",
                                "Task for omp_get_status_3",
                                "Test omp_get_status_3 task.",
                                &id))
    goto fail;

  /* Start the task. */

  if (start_task (&session, id)) goto delete_fail;

  /* Wait for the task to start on the server. */

  if (wait_for_task_start (&session, id))
    {
      goto delete_fail;
    }

  /* Request the status. */

  if (send_to_manager (&session, "<get_status/>") == -1) goto delete_fail;

  /* Read the response. */

  entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      goto delete_fail;
    }

  /* Check if the response includes the created task. */

  if (entity
      && entity_attribute (entity, "status")
      && (strcmp (entity_attribute (entity, "status"), "200") == 0))
    {
      tasks = entity->entities;
      while ((task = first_entity (tasks)))
        {
          if (entity_attribute (task, "id")
              && strcmp (entity_attribute (task, "id"), id) == 0)
            {
              if (entity_child (task, "name")
                  && (strcmp (entity_text (entity_child (task, "name")),
                              "Task for omp_get_status_3")
                      == 0)
                  && entity_child (task, "status")
                  && (status = entity_text (entity_child (task, "status")))
                  && ((strcmp (status, "Running") == 0)
                      || (strcmp (status, "Done") == 0)))
                {
                  free_entity (entity);
                  delete_task (&session, id);
                  free (id);
                  close_manager_connection (socket, session);
                  return EXIT_SUCCESS;
                }
              break;
            }
          tasks = next_entities (tasks);
        }
    }

  free_entity (entity);
 delete_fail:
  delete_task (&session, id);
  free (id);
 fail:
  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
