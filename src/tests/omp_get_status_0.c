/* Test 0 of OMP GET_STATUS.
 * $Id$
 * Description: Test the OMP <get_status/> command.
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
  entity_t entity;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (omp_authenticate_env (&session)) goto fail;

  if (omp_create_task_rc_file (&session,
                               "new_task_empty_rc",
                               "Test omp_get_status_0 task",
                               "Task for manager test omp_get_status_0.",
                               &id))
    goto fail;

  /* Start the task. */

  if (omp_start_task (&session, id)) goto delete_fail;

  /* Request the status. */

  if (omp_authenticate_env (&session)) goto delete_fail;

  if (openvas_server_send (&session, "<get_status/>") == -1)
    goto delete_fail;

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  if (entity
      && entity_attribute (entity, "status")
      && (strcmp (entity_attribute (entity, "status"), "200") == 0))
    {
      entity_t task;
      const char* status;
      entities_t tasks = entity->entities;

      while ((task = first_entity (tasks)))
        {
          if (entity_attribute (task, "id")
              && strcmp (entity_attribute (task, "id"), id) == 0)
            {
              if (entity_child (task, "name")
                  && (strcmp (entity_text (entity_child (task, "name")),
                              "Test omp_get_status_0 task")
                      == 0)
                  && entity_child (task, "status")
                  && (status = entity_text (entity_child (task, "status")))
                  && (strcmp (status, "Requested") == 0
                      || strcmp (status, "Running") == 0
                      || strcmp (status, "Done") == 0))
                {
                  free_entity (entity);
                  omp_delete_task (&session, id);
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
  omp_delete_task (&session, id);
  free (id);
 fail:
  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
