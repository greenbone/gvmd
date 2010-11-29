/* Test 2 of OMP GET_STATUS.
 * $Id$
 * Description: Test the OMP GET_STATUS command on a running task.
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

#include <glib.h>
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

  if (omp_authenticate_env (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (omp_create_task_rc_file (&session,
                               "new_task_small_rc",
                               "Task for omp_get_status_2",
                               "Test omp_get_status_2 task.",
                               &id))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Start the task. */

  if (omp_start_task (&session, id))
    {
      omp_delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  /* Wait for the task to start on the scanner. */

  if (omp_wait_for_task_start (&session, id))
    {
      omp_delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  /* Request the task status. */

  if (omp_authenticate_env (&session))
    {
      omp_delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  if (openvas_server_sendf (&session,
                            "<get_status task_id=\"%s\"/>",
                            id)
      == -1)
    {
      omp_delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);
  print_entity (stdout, entity);

  /* Compare to expected response. */

  if (entity
      && entity_attribute (entity, "status")
      && (strcmp (entity_attribute (entity, "status"), "200") == 0)
      && (task = entity_child (entity, "task"))
      && entity_attribute (task, "id")
      && (strcmp (entity_attribute (task, "id"), id) == 0)
      && entity_child (task, "name")
      && (strcmp (entity_text (entity_child (task, "name")),
                 "Task for omp_get_status_2")
          == 0)
      && entity_child (task, "status")
      && ((strcmp (entity_text (entity_child (task, "status")), "Running")
           == 0)
          || (strcmp (entity_text (entity_child (task, "status")), "Done")
              == 0)))
    {
      free_entity (entity);
      omp_delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_SUCCESS;
    }

  free_entity (entity);
  omp_delete_task (&session, id);
  close_manager_connection (socket, session);
  free (id);
  return EXIT_FAILURE;
}
