/* Test 2 of OMP DELETE_TASK.
 * $Id$
 * Description: Test OMP DELETE_TASK on a running task.
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
  const char* omp_status;
  entity_t entity, task, status;

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

  if (start_task (&session, id))
    {
      delete_task (&session, id);
      free (id);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Remove the task. */

  if (sendf_to_manager (&session,
                        "<delete_task"
                        " task_id=\"%s\">"
                        "</delete_task>",
                        id))
    {
      free (id);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      free (id);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Request the status. */

  if (sendf_to_manager (&session,
                        "<get_status task_id=\"%s\"/>",
                        id)
      == -1)
    {
      free (id);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      free (id);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Compare to expected response. */

  task = entity_child (entity, "task");
  status = entity_child (task, "status");
  if (status == NULL
      || strcmp (entity_name (entity), "get_status_response"))
    {
      free_entity (entity);
      free (id);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }
  omp_status = entity_attribute (entity, "status");
  if (strcmp (omp_status, "404"))
    {
      const char* status_text = task_status (entity);

      /* It may be that the server is still busy stopping the task. */
      if (status_text && strcmp (status_text, "Delete requested") == 0)
        {
          free_entity (entity);
          free (id);
          close_manager_connection (socket, session);
          return EXIT_SUCCESS;
        }
      else
        {
          free_entity (entity);
          free (id);
          close_manager_connection (socket, session);
          return EXIT_FAILURE;
        }
    }

  free_entity (entity);
  free (id);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
