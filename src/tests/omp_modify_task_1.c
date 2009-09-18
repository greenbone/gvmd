/* Test 1 of OMP MODIFY_TASK.
 * $Id$
 * Description: Test OMP simultaneous MODIFY_TASK commands.
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
  int socket1, socket2, ret;
  gnutls_session_t session1;
  gnutls_session_t session2;
  char* id;
  entity_t entity, task;

  setup_test ();

  socket1 = connect_to_manager (&session1);
  if (socket1 == -1) return EXIT_FAILURE;

  if (omp_authenticate_env (&session1))
    {
      close_manager_connection (socket1, session1);
      return EXIT_FAILURE;
    }

  /* Create a task in process 1. */

  if (omp_create_task_rc_file (&session1,
                               "new_task_empty_rc",
                               "Test for omp_modify_task_1",
                               "Comment.",
                               &id))
    {
      close_manager_connection (socket1, session1);
      return EXIT_FAILURE;
    }

  /* Modify the task name in process 2. */

  socket2 = connect_to_manager (&session2);
  if (socket2 == -1)
    {
      close_manager_connection (socket1, session1);
      close_manager_connection (socket2, session2);
      free (id);
      return EXIT_FAILURE;
    }

  if (omp_authenticate_env (&session2))
    {
      omp_delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      close_manager_connection (socket2, session2);
      free (id);
      return EXIT_FAILURE;
    }

  if (openvas_server_sendf (&session2,
                            "<modify_task"
                            " task_id=\"%s\">"
                            "<parameter id=\"name\">Modified name</parameter>"
                            "</modify_task>",
                            id)
      == -1)
    {
      omp_delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      close_manager_connection (socket2, session2);
      free (id);
      return EXIT_FAILURE;
    }

  entity = NULL;
  read_entity (&session2, &entity);

  entity_t expected = add_entity (NULL, "modify_task_response", NULL);
  add_attribute (expected, "status", "200");
  add_attribute (expected, "status_text", "OK");

  close_manager_connection (socket2, session2);

  if (compare_entities (entity, expected))
    {
      omp_delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      free_entity (entity);
      free_entity (expected);
      free (id);
      return EXIT_FAILURE;
    }
  free_entity (entity);
  free_entity (expected);

  /* Check that process 1 registered the change. */

  if (openvas_server_sendf (&session1,
                            "<get_status task_id=\"%s\"/>",
                            id)
      == -1)
    {
      omp_delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      free (id);
      return EXIT_FAILURE;
    }

  entity = NULL;
  if (read_entity (&session1, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      omp_delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      free (id);
      return EXIT_FAILURE;
    }

  task = entity_child (entity, "task");
  if (task)
    {
      entity_t name = entity_child (task, "name");
      if (name && strcmp (entity_text (name), "Modified name") == 0)
        ret = EXIT_SUCCESS;
      else
        ret = EXIT_FAILURE;
    }
  else
    ret = EXIT_FAILURE;

  /* Cleanup. */

  omp_delete_task (&session1, id);
  close_manager_connection (socket1, session1);
  close_manager_connection (socket2, session2);
  free_entity (entity);
  free (id);

  return ret;
}
