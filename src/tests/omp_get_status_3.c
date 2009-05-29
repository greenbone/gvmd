/* Test 3 of OMP GET_STATUS.
 * $Id$
 * Description: Test OMP <get_status/>, waiting for the task to start.
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

  entity_t entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      goto delete_fail;
    }
  if (entity) print_entity (stdout, entity);

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "get_status_response", NULL);
  add_entity (&expected->entities, "status", "200");
  add_entity (&expected->entities, "task_count", "1");
  entity_t task = add_entity (&expected->entities, "task", NULL);
  add_entity (&task->entities, "task_id", "0");
  add_entity (&task->entities, "identifier", "Simple scan");
  add_entity (&task->entities, "status", "Running");
  entity_t messages = add_entity (&task->entities, "messages", "");
  add_entity (&messages->entities, "debug", "0");
  add_entity (&messages->entities, "hole", "0");
  add_entity (&messages->entities, "info", "0");
  add_entity (&messages->entities, "log", "0");
  add_entity (&messages->entities, "warning", "0");

  if (compare_entities (entity, expected))
    {
      free_entity (entity);
      free_entity (expected);
 delete_fail:
      delete_task (&session, id);
      free (id);
 fail:
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (entity);
  free_entity (expected);
  delete_task (&session, id);
  free (id);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
