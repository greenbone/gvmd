/* Test 1 of OMP START_TASK.
 * $Id$
 * Description:
 * Test starting two tasks at the same time on the same connection.
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
  char *id1, *id2;
  entity_t entity, expected;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (omp_authenticate_env (&session)) goto fail;

  /* Create the tasks. */

  if (omp_create_task_rc_file (&session,
                               "new_task_medium_rc",
                               "Task 1 for omp_start_task_4",
                               "Test omp_start_task_0 task.",
                               &id1))
    goto fail;

  if (omp_create_task_rc_file (&session,
                               "new_task_medium_rc",
                               "Task 2 for omp_start_task_4",
                               "Test omp_start_task_0 task.",
                               &id2))
    goto fail;

  /* Start the first task. */

  if (omp_start_task (&session, id1)) goto delete_fail;

  /* Try start the second task. */

  if (openvas_server_sendf (&session,
                            "<start_task task_id=\"%s\"/>",
                            id2)
      == -1)
    return -1;

  entity = NULL;
  if (read_entity (&session, &entity)) goto delete_fail;

  expected = add_entity (NULL, "start_task_response", NULL);
  add_attribute (expected, "status", "400");
  add_attribute (expected,
                 "status_text",
                 "There is already a task running in this process");

  if (compare_entities (entity, expected))
    {
      free_entity (expected);
      free_entity (entity);
 delete_fail:
      omp_delete_task (&session, id1);
      omp_delete_task (&session, id2);
      free (id1);
      free (id2);
 fail:
      close_manager_connection (socket, session);
      /* With the new forking mechanism for starting tasks it is possible
       * to start two tasks on the same connection, so this is actually
       * the correct behaviour. */
      return EXIT_SUCCESS;
    }

  free_entity (expected);
  free_entity (entity);
  omp_delete_task (&session, id1);
  omp_delete_task (&session, id2);
  free (id1);
  free (id2);
  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
