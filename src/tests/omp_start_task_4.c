/* Test 1 of OMP START_TASK.
 * $Id$
 * Description:
 * Test starting two tasks at the same time on the same connection.
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
  char *id1, *id2;
  entity_t entity, expected;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (env_authenticate (&session)) goto fail;

  /* Create the tasks. */

  if (create_task_from_rc_file (&session,
                                "new_task_medium_rc",
                                "Task 1 for omp_start_task_4",
                                "Test omp_start_task_0 task.",
                                &id1))
    goto fail;

  if (create_task_from_rc_file (&session,
                                "new_task_medium_rc",
                                "Task 2 for omp_start_task_4",
                                "Test omp_start_task_0 task.",
                                &id2))
    goto fail;

  /* Start the first task. */

  if (start_task (&session, id1)) goto delete_fail;

  /* Try start the second task. */

  if (sendf_to_manager (&session,
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
      delete_task (&session, id1);
      delete_task (&session, id2);
      free (id1);
      free (id2);
 fail:
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (expected);
  free_entity (entity);
  delete_task (&session, id1);
  delete_task (&session, id2);
  free (id1);
  free (id2);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
