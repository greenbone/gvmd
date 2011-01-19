/* Test 3 of OMP START_TASK.
 * $Id$
 * Description:
 * Test OMP START_TASK of a task created with a target and a config.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@intevation.de>
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
  const char* id;
  entity_t entity, id_entity;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (omp_authenticate_env (&session)) goto fail;

  /* Create a task. */

  if (openvas_server_send (&session,
                           "<create_task>"
                           "<name>omp_start_task_4 task</name>"
                           "<comment>Task for omp_create_task_4.</comment>"
                           "<target>Localhost</target>"
                           "<config>Full and fast</config>"
                           "</create_task>")
      == -1)
    goto fail;

  /* Read the response. */

  entity = NULL;
  if (read_entity (&session, &entity)) return -1;

  /* Get the ID of the new task from the response. */

  id_entity = entity_child (entity, "task_id");
  if (id_entity == NULL)
    {
      free_entity (entity);
      return -1;
    }
  id = entity_text (id_entity);

  /* Start the task. */

  if (omp_start_task (&session, id))
    goto delete_fail;

  /* Wait for the task to finish on the scanner. */

  if (omp_wait_for_task_end (&session, id))
    goto delete_fail;

  omp_delete_task (&session, id);
  free_entity (entity);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;

 delete_fail:
  omp_delete_task (&session, id);
  free_entity (entity);
 fail:
  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
