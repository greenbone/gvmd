/* Test 0 of OMP CREATE_TASK.
 * $Id$
 * Description: Test the OMP CREATE_TASK command.
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
  int socket, ret;
  gnutls_session_t session;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Send request. */

  if (env_authenticate (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (send_to_manager (&session, "<create_task>"
                                 "<task_file>YmFzZTY0IHRleHQ=</task_file>"
                                 "<identifier>omp_create_task_0 task</identifier>"
                                 "<comment>Task for omp_create_task_0.</comment>"
                                 "</create_task>")
      == -1)
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity_t entity = NULL;
  if (read_entity (&session, &entity))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  entity_t id_entity = entity_child (entity, "task_id");
  if (id_entity == NULL)
    {
      free_entity (entity);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Compare. */

  entity_t expected = add_entity (NULL, "create_task_response", NULL);
  add_entity (&expected->entities, "status", "201");
  add_entity (&expected->entities, "task_id", entity_text (id_entity));

  if (compare_entities (entity, expected))
    ret = EXIT_FAILURE;
  else
    ret = EXIT_SUCCESS;

  /* Cleanup. */

  close_manager_connection (socket, session);
  free_entity (entity);
  free_entity (expected);

  return ret;
}
