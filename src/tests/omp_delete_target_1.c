/* Test 1 of OMP DELETE_TARGET.
 * $Id$
 * Description: Test deleting a target that is referenced by a task.
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
  char *id = NULL;
  entity_t entity, expected;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (omp_authenticate_env (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Add target. */

  omp_delete_target (&session, "omp_delete_target_1");

  if (omp_create_target (&session,
                         "omp_delete_target_1",
                         "localhost, 127.0.0.1",
                         "Test comment"))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Create task that uses the target. */

  if (omp_create_task (&session,
                       "omp_delete_target_1",
                       "Full and fast",
                       "omp_delete_target_1",
                       "Comment",
                       &id))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Try remove target. */

  if (openvas_server_send (&session,
                           "<delete_target>"
                           "<name>omp_delete_target_1</name>"
                           "</delete_target>"))
    goto delete_fail;

  /* Read the response. */

  entity = NULL;
  if (read_entity (&session, &entity)) goto delete_fail;

  /* Check the response. */

  expected = add_entity (NULL, "delete_target_response", NULL);
  add_attribute (expected, "status", "400");
  add_attribute (expected,
                 "status_text",
                 "Target is in use");

  if (compare_entities (entity, expected))
    {
      free_entity (expected);
      free_entity (entity);
 delete_fail:
      omp_delete_task (&session, id);
      omp_delete_target (&session, "omp_delete_target_1");
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (expected);
  free_entity (entity);
  omp_delete_task (&session, id);
  omp_delete_target (&session, "omp_delete_target_1");
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
