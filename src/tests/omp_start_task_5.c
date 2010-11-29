/* Test 5 of OMP START_TASK.
 * $Id$
 * Description: Test starting a task that is already running.
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
  int socket, ret;
  gnutls_session_t session;
  char* id;
  entity_t entity, expected;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  if (omp_authenticate_env (&session)) goto fail;

  /* Create a task. */

  if (omp_create_task_rc_file (&session,
                               "new_task_empty_rc",
                               "Task for omp_start_task_0",
                               "Test omp_start_task_0 task.",
                               &id))
    goto fail;

  /* Start the task. */

  if (omp_start_task (&session, id)) goto delete_fail;

  /* Start the task again. */

  gchar* msg = g_strdup_printf ("<start_task task_id=\"%s\"/>", id);
  ret = openvas_server_send (&session, msg);
  g_free (msg);
  if (ret == -1)
    goto delete_fail;

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare response to expected response. */

  expected = add_entity (NULL, "start_task_response", NULL);
  add_attribute (expected, "status", "400");
  add_attribute (expected, "status_text", "Task is active already");

  if (compare_entities (entity, expected))
    {
      free_entity (expected);
      free_entity (entity);
 delete_fail:
      omp_delete_task (&session, id);
      free (id);
 fail:
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (expected);
  free_entity (entity);
  omp_delete_task (&session, id);
  free (id);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
