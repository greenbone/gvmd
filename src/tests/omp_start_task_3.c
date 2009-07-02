/* Test 3 of OMP START_TASK.
 * $Id$
 * Description: Test the OMP START_TASK command with a target missing.
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

  if (env_authenticate (&session)) goto fail;

  /* Create a task. */

  if (create_task_from_rc_file (&session,
                                "new_task_small__missing_targets_rc",
                                "Task for omp_start_task_3",
                                "Test omp_start_task_3 task.",
                                &id))
    goto fail;

  /* Start the task. */

  gchar* msg = g_strdup_printf ("<start_task task_id=\"%s\"/>", id);
  int ret = send_to_manager (&session, msg);
  g_free (msg);
  if (ret == -1)
    goto delete_fail;

  /* Read the response. */

  entity_t entity = NULL;
  read_entity (&session, &entity);

  /* Compare response to expected response. */

  entity_t expected = add_entity (NULL, "start_task_response", NULL);
  add_attribute (expected, "status", "202");

  if (compare_entities (entity, expected))
    {
      free_entity (expected);
      free_entity (entity);
 delete_fail:
      delete_task (&session, id);
      free (id);
 fail:
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (expected);
  free_entity (entity);
  delete_task (&session, id);
  free (id);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
