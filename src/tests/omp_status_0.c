/* Test 0 of OMP STATUS.
 * $Id$
 * Description: Test the OMP <status/> command.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Intevation GmbH
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
  unsigned int id;

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (authenticate (&session, "mattm", "mattm")) goto fail;

  if (create_task_from_rc_file (&session,
                                "new_task_empty_rc",
                                "Test omp_status_0 task",
                                "Task for manager test omp_status_0.",
                                &id))
    goto fail;

  /* Start the task. */

  if (authenticate (&session, "mattm", "mattm")) goto fail;

  int ret;
  gchar* msg = g_strdup_printf ("<start_task>"
                                "<task_id>%u</task_id>"
                                "</start_task>",
                                id);
  ret = send_to_manager (&session, msg);
  g_free (msg);
  if (ret == -1)
    goto fail;

  entity_t entity = NULL;
  if (read_entity (&session, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      goto fail;
    }
  free_entity (entity);

  /* Request the status. */

  if (authenticate (&session, "mattm", "mattm")) goto fail;

  if (send_to_manager (&session, "<status/>") == -1)
    goto fail;

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "status_response", NULL);
  add_entity (&expected->entities, "status", "200");
  add_entity (&expected->entities, "task_count", "1");
  entity_t task = add_entity (&expected->entities, "task", NULL);
  add_entity (&task->entities, "task_id", "0");
  add_entity (&task->entities, "identifier", "omp_start_task_0");
  add_entity (&task->entities, "task_status", "Running");
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
 fail:
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (entity);
  free_entity (expected);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
