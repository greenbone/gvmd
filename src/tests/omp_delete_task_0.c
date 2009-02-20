/* Test 0 of OMP DELETE_TASK.
 * $Id$
 * Description: Test the OMP DELETE_TASK command.
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

#define TRACE 0

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
  gchar* new_task_request = NULL;
  GError* error = NULL;

  g_file_get_contents ("new_task_small.xml", &new_task_request, NULL, &error);
  if (error)
    {
      fprintf (stderr, "%s\n", error->message);
      return EXIT_FAILURE;
    }

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (authenticate (&session, "mattm", "mattm")) goto fail;

  if (send_to_manager (&session, new_task_request) == -1) goto fail;

  entity_t entity = NULL;
  read_entity (&session, &entity);
  // FIX assume ok
  // FIX get id, assume 0 for now
  free_entity (entity);

  /* Remove the task. */

  if (authenticate (&session, "mattm", "mattm")) goto fail;

  if (send_to_manager (&session,
                       "<delete_task><task_id>0</task_id></delete_task>")
      == -1)
    goto fail;

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "delete_task_response", NULL);
  add_entity (&expected->entities, "status", "201");

  if (compare_entities (entity, expected))
    {
      free_entity (expected);
      free_entity (entity);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  free_entity (expected);
  free_entity (entity);

  /* Check the status. */

  if (authenticate (&session, "mattm", "mattm")) goto fail;

  if (send_to_manager (&session, "<status/>") == -1) goto fail;

  entity = NULL;
  read_entity (&session, &entity);
  // FIX assume ok

  entity_t count = entity_child (entity, "task_count");
  if (count && strcmp (entity_text (count), "1") == 0)
    {
      free_entity (entity);
      close_manager_connection (socket, session);
      return EXIT_SUCCESS;
    }

  free_entity (entity);

 fail:
  close_manager_connection (socket, session);
  return EXIT_FAILURE;
}
