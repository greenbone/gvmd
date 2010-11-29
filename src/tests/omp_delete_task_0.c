/* Test 0 of OMP DELETE_TASK.
 * $Id$
 * Description: Test the OMP DELETE_TASK command.
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
  int socket, running = 1, ret;
  gnutls_session_t session;
  char* id;
  gchar* msg;

  setup_test ();

  socket = connect_to_manager (&session);
  if (socket == -1) return EXIT_FAILURE;

  /* Create a task. */

  if (omp_authenticate_env (&session))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  if (omp_create_task_rc_file (&session,
                               "new_task_small_rc",
                               "Test for omp_delete_task_0",
                               "Simple test scan.",
                               &id))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Remove the task. */

  msg = g_strdup_printf ("<delete_task"
                         " task_id=\"%s\">"
                         "</delete_task>",
                         id);
  ret = openvas_server_send (&session, msg);
  g_free (msg);
  if (ret == -1)
    {
      free (id);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity_t entity = NULL;
  read_entity (&session, &entity);

  /* Compare to expected response. */

  entity_t expected = add_entity (NULL, "delete_task_response", NULL);
  add_attribute (expected, "status", "202");
  add_attribute (expected, "status_text", "OK, request submitted");

  if (compare_entities (entity, expected))
    {
      entity_t expected2 = add_entity (NULL, "delete_task_response", NULL);
      add_attribute (expected, "status", "200");
      add_attribute (expected, "status_text", "OK");

      if (compare_entities (entity, expected2))
        {
          free_entity (expected2);
          running = 0;
        }
      else
        {
          free_entity (expected2);
          free_entity (expected);
          free_entity (entity);
          free (id);
          close_manager_connection (socket, session);
          return EXIT_FAILURE;
        }
    }

  free_entity (expected);
  free_entity (entity);

  /* Check the status of the task. */

  if (openvas_server_sendf (&session,
                            "<get_status task_id=\"%s\"/>",
                            id)
      == -1)
    {
      free (id);
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  entity = NULL;
  if (read_entity (&session, &entity))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  expected = add_entity (NULL, "get_status_response", NULL);
  add_attribute (expected, "status", "404");
  msg = g_strdup_printf ("Failed to find task '%s'", id);
  add_attribute (expected, "status_text", msg);
  free (id);
  g_free (msg);

  if (compare_entities (entity, expected))
    {
      const char* status = omp_task_status (entity);

      free_entity (expected);

      /* It may be that the scanner is still busy stopping the task. */
      if (running && status && strcmp (status, "Delete Requested") == 0)
        {
          free_entity (entity);
          close_manager_connection (socket, session);
          return EXIT_SUCCESS;
        }
      else
        {
          free_entity (entity);
          close_manager_connection (socket, session);
          return EXIT_FAILURE;
        }
    }

  free_entity (expected);
  free_entity (entity);
  close_manager_connection (socket, session);
  return EXIT_SUCCESS;
}
