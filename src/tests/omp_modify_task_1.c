/* Test 1 of OMP MODIFY_TASK.
 * $Id$
 * Description: Test OMP simultaneous MODIFY_TASK commands.
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
  int socket1, socket2, ret;
  gnutls_session_t session1;
  gnutls_session_t session2;
  unsigned int id;
  const char* id_str = NULL;

  verbose = 1;

  socket1 = connect_to_manager (&session1);
  if (socket1 == -1) return EXIT_FAILURE;

  if (env_authenticate (&session1))
    {
      close_manager_connection (socket1, session1);
      return EXIT_FAILURE;
    }

  /* Create a task in process 1. */

#define CONFIG "Task configuration."

  if (create_task (&session1,
                   CONFIG,
                   strlen (CONFIG),
                   "Test for omp_modify_task_1",
                   "Comment.",
                   &id))
    {
      close_manager_connection (socket1, session1);
      return EXIT_FAILURE;
    }

  if (id_string (id, &id_str))
    {
      close_manager_connection (socket1, session1);
      return EXIT_FAILURE;
    }

  /* Modify the task name in process 2. */

  socket2 = connect_to_manager (&session2);
  if (socket2 == -1)
    {
      close_manager_connection (socket1, session1);
      close_manager_connection (socket2, session2);
      return EXIT_FAILURE;
    }

  if (env_authenticate (&session2))
    {
      delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      close_manager_connection (socket2, session2);
      return EXIT_FAILURE;
    }

  if (sendf_to_manager (&session2,
                        "<modify_task>"
                        "<task_id>%u</task_id>"
                        "<parameter>name</parameter>"
                        "<value>Modified name</value>"
                        "</modify_task>",
                        id)
      == -1)
    {
      delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      close_manager_connection (socket2, session2);
      return EXIT_FAILURE;
    }

  entity_t entity = NULL;
  read_entity (&session2, &entity);

  entity_t expected = add_entity (NULL, "modify_task_response", NULL);
  add_entity (&expected->entities, "status", "201");

  close_manager_connection (socket2, session2);

  if (compare_entities (entity, expected))
    {
      delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      free_entity (entity);
      free_entity (expected);
      return EXIT_FAILURE;
    }
  free_entity (entity);
  free_entity (expected);

  /* Check that process 1 registered the change. */

  if (sendf_to_manager (&session1,
                        "<status/>")
      == -1)
    {
      delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      return EXIT_FAILURE;
    }

  entity = NULL;
  if (read_entity (&session1, &entity))
    {
      fprintf (stderr, "Failed to read response.\n");
      delete_task (&session1, id);
      close_manager_connection (socket1, session1);
      return EXIT_FAILURE;
    }

  ret = EXIT_FAILURE;
  DO_CHILDREN (entity, child, temp,
               if (strcasecmp (entity_name (child), "task") == 0)
                 {
                   entity_t task_id = entity_child (child, "task_id");
                   if (task_id == NULL) break;
                   if (strcasecmp (entity_text (task_id), id_str) == 0)
                     {
                       entity_t task_name = entity_child (child, "identifier");
                       if (task_name)
                         {
                           if (strcmp (entity_text (task_name),
                                      "Modified name"))
                             {
                               fprintf (stderr,
                                        "Name comparison failed: %s\n",
                                        entity_text (task_name));
                             }
                           else
                             ret = EXIT_SUCCESS;
                         }
                       break;
                     }
                 });

  /* Cleanup. */

  delete_task (&session1, id);
  close_manager_connection (socket1, session1);
  close_manager_connection (socket2, session2);
  free_entity (entity);

  return ret;
}
