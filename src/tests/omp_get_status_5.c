/* Test 5 of OMP GET_STATUS.
 * $Id$
 * Description: Test the OMP GET_STATUS command on a created task.
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

#include <glib.h>
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
  entity_t entity, expected, task, messages, report_count, element;
  gchar* string;

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
                               "Task for omp_get_status_5",
                               "Test omp_get_status_5 task.",
                               &id))
    {
      close_manager_connection (socket, session);
      return EXIT_FAILURE;
    }

  /* Request the task status. */

  if (openvas_server_sendf (&session,
                            "<get_status task_id=\"%s\"/>",
                            id)
      == -1)
    {
      omp_delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  /* Read the response. */

  entity = NULL;
  read_entity (&session, &entity);
  print_entity (stdout, entity);

  /* Compare to expected response. */

  expected = add_entity (NULL, "get_status_response", NULL);
  add_attribute (expected, "status", "200");
  add_attribute (expected, "status_text", "OK");
  task = add_entity (&expected->entities, "task", NULL);
  add_attribute (task, "id", id);
  add_entity (&task->entities, "name", "Task for omp_get_status_5");

  element = add_entity (&task->entities, "config", NULL);
  string = g_strdup_printf ("Imported config for task %s", id);
  add_entity (&element->entities, "name", string);
  g_free (string);
  element = add_entity (&task->entities, "escalator", NULL);
  add_entity (&element->entities, "name", NULL);
  element = add_entity (&task->entities, "target", NULL);
  string = g_strdup_printf ("Imported target for task %s", id);
  add_entity (&element->entities, "name", string);
  g_free (string);

  add_entity (&task->entities, "status", "New");
  add_entity (&task->entities, "progress", "-1");
  messages = add_entity (&task->entities, "messages", NULL);
  add_entity (&messages->entities, "debug", "0");
  add_entity (&messages->entities, "hole", "0");
  add_entity (&messages->entities, "info", "0");
  add_entity (&messages->entities, "log", "0");
  add_entity (&messages->entities, "warning", "0");
  report_count = add_entity (&task->entities, "report_count", "0");
  add_entity (&report_count->entities, "finished", "0");

  if (compare_entities (entity, expected))
    {
      free_entity (entity);
      free_entity (expected);
      omp_delete_task (&session, id);
      close_manager_connection (socket, session);
      free (id);
      return EXIT_FAILURE;
    }

  free_entity (entity);
  free_entity (expected);
  omp_delete_task (&session, id);
  close_manager_connection (socket, session);
  free (id);
  return EXIT_SUCCESS;
}
